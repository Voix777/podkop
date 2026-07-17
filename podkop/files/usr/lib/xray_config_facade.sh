PODKOP_LIB="/usr/lib/podkop"
. "$PODKOP_LIB/helpers.sh"
. "$PODKOP_LIB/xray_config_manager.sh"

#######################################
# Add a proxy outbound to an xray JSON configuration by parsing a proxy URL.
# Supports: vless, vmess, trojan, ss, socks4/socks4a/socks5
# Note: hysteria2/hy2 is NOT supported by xray-core.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   section: string, UCI section name (used to derive the outbound tag)
#   url: string, proxy URL
# Outputs:
#   Writes updated JSON configuration to stdout
#######################################
xray_cf_add_proxy_outbound() {
    local config="$1"
    local section="$2"
    local url="$3"

    url=$(url_decode "$url")
    url=$(url_strip_fragment "$url")

    local scheme
    scheme="$(url_get_scheme "$url")"
    case "$scheme" in
    socks4 | socks4a | socks5)
        local tag host port userinfo username password
        tag=$(get_outbound_tag_by_section "$section")
        host=$(url_get_host "$url")
        port=$(url_get_port "$url")

        if [ "$scheme" = "socks5" ]; then
            userinfo=$(url_get_userinfo "$url")
            if [ -n "$userinfo" ]; then
                username="${userinfo%%:*}"
                password="${userinfo#*:}"
            fi
        fi

        config=$(xray_cm_add_socks_outbound "$config" "$tag" "$host" "$port" "$username" "$password")
        ;;

    vless)
        local tag host port uuid flow
        tag=$(get_outbound_tag_by_section "$section")
        host=$(url_get_host "$url")
        port=$(url_get_port "$url")
        uuid=$(url_get_userinfo "$url")
        flow=$(url_get_query_param "$url" "flow")

        config=$(xray_cm_add_vless_outbound "$config" "$tag" "$host" "$port" "$uuid" "$flow")
        config=$(_xray_add_outbound_security "$config" "$tag" "$url")
        config=$(_xray_add_outbound_transport "$config" "$tag" "$url")
        ;;

    vmess)
        # vmess links are base64-encoded JSON: vmess://<base64>
        local tag raw_b64 vmess_json host port uuid alter_id security
        tag=$(get_outbound_tag_by_section "$section")

        raw_b64="${url#vmess://}"
        vmess_json=$(echo "$raw_b64" | base64 -d 2>/dev/null)
        if [ -z "$vmess_json" ]; then
            log "Cannot decode vmess URL. Aborted." "fatal"
            exit 1
        fi

        host=$(echo "$vmess_json" | jq -r '.add // ""')
        port=$(echo "$vmess_json" | jq -r '.port // ""')
        uuid=$(echo "$vmess_json" | jq -r '.id // ""')
        alter_id=$(echo "$vmess_json" | jq -r '.aid // 0')
        security=$(echo "$vmess_json" | jq -r '.scy // "auto"')

        local net tls sni path_val host_header svc_name fp
        net=$(echo "$vmess_json" | jq -r '.net // "tcp"')
        tls=$(echo "$vmess_json" | jq -r '.tls // ""')
        sni=$(echo "$vmess_json" | jq -r '.sni // ""')
        fp=$(echo "$vmess_json" | jq -r '.fp // ""')
        path_val=$(echo "$vmess_json" | jq -r '.path // "/"')
        host_header=$(echo "$vmess_json" | jq -r '.host // ""')
        svc_name=$(echo "$vmess_json" | jq -r '.path // ""')  # grpc uses path for serviceName

        config=$(xray_cm_add_vmess_outbound "$config" "$tag" "$host" "$port" "$uuid" "$alter_id" "$security")

        case "$net" in
        ws)
            config=$(xray_cm_set_ws_transport_for_outbound "$config" "$tag" "$path_val" "$host_header" "")
            ;;
        grpc)
            config=$(xray_cm_set_grpc_transport_for_outbound "$config" "$tag" "$svc_name")
            ;;
        tcp | *)
            config=$(xray_cm_set_tcp_transport_for_outbound "$config" "$tag")
            ;;
        esac

        if [ "$tls" = "tls" ]; then
            config=$(xray_cm_set_tls_for_outbound "$config" "$tag" "$sni" "" "$fp" "")
        fi
        ;;

    trojan)
        local tag host port password
        tag=$(get_outbound_tag_by_section "$section")
        host=$(url_get_host "$url")
        port=$(url_get_port "$url")
        password=$(url_get_userinfo "$url")

        config=$(xray_cm_add_trojan_outbound "$config" "$tag" "$host" "$port" "$password")
        config=$(_xray_add_outbound_security "$config" "$tag" "$url")
        config=$(_xray_add_outbound_transport "$config" "$tag" "$url")
        ;;

    ss)
        local userinfo tag host port method password
        userinfo=$(url_get_userinfo "$url")
        if ! is_shadowsocks_userinfo_format "$userinfo"; then
            userinfo=$(base64_decode "$userinfo")
            if [ $? -ne 0 ]; then
                log "Cannot decode shadowsocks userinfo or it does not match the expected format. Aborted." "fatal"
                exit 1
            fi
        fi

        tag=$(get_outbound_tag_by_section "$section")
        host=$(url_get_host "$url")
        port=$(url_get_port "$url")
        method="${userinfo%%:*}"
        password="${userinfo#*:}"

        config=$(xray_cm_add_shadowsocks_outbound "$config" "$tag" "$host" "$port" "$method" "$password")
        ;;

    hysteria2 | hy2)
        log "Hysteria2 is not supported by xray-core. Use a sing-box 'proxy' section instead. Aborted." "fatal"
        exit 1
        ;;

    *)
        log "Unsupported proxy scheme '$scheme' for xray. Aborted." "fatal"
        exit 1
        ;;
    esac

    echo "$config"
}

#######################################
# Add a raw JSON outbound to an xray configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   section: string, UCI section name (used to derive the outbound tag)
#   json_outbound: string (JSON), complete xray outbound object
# Outputs:
#   Writes updated JSON configuration to stdout
#######################################
xray_cf_add_json_outbound() {
    local config="$1"
    local section="$2"
    local json_outbound="$3"

    local tag
    tag=$(get_outbound_tag_by_section "$section")
    config=$(xray_cm_add_raw_outbound "$config" "$tag" "$json_outbound")

    echo "$config"
}

## Private helpers

_xray_add_outbound_security() {
    local config="$1"
    local outbound_tag="$2"
    local url="$3"

    local security
    security=$(url_get_query_param "$url" "security")

    case "$security" in
    tls)
        local sni insecure fingerprint alpn_raw alpn
        sni=$(url_get_query_param "$url" "sni")
        insecure=$(_xray_get_insecure_param "$url")
        fingerprint=$(url_get_query_param "$url" "fp")
        alpn_raw=$(url_get_query_param "$url" "alpn")
        alpn=$(comma_string_to_json_array "$alpn_raw")
        [ "$alpn" = "[]" ] && alpn=""

        config=$(xray_cm_set_tls_for_outbound "$config" "$outbound_tag" "$sni" \
            "$([ "$insecure" = "1" ] && echo "true" || echo "")" "$fingerprint" "$alpn")
        ;;
    reality)
        local sni fingerprint public_key short_id
        sni=$(url_get_query_param "$url" "sni")
        fingerprint=$(url_get_query_param "$url" "fp")
        public_key=$(url_get_query_param "$url" "pbk")
        short_id=$(url_get_query_param "$url" "sid")

        config=$(xray_cm_set_reality_for_outbound "$config" "$outbound_tag" "$sni" "$fingerprint" \
            "$public_key" "$short_id")
        ;;
    none | "")
        # No TLS — ensure streamSettings at least has network set
        config=$(xray_cm_set_tcp_transport_for_outbound "$config" "$outbound_tag")
        ;;
    *)
        log "Unknown security '$security' for xray outbound. Ignoring." "warn"
        ;;
    esac

    echo "$config"
}

_xray_get_insecure_param() {
    local url="$1"
    local insecure
    insecure=$(url_get_query_param "$url" "allowInsecure")
    [ -z "$insecure" ] && insecure=$(url_get_query_param "$url" "insecure")
    echo "$insecure"
}

_xray_add_outbound_transport() {
    local config="$1"
    local outbound_tag="$2"
    local url="$3"

    local transport
    transport=$(url_get_query_param "$url" "type")

    case "$transport" in
    tcp | raw | "")
        # TCP is set by _xray_add_outbound_security for none/tls, already correct
        ;;
    ws)
        local ws_path ws_host ws_early_data
        ws_path=$(url_get_query_param "$url" "path")
        ws_host=$(url_get_query_param "$url" "host")
        ws_early_data=$(url_get_query_param "$url" "ed")

        config=$(xray_cm_set_ws_transport_for_outbound "$config" "$outbound_tag" \
            "$ws_path" "$ws_host" "$ws_early_data")
        ;;
    grpc)
        local grpc_service_name
        grpc_service_name=$(url_get_query_param "$url" "serviceName")

        config=$(xray_cm_set_grpc_transport_for_outbound "$config" "$outbound_tag" "$grpc_service_name")
        ;;
    *)
        log "Unknown transport '$transport' for xray outbound. Ignoring." "warn"
        ;;
    esac

    echo "$config"
}
