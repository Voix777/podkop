## xray configuration manager
## Builds xray-core JSON config (sidecar model: SOCKS5 inbound + proxy outbounds)

#######################################
# Configure the log section of an xray JSON configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   log_level: string, log level (debug|info|warning|error|none)
# Outputs:
#   Writes updated JSON configuration to stdout
# Example:
#   CONFIG=$(xray_cm_configure_log "$CONFIG" "warning")
#######################################
xray_cm_configure_log() {
    local config="$1"
    local log_level="${2:-warning}"

    echo "$config" | jq \
        --arg level "$log_level" \
        '.log = {loglevel: $level}'
}

#######################################
# Add a SOCKS5 inbound to the inbounds section of an xray JSON configuration.
# This is the listener that sing-box routes proxy-xray traffic to.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier for the inbound
#   listen_address: string, IP address to listen on
#   listen_port: integer, port to listen on
# Outputs:
#   Writes updated JSON configuration to stdout
# Example:
#   CONFIG=$(xray_cm_add_socks_inbound "$CONFIG" "socks-in" "127.0.0.1" 1603)
#######################################
xray_cm_add_socks_inbound() {
    local config="$1"
    local tag="$2"
    local listen_address="$3"
    local listen_port="$4"

    echo "$config" | jq \
        --arg tag "$tag" \
        --arg listen_address "$listen_address" \
        --argjson listen_port "$listen_port" \
        '.inbounds += [{
            tag: $tag,
            listen: $listen_address,
            port: $listen_port,
            protocol: "socks",
            settings: {
                auth: "noauth",
                udp: true
            },
            sniffing: {
                enabled: true,
                destOverride: ["http", "tls"]
            }
        }]'
}

#######################################
# Add a Freedom (direct) outbound to the outbounds section of an xray JSON configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier for the outbound
# Outputs:
#   Writes updated JSON configuration to stdout
# Example:
#   CONFIG=$(xray_cm_add_freedom_outbound "$CONFIG" "direct-out")
#######################################
xray_cm_add_freedom_outbound() {
    local config="$1"
    local tag="$2"

    echo "$config" | jq \
        --arg tag "$tag" \
        '.outbounds += [{
            tag: $tag,
            protocol: "freedom"
        }]'
}

#######################################
# Add a Blackhole (block) outbound to the outbounds section of an xray JSON configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier for the outbound
# Outputs:
#   Writes updated JSON configuration to stdout
# Example:
#   CONFIG=$(xray_cm_add_blackhole_outbound "$CONFIG" "block-out")
#######################################
xray_cm_add_blackhole_outbound() {
    local config="$1"
    local tag="$2"

    echo "$config" | jq \
        --arg tag "$tag" \
        '.outbounds += [{
            tag: $tag,
            protocol: "blackhole"
        }]'
}

#######################################
# Add a VLESS outbound to the outbounds section of an xray JSON configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier for the outbound
#   server_address: string, IP address or hostname of the VLESS server
#   server_port: integer, port of the VLESS server
#   uuid: string, user UUID
#   flow: string, flow setting e.g. xtls-rprx-vision (optional)
# Outputs:
#   Writes updated JSON configuration to stdout
# Example:
#   CONFIG=$(xray_cm_add_vless_outbound "$CONFIG" "vless-out" "example.com" 443 "uuid-here" "xtls-rprx-vision")
#######################################
xray_cm_add_vless_outbound() {
    local config="$1"
    local tag="$2"
    local server_address="$3"
    local server_port="$4"
    local uuid="$5"
    local flow="$6"

    echo "$config" | jq \
        --arg tag "$tag" \
        --arg server_address "$server_address" \
        --arg server_port "$server_port" \
        --arg uuid "$uuid" \
        --arg flow "$flow" \
        '.outbounds += [{
            tag: $tag,
            protocol: "vless",
            settings: {
                vnext: [{
                    address: $server_address,
                    port: ($server_port | tonumber),
                    users: [{
                        id: $uuid,
                        encryption: "none"
                    }
                    + (if $flow != "" then {flow: $flow} else {} end)]
                }]
            },
            streamSettings: {}
        }]'
}

#######################################
# Add a VMess outbound to the outbounds section of an xray JSON configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier for the outbound
#   server_address: string, IP address or hostname of the VMess server
#   server_port: integer, port of the VMess server
#   uuid: string, user UUID
#   alter_id: integer, alterId (default 0)
#   security: string, encryption method (default "auto")
# Outputs:
#   Writes updated JSON configuration to stdout
# Example:
#   CONFIG=$(xray_cm_add_vmess_outbound "$CONFIG" "vmess-out" "example.com" 443 "uuid-here" 0 "auto")
#######################################
xray_cm_add_vmess_outbound() {
    local config="$1"
    local tag="$2"
    local server_address="$3"
    local server_port="$4"
    local uuid="$5"
    local alter_id="${6:-0}"
    local security="${7:-auto}"

    echo "$config" | jq \
        --arg tag "$tag" \
        --arg server_address "$server_address" \
        --arg server_port "$server_port" \
        --arg uuid "$uuid" \
        --argjson alter_id "$alter_id" \
        --arg security "$security" \
        '.outbounds += [{
            tag: $tag,
            protocol: "vmess",
            settings: {
                vnext: [{
                    address: $server_address,
                    port: ($server_port | tonumber),
                    users: [{
                        id: $uuid,
                        alterId: $alter_id,
                        security: $security
                    }]
                }]
            },
            streamSettings: {}
        }]'
}

#######################################
# Add a Trojan outbound to the outbounds section of an xray JSON configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier for the outbound
#   server_address: string, IP address or hostname of the Trojan server
#   server_port: integer, port of the Trojan server
#   password: string, password for authentication
# Outputs:
#   Writes updated JSON configuration to stdout
# Example:
#   CONFIG=$(xray_cm_add_trojan_outbound "$CONFIG" "trojan-out" "example.com" 443 "password")
#######################################
xray_cm_add_trojan_outbound() {
    local config="$1"
    local tag="$2"
    local server_address="$3"
    local server_port="$4"
    local password="$5"

    echo "$config" | jq \
        --arg tag "$tag" \
        --arg server_address "$server_address" \
        --arg server_port "$server_port" \
        --arg password "$password" \
        '.outbounds += [{
            tag: $tag,
            protocol: "trojan",
            settings: {
                servers: [{
                    address: $server_address,
                    port: ($server_port | tonumber),
                    password: $password
                }]
            },
            streamSettings: {}
        }]'
}

#######################################
# Add a Shadowsocks outbound to the outbounds section of an xray JSON configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier for the outbound
#   server_address: string, IP address or hostname of the Shadowsocks server
#   server_port: integer, port of the Shadowsocks server
#   method: string, encryption method
#   password: string, password for encryption
# Outputs:
#   Writes updated JSON configuration to stdout
# Example:
#   CONFIG=$(xray_cm_add_shadowsocks_outbound "$CONFIG" "ss-out" "example.com" 443 "chacha20-ietf-poly1305" "pass")
#######################################
xray_cm_add_shadowsocks_outbound() {
    local config="$1"
    local tag="$2"
    local server_address="$3"
    local server_port="$4"
    local method="$5"
    local password="$6"

    echo "$config" | jq \
        --arg tag "$tag" \
        --arg server_address "$server_address" \
        --arg server_port "$server_port" \
        --arg method "$method" \
        --arg password "$password" \
        '.outbounds += [{
            tag: $tag,
            protocol: "shadowsocks",
            settings: {
                servers: [{
                    address: $server_address,
                    port: ($server_port | tonumber),
                    method: $method,
                    password: $password
                }]
            },
            streamSettings: {}
        }]'
}

#######################################
# Add a SOCKS outbound to the outbounds section of an xray JSON configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier for the outbound
#   server_address: string, IP address or hostname of the SOCKS server
#   server_port: integer, port of the SOCKS server
#   username: string, username for authentication (optional)
#   password: string, password for authentication (optional)
# Outputs:
#   Writes updated JSON configuration to stdout
# Example:
#   CONFIG=$(xray_cm_add_socks_outbound "$CONFIG" "socks-out" "127.0.0.1" 1080)
#######################################
xray_cm_add_socks_outbound() {
    local config="$1"
    local tag="$2"
    local server_address="$3"
    local server_port="$4"
    local username="$5"
    local password="$6"

    echo "$config" | jq \
        --arg tag "$tag" \
        --arg server_address "$server_address" \
        --arg server_port "$server_port" \
        --arg username "$username" \
        --arg password "$password" \
        '.outbounds += [{
            tag: $tag,
            protocol: "socks",
            settings: {
                servers: [{
                    address: $server_address,
                    port: ($server_port | tonumber)
                }
                + (if $username != "" then {users: [{user: $username, pass: $password}]} else {} end)]
            }
        }]'
}

#######################################
# Add a raw (pre-built JSON) outbound to an xray JSON configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier for the outbound
#   json_outbound: string (JSON), complete outbound object
# Outputs:
#   Writes updated JSON configuration to stdout
#######################################
xray_cm_add_raw_outbound() {
    local config="$1"
    local tag="$2"
    local json_outbound="$3"

    # Inject the tag into the raw outbound object
    echo "$config" | jq \
        --arg tag "$tag" \
        --argjson outbound "$json_outbound" \
        '.outbounds += [$outbound + {tag: $tag}]'
}

#######################################
# Set TLS streamSettings for an outbound in an xray JSON configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier of the outbound to modify
#   sni: string, server name indication (optional)
#   insecure: string, "true" to allow insecure (optional)
#   fingerprint: string, uTLS fingerprint e.g. "chrome" (optional)
#   alpn: string, JSON array of ALPN values e.g. '["h2","http/1.1"]' (optional)
# Outputs:
#   Writes updated JSON configuration to stdout
#######################################
xray_cm_set_tls_for_outbound() {
    local config="$1"
    local tag="$2"
    local sni="$3"
    local insecure="$4"
    local fingerprint="$5"
    local alpn="$6"  # JSON array string or ""

    echo "$config" | jq \
        --arg tag "$tag" \
        --arg sni "$sni" \
        --arg insecure "$insecure" \
        --arg fingerprint "$fingerprint" \
        --argjson alpn "$([ -n "$alpn" ] && echo "$alpn" || echo "null")" \
        '.outbounds |= map(
            if .tag == $tag then
                .streamSettings = ((.streamSettings // {}) + {
                    security: "tls",
                    tlsSettings: (
                        {}
                        + (if $sni != "" then {serverName: $sni} else {} end)
                        + (if $insecure == "true" then {allowInsecure: true} else {} end)
                        + (if $fingerprint != "" then {fingerprint: $fingerprint} else {} end)
                        + (if $alpn != null then {alpn: $alpn} else {} end)
                    )
                })
            else . end
        )'
}

#######################################
# Set REALITY streamSettings for an outbound in an xray JSON configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier of the outbound to modify
#   sni: string, server name indication
#   fingerprint: string, uTLS fingerprint e.g. "chrome"
#   public_key: string, Reality public key
#   short_id: string, Reality short ID
# Outputs:
#   Writes updated JSON configuration to stdout
#######################################
xray_cm_set_reality_for_outbound() {
    local config="$1"
    local tag="$2"
    local sni="$3"
    local fingerprint="$4"
    local public_key="$5"
    local short_id="$6"

    echo "$config" | jq \
        --arg tag "$tag" \
        --arg sni "$sni" \
        --arg fingerprint "$fingerprint" \
        --arg public_key "$public_key" \
        --arg short_id "$short_id" \
        '.outbounds |= map(
            if .tag == $tag then
                .streamSettings = ((.streamSettings // {}) + {
                    security: "reality",
                    realitySettings: {
                        serverName: $sni,
                        fingerprint: $fingerprint,
                        publicKey: $public_key,
                        shortId: $short_id
                    }
                })
            else . end
        )'
}

#######################################
# Set WebSocket transport in streamSettings for an outbound in an xray JSON configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier of the outbound to modify
#   path: string, WebSocket path (optional)
#   host: string, Host header value (optional)
#   early_data: string, max early data bytes (optional)
# Outputs:
#   Writes updated JSON configuration to stdout
#######################################
xray_cm_set_ws_transport_for_outbound() {
    local config="$1"
    local tag="$2"
    local path="$3"
    local host="$4"
    local early_data="$5"

    echo "$config" | jq \
        --arg tag "$tag" \
        --arg path "$path" \
        --arg host "$host" \
        --arg early_data "$early_data" \
        '.outbounds |= map(
            if .tag == $tag then
                .streamSettings = ((.streamSettings // {}) + {
                    network: "ws",
                    wsSettings: (
                        {}
                        + (if $path != "" then {path: $path} else {path: "/"} end)
                        + (if $host != "" then {headers: {Host: $host}} else {} end)
                        + (if $early_data != "" then {maxEarlyData: ($early_data | tonumber), earlyDataHeaderName: "Sec-WebSocket-Protocol"} else {} end)
                    )
                })
            else . end
        )'
}

#######################################
# Set gRPC transport in streamSettings for an outbound in an xray JSON configuration.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier of the outbound to modify
#   service_name: string, gRPC service name (optional)
# Outputs:
#   Writes updated JSON configuration to stdout
#######################################
xray_cm_set_grpc_transport_for_outbound() {
    local config="$1"
    local tag="$2"
    local service_name="$3"

    echo "$config" | jq \
        --arg tag "$tag" \
        --arg service_name "$service_name" \
        '.outbounds |= map(
            if .tag == $tag then
                .streamSettings = ((.streamSettings // {}) + {
                    network: "grpc",
                    grpcSettings: (
                        {}
                        + (if $service_name != "" then {serviceName: $service_name} else {} end)
                    )
                })
            else . end
        )'
}

#######################################
# Set TCP transport (default) in streamSettings for an outbound in an xray JSON configuration.
# Sets network to "tcp" explicitly — needed when TLS/Reality is applied without a custom transport.
# Arguments:
#   config: string (JSON), xray configuration to modify
#   tag: string, identifier of the outbound to modify
# Outputs:
#   Writes updated JSON configuration to stdout
#######################################
xray_cm_set_tcp_transport_for_outbound() {
    local config="$1"
    local tag="$2"

    echo "$config" | jq \
        --arg tag "$tag" \
        '.outbounds |= map(
            if .tag == $tag then
                .streamSettings = ((.streamSettings // {}) + {network: "tcp"})
            else . end
        )'
}
