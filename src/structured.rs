use serde_json::{Map, Value};

use crate::model::{Proxy, ProxyKind};

pub fn parse_subscription(content: &str, group_id: u32) -> Option<Vec<Proxy>> {
    let trimmed = content.trim_start();
    let has_container_key = content
        .lines()
        .any(|line| matches!(line.trim(), "proxies:" | "outbounds:" | "endpoints:"));
    if !trimmed.starts_with('{') && !has_container_key {
        return None;
    }
    let root: Value = serde_yaml::from_str(content).ok()?;
    let object = root.as_object()?;
    let mut nodes = Vec::new();
    let mut recognized = false;
    for key in ["proxies", "outbounds", "endpoints"] {
        let Some(values) = object.get(key).and_then(Value::as_array) else {
            continue;
        };
        recognized = true;
        nodes.extend(
            values
                .iter()
                .filter_map(|value| parse_proxy(value.as_object()?, group_id)),
        );
    }
    (recognized && !nodes.is_empty()).then_some(nodes)
}

fn parse_proxy(object: &Map<String, Value>, group_id: u32) -> Option<Proxy> {
    let type_name = text(object, &["type"]).to_ascii_lowercase();
    let mut kind = match type_name.as_str() {
        "ss" | "shadowsocks" => ProxyKind::Shadowsocks,
        "vmess" => ProxyKind::Vmess,
        "vless" => ProxyKind::Vless,
        "trojan" => ProxyKind::Trojan,
        "tuic" => ProxyKind::Tuic,
        "anytls" => ProxyKind::Anytls,
        "hysteria2" | "hy2" => ProxyKind::Hysteria2,
        "http" => ProxyKind::Http,
        "https" => ProxyKind::Https,
        "socks" | "socks5" => ProxyKind::Socks5,
        "snell" => ProxyKind::Snell,
        "wireguard" => ProxyKind::Wireguard,
        _ => return None,
    };

    let peer = if kind == ProxyKind::Wireguard {
        object
            .get("peers")
            .and_then(Value::as_array)
            .and_then(|peers| peers.first())
            .and_then(Value::as_object)
    } else {
        None
    };
    let server = non_empty(
        text(object, &["server"]),
        &peer.map_or_else(String::new, |peer| text(peer, &["address"])),
    );
    let port = number_u16(object, &["port", "server_port"])
        .or_else(|| peer.and_then(|peer| number_u16(peer, &["port"])))?;
    if server.is_empty() || port == 0 {
        return None;
    }
    let tls_object = object.get("tls").and_then(Value::as_object);
    let tls_enabled =
        boolean(object, &["tls"]).or_else(|| tls_object.and_then(|tls| boolean(tls, &["enabled"])));
    if kind == ProxyKind::Http && tls_enabled == Some(true) {
        kind = ProxyKind::Https;
    }

    let mut proxy = Proxy::new(kind, server, port);
    proxy.group_id = group_id;
    proxy.name = non_empty(
        text(object, &["name", "tag"]),
        &format!("{}:{}", proxy.server, proxy.port),
    );
    proxy.group = text(object, &["group"]);
    proxy.username = text(object, &["username"]);
    proxy.password = text(object, &["password", "psk"]);
    proxy.uuid = text(object, &["uuid"]);
    proxy.method = text(object, &["cipher", "method", "security"]);
    proxy.alter_id = number_u16(object, &["alterId", "alter_id"]).unwrap_or_default();
    proxy.flow = text(object, &["flow"]);
    proxy.network = text(object, &["network"]);
    proxy.host = text(object, &["host"]);
    proxy.path = text(object, &["path"]);
    proxy.server_name = non_empty(
        text(object, &["servername", "server_name", "sni"]),
        &tls_object.map_or_else(String::new, |tls| text(tls, &["server_name"])),
    );
    proxy.tls = tls_enabled.unwrap_or(matches!(
        kind,
        ProxyKind::Trojan | ProxyKind::Tuic | ProxyKind::Anytls | ProxyKind::Hysteria2
    ));
    proxy.skip_cert_verify = boolean(object, &["skip-cert-verify", "skip_cert_verify"])
        .or_else(|| tls_object.and_then(|tls| boolean(tls, &["insecure"])));
    proxy.udp = boolean(object, &["udp"]);
    proxy.tcp_fast_open = boolean(object, &["tfo", "tcp_fast_open"]);
    proxy.plugin = text(object, &["plugin"]);
    proxy.plugin_opts = value_text(object, &["plugin-opts", "plugin_opts"]);
    proxy.congestion_control = text(object, &["congestion-controller", "congestion_control"]);
    proxy.udp_relay_mode = text(object, &["udp-relay-mode", "udp_relay_mode"]);
    proxy.heartbeat_interval = text(object, &["heartbeat-interval", "heartbeat"]);
    proxy.up_mbps = number_u32(object, &["up", "up_mbps"]);
    proxy.down_mbps = number_u32(object, &["down", "down_mbps"]);
    proxy.obfs = text(object, &["obfs"]);
    proxy.obfs_password = text(object, &["obfs-password", "obfs_password"]);
    proxy.ports = text(object, &["ports"]);
    proxy.ca = text(object, &["ca"]);
    proxy.ca_str = text(object, &["ca-str", "ca_str"]);
    proxy.cwnd = number_u32(object, &["cwnd"]);
    proxy.hop_interval = duration_seconds(object, &["hop-interval", "hop_interval"]);
    proxy.idle_session_check_interval = duration_seconds(
        object,
        &["idle-session-check-interval", "idle_session_check_interval"],
    );
    proxy.idle_session_timeout =
        duration_seconds(object, &["idle-session-timeout", "idle_session_timeout"]);
    proxy.min_idle_session = number_u32(object, &["min-idle-session", "min_idle_session"]);
    proxy.snell_version = number_u16(object, &["version"]);
    if let Some(obfs) = object.get("obfs-opts").and_then(Value::as_object) {
        proxy.obfs = text(obfs, &["mode"]);
        proxy.host = text(obfs, &["host"]);
    }

    parse_transport(object, &mut proxy);
    parse_tls_details(object, tls_object, &mut proxy);
    if kind == ProxyKind::Wireguard {
        parse_wireguard(object, peer, &mut proxy);
    }
    Some(proxy)
}

fn parse_transport(object: &Map<String, Value>, proxy: &mut Proxy) {
    if let Some(transport) = object.get("transport").and_then(Value::as_object) {
        proxy.network = text(transport, &["type"]);
        proxy.path = text(transport, &["path", "service_name"]);
        proxy.host = first_string(transport, &["host"]);
        if proxy.host.is_empty() {
            proxy.host = transport
                .get("headers")
                .and_then(Value::as_object)
                .map_or_else(String::new, |headers| text(headers, &["Host", "host"]));
        }
    }
    if let Some(ws) = object.get("ws-opts").and_then(Value::as_object) {
        proxy.network = "ws".into();
        proxy.path = text(ws, &["path"]);
        proxy.host = ws
            .get("headers")
            .and_then(Value::as_object)
            .map_or_else(String::new, |headers| text(headers, &["Host", "host"]));
    }
    if let Some(grpc) = object.get("grpc-opts").and_then(Value::as_object) {
        proxy.network = "grpc".into();
        proxy.path = text(grpc, &["grpc-service-name", "service_name"]);
    }
    if let Some(h2) = object.get("h2-opts").and_then(Value::as_object) {
        proxy.network = "h2".into();
        proxy.path = text(h2, &["path"]);
        proxy.host = first_string(h2, &["host"]);
    }
}

fn parse_tls_details(
    object: &Map<String, Value>,
    tls: Option<&Map<String, Value>>,
    proxy: &mut Proxy,
) {
    proxy.alpn = string_list(object, &["alpn"]);
    if proxy.alpn.is_empty() {
        proxy.alpn = tls.map_or_else(Vec::new, |tls| string_list(tls, &["alpn"]));
    }
    proxy.fingerprint = text(object, &["client-fingerprint", "fingerprint"]);
    if proxy.fingerprint.is_empty() {
        proxy.fingerprint = tls
            .and_then(|tls| tls.get("utls"))
            .and_then(Value::as_object)
            .map_or_else(String::new, |utls| text(utls, &["fingerprint"]));
    }
    let reality = object
        .get("reality-opts")
        .or_else(|| tls.and_then(|tls| tls.get("reality")))
        .and_then(Value::as_object);
    if let Some(reality) = reality {
        proxy.public_key = text(reality, &["public-key", "public_key"]);
        proxy.short_id = text(reality, &["short-id", "short_id"]);
        proxy.tls = true;
    }
}

fn parse_wireguard(
    object: &Map<String, Value>,
    peer: Option<&Map<String, Value>>,
    proxy: &mut Proxy,
) {
    proxy.wireguard_address = string_list(object, &["address"]);
    for key in ["ip", "ipv6"] {
        let value = text(object, &[key]);
        if !value.is_empty() {
            proxy.wireguard_address.push(value);
        }
    }
    proxy.private_key = text(object, &["private-key", "private_key"]);
    proxy.public_key = non_empty(
        text(object, &["public-key", "public_key"]),
        &peer.map_or_else(String::new, |peer| text(peer, &["public_key"])),
    );
    proxy.pre_shared_key = non_empty(
        text(object, &["pre-shared-key", "pre_shared_key"]),
        &peer.map_or_else(String::new, |peer| text(peer, &["pre_shared_key"])),
    );
    proxy.allowed_ips = peer.map_or_else(
        || string_list(object, &["allowed-ips", "allowed_ips"]),
        |peer| string_list(peer, &["allowed_ips"]),
    );
    if proxy.allowed_ips.is_empty() {
        proxy.allowed_ips = vec!["0.0.0.0/0".into(), "::/0".into()];
    }
    proxy.dns_servers = string_list(object, &["dns"]);
    proxy.mtu = number_u16(object, &["mtu"]);
    proxy.persistent_keepalive = peer
        .and_then(|peer| number_u16(peer, &["persistent_keepalive"]))
        .or_else(|| number_u16(object, &["persistent-keepalive", "persistent_keepalive"]));
    proxy.reserved = peer.map_or_else(
        || byte_list(object, &["reserved"]),
        |peer| byte_list(peer, &["reserved"]),
    );
}

fn text(object: &Map<String, Value>, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| object.get(*key))
        .map(value_string)
        .unwrap_or_default()
}

fn value_text(object: &Map<String, Value>, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| object.get(*key))
        .map(|value| match value {
            Value::String(value) => value.clone(),
            _ => serde_json::to_string(value).unwrap_or_default(),
        })
        .unwrap_or_default()
}

fn value_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        _ => String::new(),
    }
}

fn non_empty(value: String, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_owned()
    } else {
        value
    }
}

fn boolean(object: &Map<String, Value>, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| match object.get(*key)? {
        Value::Bool(value) => Some(*value),
        Value::String(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "true" => Some(true),
            "0" | "false" => Some(false),
            _ => None,
        },
        Value::Number(value) => value.as_u64().map(|value| value != 0),
        _ => None,
    })
}

fn number_u16(object: &Map<String, Value>, keys: &[&str]) -> Option<u16> {
    number_u64(object, keys).and_then(|value| value.try_into().ok())
}

fn number_u32(object: &Map<String, Value>, keys: &[&str]) -> Option<u32> {
    number_u64(object, keys).and_then(|value| value.try_into().ok())
}

fn number_u64(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter().find_map(|key| match object.get(*key)? {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    })
}

fn duration_seconds(object: &Map<String, Value>, keys: &[&str]) -> Option<u32> {
    let value = text(object, keys);
    if let Ok(seconds) = value.parse() {
        return Some(seconds);
    }
    value.strip_suffix('s')?.parse().ok()
}

fn string_list(object: &Map<String, Value>, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .map(|value| match value {
            Value::Array(values) => values
                .iter()
                .map(value_string)
                .filter(|value| !value.is_empty())
                .collect(),
            Value::String(value) => value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            _ => Vec::new(),
        })
        .unwrap_or_default()
}

fn first_string(object: &Map<String, Value>, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| object.get(*key))
        .map(|value| match value {
            Value::Array(values) => values.first().map(value_string).unwrap_or_default(),
            _ => value_string(value),
        })
        .unwrap_or_default()
}

fn byte_list(object: &Map<String, Value>, keys: &[&str]) -> Vec<u8> {
    keys.iter()
        .find_map(|key| object.get(*key))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_u64)
                .filter_map(|value| value.try_into().ok())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use crate::export::{to_clash, to_singbox};

    use super::*;

    #[test]
    fn parses_clash_yaml_with_snell_and_wireguard() {
        let nodes = parse_subscription(
            r#"
proxies:
  - name: snell
    type: snell
    server: snell.example
    port: 44046
    psk: secret
    version: 3
    obfs-opts: {mode: http, host: cdn.example}
  - name: wg
    type: wireguard
    server: wg.example
    port: 51820
    ip: 10.0.0.2/32
    ipv6: fd00::2/128
    private-key: private
    public-key: public
    pre-shared-key: shared
    allowed-ips: [0.0.0.0/0, "::/0"]
    reserved: [1, 2, 3]
    mtu: 1420
"#,
            4,
        )
        .unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].kind, ProxyKind::Snell);
        assert_eq!(nodes[0].snell_version, Some(3));
        assert_eq!(nodes[1].kind, ProxyKind::Wireguard);
        assert_eq!(nodes[1].wireguard_address.len(), 2);
        assert_eq!(nodes[1].reserved, [1, 2, 3]);
        assert!(nodes.iter().all(|node| node.group_id == 4));

        let clash: Value = serde_yaml::from_str(&to_clash(&nodes, false, false).unwrap()).unwrap();
        assert_eq!(clash["proxies"][0]["type"], "snell");
        assert_eq!(clash["proxies"][0]["obfs-opts"]["host"], "cdn.example");
        assert_eq!(clash["proxies"][1]["type"], "wireguard");
        assert_eq!(clash["proxies"][1]["reserved"][2], 3);

        let singbox: Value =
            serde_json::from_str(&to_singbox(&nodes, false, false).unwrap()).unwrap();
        assert!(
            singbox["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .all(|outbound| outbound["tag"] != "snell")
        );
        assert_eq!(singbox["endpoints"][0]["tag"], "wg");
        assert_eq!(singbox["endpoints"][0]["peers"][0]["public_key"], "public");
        let global = singbox["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|outbound| outbound["tag"] == "GLOBAL")
            .unwrap();
        assert!(
            global["outbounds"]
                .as_array()
                .unwrap()
                .contains(&"wg".into())
        );
        assert!(
            !global["outbounds"]
                .as_array()
                .unwrap()
                .contains(&"snell".into())
        );
    }

    #[test]
    fn parses_singbox_wireguard_endpoint() {
        let nodes = parse_subscription(
            r#"{
  "endpoints": [{
    "type": "wireguard",
    "tag": "wg",
    "address": ["10.0.0.2/32", "fd00::2/128"],
    "private_key": "private",
    "mtu": 1420,
    "peers": [{
      "address": "wg.example",
      "port": 51820,
      "public_key": "public",
      "pre_shared_key": "shared",
      "allowed_ips": ["0.0.0.0/0", "::/0"],
      "reserved": [1, 2, 3]
    }]
  }]
}"#,
            2,
        )
        .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].server, "wg.example");
        assert_eq!(nodes[0].public_key, "public");
        assert_eq!(nodes[0].reserved, [1, 2, 3]);
    }
}
