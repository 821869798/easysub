use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose};
use percent_encoding::percent_decode_str;
use serde_json::Value;
use url::Url;

use crate::{
    error::{AppError, Result},
    model::{Proxy, ProxyKind},
};

pub fn parse_node(input: &str, group_id: u32) -> Result<Proxy> {
    let input = input.trim().trim_matches('"');
    let input = input
        .strip_prefix("tag:")
        .and_then(|tagged| tagged.split_once(',').map(|(_, link)| link))
        .unwrap_or(input);

    let mut proxy = if input.starts_with("https://t.me/socks") || input.starts_with("tg://socks") {
        parse_telegram_proxy(input, ProxyKind::Socks5)?
    } else if input.starts_with("https://t.me/http") || input.starts_with("tg://http") {
        parse_telegram_proxy(
            input,
            if input.contains("/https") {
                ProxyKind::Https
            } else {
                ProxyKind::Http
            },
        )?
    } else if input.starts_with("ss://") {
        parse_shadowsocks(input)?
    } else if input.starts_with("vmess://") || input.starts_with("vmess1://") {
        parse_vmess(input)?
    } else if input.starts_with("vless://") || input.starts_with("vless1://") {
        parse_url_proxy(input, ProxyKind::Vless)?
    } else if input.starts_with("trojan://") {
        parse_url_proxy(input, ProxyKind::Trojan)?
    } else if input.starts_with("tuic://") {
        parse_url_proxy(input, ProxyKind::Tuic)?
    } else if input.starts_with("anytls://") {
        parse_url_proxy(input, ProxyKind::Anytls)?
    } else if input.starts_with("hysteria2://") || input.starts_with("hy2://") {
        parse_url_proxy(input, ProxyKind::Hysteria2)?
    } else if input.starts_with("socks://") || input.starts_with("socks5://") {
        parse_url_proxy(input, ProxyKind::Socks5)?
    } else if input.starts_with("http://") || input.starts_with("https://") {
        parse_url_proxy(
            input,
            if input.starts_with("https://") {
                ProxyKind::Https
            } else {
                ProxyKind::Http
            },
        )?
    } else {
        return Err(AppError::Unsupported(input.chars().take(32).collect()));
    };
    proxy.group_id = group_id;
    Ok(proxy)
}

pub fn parse_subscription(content: &str, first_group_id: u32) -> Result<Vec<Proxy>> {
    let decoded;
    let text = if content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
        <= 1
        && !looks_like_proxy(content.trim())
    {
        decoded = decode_base64(content.trim())
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok());
        decoded.as_deref().unwrap_or(content)
    } else {
        content
    };

    let mut nodes = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if let Ok(node) = parse_node(line, first_group_id) {
            nodes.push(node);
        }
    }
    if nodes.is_empty() {
        return Err(AppError::Unsupported(
            "subscription contains no supported nodes".into(),
        ));
    }
    Ok(nodes)
}

pub fn looks_like_proxy(value: &str) -> bool {
    [
        "ss://",
        "vmess://",
        "vmess1://",
        "vless://",
        "vless1://",
        "trojan://",
        "tuic://",
        "anytls://",
        "hysteria2://",
        "hy2://",
        "socks://",
        "socks5://",
        "https://t.me/socks",
        "tg://socks",
        "https://t.me/http",
        "tg://http",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
}

fn parse_telegram_proxy(input: &str, kind: ProxyKind) -> Result<Proxy> {
    let url = Url::parse(input)
        .map_err(|error| AppError::BadRequest(format!("invalid Telegram proxy URL: {error}")))?;
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let server = value(&query, &["server"]);
    if server.is_empty() {
        return Err(AppError::BadRequest(
            "Telegram proxy URL has no server".into(),
        ));
    }
    let port = value(&query, &["port"])
        .parse::<u16>()
        .map_err(|_| AppError::BadRequest("invalid Telegram proxy port".into()))?;
    let mut proxy = Proxy::new(kind, server, port);
    proxy.username = value(&query, &["user", "username"]);
    proxy.password = value(&query, &["pass", "password"]);
    proxy.group = value(&query, &["group"]);
    proxy.name = non_empty(
        value(&query, &["remarks"]),
        &format!("{}:{}", proxy.server, proxy.port),
    );
    proxy.tls = kind == ProxyKind::Https;
    Ok(proxy)
}

fn parse_shadowsocks(input: &str) -> Result<Proxy> {
    let raw = input
        .strip_prefix("ss://")
        .ok_or_else(|| AppError::BadRequest("invalid Shadowsocks URL".into()))?;
    let (before_fragment, fragment) = raw.split_once('#').unwrap_or((raw, ""));
    let (authority, query) = before_fragment
        .split_once('?')
        .unwrap_or((before_fragment, ""));

    let decoded_authority;
    let authority = if authority.contains('@') {
        authority
    } else {
        decoded_authority = String::from_utf8(decode_base64(authority)?)
            .map_err(|_| AppError::BadRequest("invalid Shadowsocks base64".into()))?;
        &decoded_authority
    };
    let (secret, endpoint) = authority
        .rsplit_once('@')
        .ok_or_else(|| AppError::BadRequest("Shadowsocks URL has no endpoint".into()))?;
    let decoded_secret;
    let secret = if secret.contains(':') {
        percent_decode(secret)
    } else {
        decoded_secret = String::from_utf8(decode_base64(secret)?)
            .map_err(|_| AppError::BadRequest("invalid Shadowsocks secret".into()))?;
        decoded_secret
    };
    let (method, password) = secret
        .split_once(':')
        .ok_or_else(|| AppError::BadRequest("Shadowsocks secret has no method".into()))?;
    let (server, port) = split_endpoint(endpoint)?;
    let mut proxy = Proxy::new(ProxyKind::Shadowsocks, server, port);
    proxy.method = method.to_owned();
    proxy.password = password.to_owned();
    proxy.name = non_empty_name(fragment, &proxy.server, proxy.port);

    let params: HashMap<_, _> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    if let Some(value) = params.get("plugin") {
        let (plugin, options) = value.split_once(';').unwrap_or((value, ""));
        proxy.plugin = plugin.to_owned();
        proxy.plugin_opts = options.to_owned();
    }
    Ok(proxy)
}

fn parse_vmess(input: &str) -> Result<Proxy> {
    let raw = input
        .split_once("://")
        .map(|(_, value)| value)
        .unwrap_or(input);
    let encoded = raw.split(['?', '#']).next().unwrap_or(raw);
    if input.starts_with("vmess1://") || encoded.contains('@') {
        return parse_vmess_url(input);
    }
    let bytes = decode_base64(encoded)?;
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        return parse_vmess_json(&value);
    }
    let decoded = String::from_utf8(bytes)
        .map_err(|_| AppError::BadRequest("VMess payload is not UTF-8".into()))?;
    if decoded.contains("vmess,") && decoded.contains('=') {
        return parse_vmess_quan(&decoded);
    }
    parse_vmess_shadowrocket(&decoded, raw)
}

fn parse_vmess_json(value: &Value) -> Result<Proxy> {
    let get = |key: &str| json_string(value, key);
    let server = get("add");
    let port = get("port")
        .parse::<u16>()
        .map_err(|_| AppError::BadRequest("invalid VMess port".into()))?;
    let mut proxy = Proxy::new(ProxyKind::Vmess, server, port);
    proxy.name = match get("ps") {
        name if !name.is_empty() => name,
        _ => format!("{}:{}", proxy.server, proxy.port),
    };
    proxy.uuid = get("id");
    proxy.alter_id = get("aid").parse().unwrap_or_default();
    proxy.network = non_empty(get("net"), "tcp");
    proxy.host = get("host");
    proxy.path = get("path");
    if matches!(get("v").as_str(), "" | "1") {
        if let Some((host, path)) = proxy
            .host
            .split_once(';')
            .map(|(host, path)| (host.to_owned(), path.to_owned()))
        {
            proxy.host = host;
            proxy.path = path;
        }
    }
    proxy.tls = !matches!(get("tls").as_str(), "" | "none");
    proxy.server_name = get("sni");
    proxy.method = match get("scy") {
        cipher if !cipher.is_empty() => cipher,
        _ => "auto".into(),
    };
    apply_vmess_defaults(&mut proxy);
    Ok(proxy)
}

fn parse_vmess_url(input: &str) -> Result<Proxy> {
    let normalized;
    let input = if input.starts_with("vmess1://") {
        normalized = input.replacen("vmess1://", "vmess://", 1);
        normalized.as_str()
    } else {
        input
    };
    let url = Url::parse(input)
        .map_err(|error| AppError::BadRequest(format!("invalid VMess URL: {error}")))?;
    let server = url
        .host_str()
        .ok_or_else(|| AppError::BadRequest("VMess URL has no host".into()))?
        .to_owned();
    let port = url
        .port()
        .ok_or_else(|| AppError::BadRequest("VMess URL has no port".into()))?;
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let username = percent_decode(url.username());
    let (transport, tls, credential) = match url.password().map(percent_decode) {
        Some(credential) => {
            let (transport, tls) = username
                .split_once('+')
                .map_or((username.as_str(), false), |(transport, security)| {
                    (transport, security.eq_ignore_ascii_case("tls"))
                });
            (transport.to_owned(), tls, credential)
        }
        None => (
            non_empty(value(&query, &["network"]), "tcp"),
            parse_bool(&value(&query, &["tls"])).unwrap_or(false),
            username,
        ),
    };
    let (uuid, alter_id) = credential
        .rsplit_once('-')
        .filter(|(_, aid)| aid.parse::<u16>().is_ok())
        .map_or((credential.as_str(), 0), |(uuid, aid)| {
            (uuid, aid.parse().unwrap_or_default())
        });
    if uuid.is_empty() {
        return Err(AppError::BadRequest("VMess URL has no UUID".into()));
    }
    let mut proxy = Proxy::new(ProxyKind::Vmess, server, port);
    proxy.uuid = uuid.to_owned();
    proxy.alter_id = alter_id;
    proxy.network = transport;
    proxy.tls = tls;
    proxy.method = non_empty(value(&query, &["security", "cipher"]), "auto");
    proxy.host = value(&query, &["host", "ws.host"]);
    proxy.path = non_empty(
        value(&query, &["path", "key"]),
        url.path().trim_start_matches('/'),
    );
    if !proxy.path.is_empty() && !proxy.path.starts_with('/') {
        proxy.path.insert(0, '/');
    }
    proxy.server_name = value(&query, &["sni", "peer"]);
    proxy.name = non_empty_name(
        url.fragment().unwrap_or_default(),
        &proxy.server,
        proxy.port,
    );
    apply_vmess_defaults(&mut proxy);
    Ok(proxy)
}

fn parse_vmess_shadowrocket(decoded: &str, raw: &str) -> Result<Proxy> {
    let (secret, endpoint) = decoded
        .rsplit_once('@')
        .ok_or_else(|| AppError::BadRequest("unsupported VMess payload".into()))?;
    let (method, uuid) = secret
        .split_once(':')
        .ok_or_else(|| AppError::BadRequest("invalid Shadowrocket VMess secret".into()))?;
    let (server, port) = split_endpoint(endpoint)?;
    let query = raw
        .split_once('?')
        .map(|(_, query)| query.split('#').next().unwrap_or(query))
        .unwrap_or_default();
    let query: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let mut proxy = Proxy::new(ProxyKind::Vmess, server, port);
    proxy.uuid = uuid.to_owned();
    proxy.alter_id = value(&query, &["aid"]).parse().unwrap_or_default();
    proxy.method = non_empty(method.to_owned(), "auto");
    proxy.network = if value(&query, &["obfs"]) == "websocket" {
        "ws".into()
    } else {
        non_empty(value(&query, &["network"]), "tcp")
    };
    proxy.host = value(&query, &["obfsParam", "wsHost"]);
    proxy.path = value(&query, &["path", "wspath"]);
    proxy.tls = parse_bool(&value(&query, &["tls"])).unwrap_or(false);
    proxy.name = non_empty(
        value(&query, &["remarks"]),
        &format!("{}:{}", proxy.server, proxy.port),
    );
    apply_vmess_defaults(&mut proxy);
    Ok(proxy)
}

fn parse_vmess_quan(decoded: &str) -> Result<Proxy> {
    let (name, definition) = decoded
        .split_once('=')
        .ok_or_else(|| AppError::BadRequest("invalid Quan VMess assignment".into()))?;
    let normalized = format!("{},{}", name.trim(), definition.trim());
    let parts: Vec<_> = normalized.split(',').map(str::trim).collect();
    if parts.len() < 6 || !parts[1].eq_ignore_ascii_case("vmess") {
        return Err(AppError::BadRequest("invalid Quan VMess payload".into()));
    }
    let port = parts[3]
        .parse::<u16>()
        .map_err(|_| AppError::BadRequest("invalid Quan VMess port".into()))?;
    let mut proxy = Proxy::new(ProxyKind::Vmess, parts[2].to_owned(), port);
    proxy.name = parts[0].to_owned();
    proxy.method = parts[4].to_owned();
    proxy.uuid = parts[5].trim_matches('"').to_owned();
    proxy.network = "tcp".into();
    for option in &parts[6..] {
        let Some((key, value)) = option.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        match key {
            "group" => proxy.group = value.to_owned(),
            "over-tls" => proxy.tls = value.eq_ignore_ascii_case("true"),
            "tls-host" => proxy.server_name = value.to_owned(),
            "obfs-path" => proxy.path = value.to_owned(),
            "obfs" if value.eq_ignore_ascii_case("ws") => proxy.network = "ws".into(),
            "obfs-header" => {
                for header in value.split(['|', '\r', '\n']) {
                    if let Some((name, value)) = header.split_once(':') {
                        if name.trim().eq_ignore_ascii_case("host") {
                            proxy.host = value.trim().to_owned();
                        }
                    }
                }
            }
            _ => {}
        }
    }
    apply_vmess_defaults(&mut proxy);
    Ok(proxy)
}

fn apply_vmess_defaults(proxy: &mut Proxy) {
    if proxy.network.is_empty() {
        proxy.network = "tcp".into();
    }
    if proxy.path.is_empty() {
        proxy.path = "/".into();
    }
    if proxy.host.is_empty() && proxy.server.parse::<std::net::IpAddr>().is_err() {
        proxy.host = proxy.server.clone();
    }
}

fn non_empty(value: String, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_owned()
    } else {
        value
    }
}

fn parse_url_proxy(input: &str, kind: ProxyKind) -> Result<Proxy> {
    let normalized;
    let input = if input.starts_with("hy2://") {
        normalized = input.replacen("hy2://", "hysteria2://", 1);
        normalized.as_str()
    } else if input.starts_with("vless1://") {
        normalized = input.replacen("vless1://", "vless://", 1);
        normalized.as_str()
    } else if input.starts_with("socks://") {
        normalized = input.replacen("socks://", "socks5://", 1);
        normalized.as_str()
    } else {
        input
    };
    let url = Url::parse(input)
        .map_err(|error| AppError::BadRequest(format!("invalid proxy URL: {error}")))?;
    let server = url
        .host_str()
        .ok_or_else(|| AppError::BadRequest("proxy URL has no host".into()))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| AppError::BadRequest("proxy URL has no port".into()))?;
    let mut proxy = Proxy::new(kind, server, port);
    proxy.name = non_empty_name(
        url.fragment().unwrap_or_default(),
        &proxy.server,
        proxy.port,
    );
    proxy.username = percent_decode(url.username());
    proxy.password = url.password().map(percent_decode).unwrap_or_default();
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();

    match kind {
        ProxyKind::Vless => {
            proxy.uuid = proxy.username.clone();
            proxy.username.clear();
            proxy.flow = value(&query, &["flow"]);
            proxy.network = value(&query, &["type", "network"]);
            if proxy.network.is_empty() {
                proxy.network = "tcp".into();
            }
            proxy.tls = matches!(
                value(&query, &["security"]).as_str(),
                "tls" | "reality" | "xtls"
            );
        }
        ProxyKind::Trojan | ProxyKind::Hysteria2 | ProxyKind::Anytls => {
            if proxy.password.is_empty() {
                proxy.password = if proxy.username.is_empty() {
                    value(&query, &["password", "auth"])
                } else {
                    std::mem::take(&mut proxy.username)
                };
            }
            proxy.tls = true;
            if kind == ProxyKind::Trojan {
                proxy.network = value(&query, &["type", "network"]);
                if parse_bool(&value(&query, &["ws"])).unwrap_or(false) {
                    proxy.network = "ws".into();
                }
                if proxy.network.is_empty() {
                    proxy.network = "tcp".into();
                }
            }
        }
        ProxyKind::Tuic => {
            proxy.uuid = std::mem::take(&mut proxy.username);
            if proxy.uuid.is_empty() {
                proxy.uuid = value(&query, &["uuid"]);
            }
            if proxy.password.is_empty() {
                proxy.password = value(&query, &["password"]);
            }
            proxy.congestion_control = value(&query, &["congestion_control"]);
            proxy.udp_relay_mode = value(&query, &["udp_relay_mode"]);
            proxy.heartbeat_interval = value(&query, &["heartbeat_interval", "heartbeat"]);
            proxy.disable_sni = parse_bool(&value(&query, &["disable_sni"]));
            proxy.reduce_rtt = parse_bool(&value(&query, &["reduce_rtt"]));
            proxy.request_timeout = parse_u32(&value(&query, &["request_timeout"]));
            proxy.max_udp_relay_packet_size =
                parse_u32(&value(&query, &["max_udp_relay_packet_size"]));
            proxy.max_open_streams = parse_u32(&value(&query, &["max_open_streams"]));
            proxy.fast_open = parse_bool(&value(&query, &["fast_open"]));
            proxy.tls = true;
        }
        _ => {}
    }

    proxy.server_name = value(&query, &["sni", "peer", "servername"]);
    proxy.host = value(&query, &["host"]);
    proxy.path = value(&query, &["path", "wspath", "serviceName", "key"]);
    if proxy.network.is_empty() {
        proxy.network = value(&query, &["type", "network"]);
    }
    proxy.fingerprint = value(&query, &["fp", "fingerprint", "pinSHA256", "hpkp"]);
    proxy.public_key = value(&query, &["pbk", "public_key"]);
    proxy.short_id = value(&query, &["sid", "short_id"]);
    proxy.obfs = value(&query, &["obfs"]);
    proxy.obfs_password = value(&query, &["obfs-password", "obfs_password"]);
    proxy.alpn = value(&query, &["alpn"])
        .split(',')
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    proxy.skip_cert_verify = parse_bool(&value(&query, &["insecure", "allowInsecure"]));
    proxy.tcp_fast_open = parse_bool(&value(&query, &["tfo", "fast_open"]));
    proxy.up_mbps = parse_u32(&value(&query, &["upmbps", "up"]));
    proxy.down_mbps = parse_u32(&value(&query, &["downmbps", "down"]));
    proxy.group = value(&query, &["group"]);
    if kind == ProxyKind::Hysteria2 {
        proxy.ports = non_empty(value(&query, &["ports", "mport"]), &proxy.port.to_string());
        proxy.ca = value(&query, &["ca"]);
        proxy.ca_str = value(&query, &["ca_str"]);
        proxy.cwnd = parse_u32(&value(&query, &["cwnd"]));
        proxy.hop_interval = parse_u32(&value(&query, &["hop_interval"]));
    }
    if kind == ProxyKind::Trojan && proxy.network == "ws" && proxy.host.is_empty() {
        proxy.host = proxy.server_name.clone();
    }
    proxy.idle_session_check_interval = parse_u32(&value(&query, &["idle_session_check_interval"]));
    proxy.idle_session_timeout = parse_u32(&value(&query, &["idle_session_timeout"]));
    proxy.min_idle_session = parse_u32(&value(&query, &["min_idle_session"]));
    Ok(proxy)
}

fn value(map: &HashMap<String, String>, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| map.get(*key))
        .cloned()
        .unwrap_or_default()
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

fn parse_u32(value: &str) -> Option<u32> {
    value.parse().ok()
}

fn json_string(value: &Value, key: &str) -> String {
    match value.get(key) {
        Some(Value::String(value)) => value.clone(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => String::new(),
    }
}

fn split_endpoint(endpoint: &str) -> Result<(String, u16)> {
    let url = Url::parse(&format!("tcp://{endpoint}"))
        .map_err(|error| AppError::BadRequest(format!("invalid endpoint: {error}")))?;
    let host = url
        .host_str()
        .ok_or_else(|| AppError::BadRequest("endpoint has no host".into()))?;
    let port = url
        .port()
        .ok_or_else(|| AppError::BadRequest("endpoint has no port".into()))?;
    Ok((host.to_owned(), port))
}

fn decode_base64(input: &str) -> Result<Vec<u8>> {
    let input = input.trim();
    for engine in [
        &general_purpose::URL_SAFE_NO_PAD,
        &general_purpose::URL_SAFE,
        &general_purpose::STANDARD_NO_PAD,
        &general_purpose::STANDARD,
    ] {
        if let Ok(bytes) = engine.decode(input) {
            return Ok(bytes);
        }
    }
    Err(AppError::BadRequest("invalid base64".into()))
}

fn percent_decode(value: &str) -> String {
    percent_decode_str(value).decode_utf8_lossy().into_owned()
}

fn non_empty_name(fragment: &str, server: &str, port: u16) -> String {
    let decoded = percent_decode(fragment);
    if decoded.is_empty() {
        format!("{server}:{port}")
    } else {
        decoded
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn malformed_proxy_and_subscription_inputs_never_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..4096)
        ) {
            let input = String::from_utf8_lossy(&bytes);
            let _ = parse_node(&input, 0);
            let _ = parse_subscription(&input, 0);
        }
    }

    #[test]
    fn parses_vmess_fixture() {
        let input = "vmess://ew0KICAicHMiOiAicnVzc2lhbi1jbG91ZCIsDQogICJhZGQiOiAiMTg1LjE3Ny4yMTYuMTM0IiwNCiAgInBvcnQiOiAiMjI1MzUiLA0KICAiaWQiOiAiNTIwNTAwNTctZjVlMS00YjllLWI3OGItNWY0OWI1NDlmZDIxIiwNCiAgImFpZCI6ICI2NCIsDQogICJuZXQiOiAia2NwIiwNCiAgInR5cGUiOiAic3J0cCIsDQogICJob3N0IjogIiIsDQogICJ0bHMiOiAiIg0KfQ==";
        let proxy = parse_node(input, 3).unwrap();
        assert_eq!(proxy.kind, ProxyKind::Vmess);
        assert_eq!(proxy.server, "185.177.216.134");
        assert_eq!(proxy.port, 22535);
        assert_eq!(proxy.group_id, 3);
    }

    #[test]
    fn parses_standard_and_kitsunebi_vmess_urls() {
        let standard = parse_node(
            "vmess://ws+tls:52050057-f5e1-4b9e-b789-5f49b549fd21-2@edge.example:443?host=cdn.example&path=%2Fws&sni=tls.example#standard",
            0,
        )
        .unwrap();
        assert_eq!(standard.uuid, "52050057-f5e1-4b9e-b789-5f49b549fd21");
        assert_eq!(standard.alter_id, 2);
        assert_eq!(standard.network, "ws");
        assert!(standard.tls);
        assert_eq!(standard.host, "cdn.example");
        assert_eq!(standard.path, "/ws");

        let kitsunebi = parse_node(
            "vmess1://52050057-f5e1-4b9e-b789-5f49b549fd21@kit.example:8443/ws?network=ws&tls=true&ws.host=cdn.kit.example#kit",
            0,
        )
        .unwrap();
        assert_eq!(kitsunebi.network, "ws");
        assert!(kitsunebi.tls);
        assert_eq!(kitsunebi.host, "cdn.kit.example");
        assert_eq!(kitsunebi.path, "/ws");
    }

    #[test]
    fn parses_shadowrocket_vmess_payload() {
        let encoded = general_purpose::URL_SAFE_NO_PAD
            .encode("auto:52050057-f5e1-4b9e-b789-5f49b549fd21@rocket.example:443");
        let proxy = parse_node(
            &format!(
                "vmess://{encoded}?remarks=Rocket+Node&obfs=websocket&obfsParam=cdn.example&path=%2Frocket&tls=true"
            ),
            0,
        )
        .unwrap();
        assert_eq!(proxy.name, "Rocket Node");
        assert_eq!(proxy.network, "ws");
        assert_eq!(proxy.host, "cdn.example");
        assert_eq!(proxy.path, "/rocket");
        assert!(proxy.tls);
    }

    #[test]
    fn parses_quan_vmess_payload() {
        let quan = r#"Quan Node = vmess, quan.example, 443, auto, "52050057-f5e1-4b9e-b789-5f49b549fd21", group=Quan, over-tls=true, tls-host=tls.quan.example, obfs=ws, obfs-path="/quan", obfs-header="Host: cdn.quan.example""#;
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(quan);
        let proxy = parse_node(&format!("vmess://{encoded}"), 0).unwrap();
        assert_eq!(proxy.name, "Quan Node");
        assert_eq!(proxy.group, "Quan");
        assert_eq!(proxy.network, "ws");
        assert_eq!(proxy.host, "cdn.quan.example");
        assert_eq!(proxy.path, "/quan");
        assert!(proxy.tls);
    }

    #[test]
    fn parses_anytls_session_fields() {
        let proxy = parse_node("anytls://mypass@192.168.1.1:8443?peer=test.com&idle_session_check_interval=30&idle_session_timeout=60&min_idle_session=2", 0).unwrap();
        assert_eq!(proxy.password, "mypass");
        assert_eq!(proxy.server_name, "test.com");
        assert_eq!(proxy.idle_session_timeout, Some(60));
    }

    #[test]
    fn parses_vless_reality_grpc_fields() {
        let proxy = parse_node(
            "vless1://52050057-f5e1-4b9e-b789-5f49b549fd21@vless.example:443?security=reality&type=grpc&serviceName=grpc-service&pbk=public-key&sid=01&fp=chrome&sni=tls.example#vless",
            0,
        )
        .unwrap();
        assert_eq!(proxy.kind, ProxyKind::Vless);
        assert_eq!(proxy.network, "grpc");
        assert_eq!(proxy.path, "grpc-service");
        assert_eq!(proxy.public_key, "public-key");
        assert_eq!(proxy.short_id, "01");
        assert_eq!(proxy.fingerprint, "chrome");
        assert!(proxy.tls);
    }

    #[test]
    fn parses_trojan_websocket_aliases() {
        let proxy = parse_node(
            "trojan://secret@trojan.example:443?ws=1&wspath=%2Fsocket&peer=cdn.example&group=Trojan#trojan",
            0,
        )
        .unwrap();
        assert_eq!(proxy.network, "ws");
        assert_eq!(proxy.path, "/socket");
        assert_eq!(proxy.host, "cdn.example");
        assert_eq!(proxy.server_name, "cdn.example");
        assert_eq!(proxy.group, "Trojan");
    }

    #[test]
    fn parses_extended_tuic_and_hysteria2_fields() {
        let tuic = parse_node(
            "tuic://tuic.example:443?uuid=52050057-f5e1-4b9e-b789-5f49b549fd21&password=secret&heartbeat_interval=10s&disable_sni=true&reduce_rtt=1&request_timeout=8000&udp_relay_mode=native&congestion_control=bbr&max_udp_relay_packet_size=1500&max_open_streams=100&fast_open=true&sni=tls.example#tuic",
            0,
        )
        .unwrap();
        assert_eq!(tuic.uuid, "52050057-f5e1-4b9e-b789-5f49b549fd21");
        assert_eq!(tuic.heartbeat_interval, "10s");
        assert_eq!(tuic.disable_sni, Some(true));
        assert_eq!(tuic.reduce_rtt, Some(true));
        assert_eq!(tuic.request_timeout, Some(8000));
        assert_eq!(tuic.max_open_streams, Some(100));

        let hysteria = parse_node(
            "hy2://hy.example:443?password=secret&mport=20000-30000&up=100&down=200&obfs=salamander&obfs-password=obfs&pinSHA256=pin&ca=ca.pem&ca_str=certificate&cwnd=64&hop_interval=30&sni=tls.example#hy2",
            0,
        )
        .unwrap();
        assert_eq!(hysteria.ports, "20000-30000");
        assert_eq!(hysteria.up_mbps, Some(100));
        assert_eq!(hysteria.down_mbps, Some(200));
        assert_eq!(hysteria.fingerprint, "pin");
        assert_eq!(hysteria.ca, "ca.pem");
        assert_eq!(hysteria.ca_str, "certificate");
        assert_eq!(hysteria.cwnd, Some(64));
        assert_eq!(hysteria.hop_interval, Some(30));
    }

    #[test]
    fn parses_sip002_shadowsocks() {
        let proxy = parse_node("ss://YWVzLTEyOC1nY206cGFzcw@example.com:443#node", 0).unwrap();
        assert_eq!(proxy.method, "aes-128-gcm");
        assert_eq!(proxy.password, "pass");
        assert_eq!(proxy.name, "node");
    }

    #[test]
    fn subscription_nodes_share_the_source_group_id() {
        let nodes = parse_subscription(
            "trojan://one@one.example:443#one\ntrojan://two@two.example:443#two",
            7,
        )
        .unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().all(|node| node.group_id == 7));
    }

    #[test]
    fn parses_telegram_socks_and_http_links() {
        let socks = parse_node(
            "tg://socks?server=socks.example&port=1080&user=test&pass=secret&remarks=Telegram+SOCKS&group=TG",
            0,
        )
        .unwrap();
        assert_eq!(socks.kind, ProxyKind::Socks5);
        assert_eq!(socks.username, "test");
        assert_eq!(socks.password, "secret");
        assert_eq!(socks.name, "Telegram SOCKS");
        assert_eq!(socks.group, "TG");

        let http = parse_node(
            "https://t.me/https?server=http.example&port=8443&user=test&pass=secret&remarks=Telegram+HTTPS",
            0,
        )
        .unwrap();
        assert_eq!(http.kind, ProxyKind::Https);
        assert!(http.tls);
    }
}
