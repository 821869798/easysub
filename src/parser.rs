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

    let mut proxy = if input.starts_with("ss://") {
        parse_shadowsocks(input)?
    } else if input.starts_with("vmess://") || input.starts_with("vmess1://") {
        parse_vmess(input)?
    } else if input.starts_with("vless://") {
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
    for (index, line) in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        if let Ok(node) = parse_node(line, first_group_id.saturating_add(index as u32)) {
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
        "trojan://",
        "tuic://",
        "anytls://",
        "hysteria2://",
        "hy2://",
        "socks://",
        "socks5://",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
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
    let encoded = input
        .split_once("://")
        .map(|(_, value)| value)
        .unwrap_or(input);
    let encoded = encoded.split(['?', '#']).next().unwrap_or(encoded);
    let bytes = decode_base64(encoded)?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| AppError::BadRequest(format!("invalid VMess JSON: {error}")))?;
    let get = |key: &str| json_string(&value, key);
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
    proxy.network = get("net");
    proxy.host = get("host");
    proxy.path = get("path");
    proxy.tls = !matches!(get("tls").as_str(), "" | "none");
    proxy.server_name = get("sni");
    proxy.method = match get("scy") {
        cipher if !cipher.is_empty() => cipher,
        _ => "auto".into(),
    };
    Ok(proxy)
}

fn parse_url_proxy(input: &str, kind: ProxyKind) -> Result<Proxy> {
    let normalized;
    let input = if input.starts_with("hy2://") {
        normalized = input.replacen("hy2://", "hysteria2://", 1);
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
        }
        ProxyKind::Tuic => {
            proxy.uuid = std::mem::take(&mut proxy.username);
            proxy.congestion_control = value(&query, &["congestion_control"]);
            proxy.udp_relay_mode = value(&query, &["udp_relay_mode"]);
            proxy.tls = true;
        }
        _ => {}
    }

    proxy.server_name = value(&query, &["sni", "peer", "servername"]);
    proxy.host = value(&query, &["host"]);
    proxy.path = value(&query, &["path"]);
    if proxy.network.is_empty() {
        proxy.network = value(&query, &["type", "network"]);
    }
    proxy.fingerprint = value(&query, &["fp", "fingerprint"]);
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
    if value.is_empty() {
        None
    } else {
        value.parse().ok()
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
    use super::*;

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
    fn parses_anytls_session_fields() {
        let proxy = parse_node("anytls://mypass@192.168.1.1:8443?peer=test.com&idle_session_check_interval=30&idle_session_timeout=60&min_idle_session=2", 0).unwrap();
        assert_eq!(proxy.password, "mypass");
        assert_eq!(proxy.server_name, "test.com");
        assert_eq!(proxy.idle_session_timeout, Some(60));
    }

    #[test]
    fn parses_sip002_shadowsocks() {
        let proxy = parse_node("ss://YWVzLTEyOC1nY206cGFzcw@example.com:443#node", 0).unwrap();
        assert_eq!(proxy.method, "aes-128-gcm");
        assert_eq!(proxy.password, "pass");
        assert_eq!(proxy.name, "node");
    }
}
