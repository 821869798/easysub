use serde_json::{Map, Value, json};

use crate::{
    error::{AppError, Result},
    model::{Proxy, ProxyKind},
};

use super::prepare_nodes;

pub fn to_singbox(nodes: &[Proxy], append_type: bool, sort: bool) -> Result<String> {
    to_singbox_with_base(nodes, None, append_type, sort)
}

pub fn to_singbox_with_base(
    nodes: &[Proxy],
    base: Option<&str>,
    append_type: bool,
    sort: bool,
) -> Result<String> {
    let nodes = prepare_nodes(nodes, append_type, sort);
    let mut outbounds = vec![
        json!({"type": "direct", "tag": "DIRECT"}),
        json!({"type": "block", "tag": "REJECT"}),
    ];
    outbounds.extend(nodes.iter().map(proxy_value));
    let names: Vec<_> = nodes
        .iter()
        .map(|node| node.name.clone())
        .chain(["DIRECT".into()])
        .collect();
    outbounds.push(json!({"type": "selector", "tag": "GLOBAL", "outbounds": names}));
    let mut config = match base {
        Some(base) => serde_json::from_str::<Value>(base).map_err(|error| {
            AppError::Conversion(format!("sing-box base JSON is invalid: {error}"))
        })?,
        None => json!({
            "log": {"level": "info", "timestamp": true},
            "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}],
            "route": {"rules": [], "auto_detect_interface": true}
        }),
    };
    let object = config
        .as_object_mut()
        .ok_or_else(|| AppError::Conversion("sing-box base must be a JSON object".into()))?;
    object.insert("outbounds".into(), Value::Array(outbounds));
    let route = object
        .entry("route")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| AppError::Conversion("sing-box route must be an object".into()))?;
    route.entry("rules").or_insert_with(|| json!([]));
    route.entry("final").or_insert_with(|| "GLOBAL".into());
    serde_json::to_string(&config).map_err(|error| {
        AppError::Conversion(format!("sing-box JSON serialization failed: {error}"))
    })
}

fn proxy_value(proxy: &Proxy) -> Value {
    let mut object = Map::new();
    insert(&mut object, "tag", &proxy.name);
    insert(&mut object, "server", &proxy.server);
    object.insert("server_port".into(), proxy.port.into());
    match proxy.kind {
        ProxyKind::Shadowsocks => {
            insert(&mut object, "type", "shadowsocks");
            insert(&mut object, "method", &proxy.method);
            insert(&mut object, "password", &proxy.password);
            insert_nonempty(&mut object, "plugin", &proxy.plugin);
            insert_nonempty(&mut object, "plugin_opts", &proxy.plugin_opts);
        }
        ProxyKind::Vmess => {
            insert(&mut object, "type", "vmess");
            insert(&mut object, "uuid", &proxy.uuid);
            object.insert("alter_id".into(), proxy.alter_id.into());
            insert(
                &mut object,
                "security",
                if proxy.method.is_empty() {
                    "auto"
                } else {
                    &proxy.method
                },
            );
            add_transport(&mut object, proxy);
            add_tls(&mut object, proxy);
        }
        ProxyKind::Vless => {
            insert(&mut object, "type", "vless");
            insert(&mut object, "uuid", &proxy.uuid);
            insert_nonempty(&mut object, "flow", &proxy.flow);
            add_transport(&mut object, proxy);
            add_tls(&mut object, proxy);
        }
        ProxyKind::Trojan => {
            insert(&mut object, "type", "trojan");
            insert(&mut object, "password", &proxy.password);
            add_transport(&mut object, proxy);
            add_tls(&mut object, proxy);
        }
        ProxyKind::Tuic => {
            insert(&mut object, "type", "tuic");
            insert(&mut object, "uuid", &proxy.uuid);
            insert(&mut object, "password", &proxy.password);
            insert_nonempty(&mut object, "congestion_control", &proxy.congestion_control);
            insert_nonempty(&mut object, "udp_relay_mode", &proxy.udp_relay_mode);
            add_tls(&mut object, proxy);
        }
        ProxyKind::Anytls => {
            insert(&mut object, "type", "anytls");
            insert(&mut object, "password", &proxy.password);
            add_tls(&mut object, proxy);
            insert_duration(
                &mut object,
                "idle_session_check_interval",
                proxy.idle_session_check_interval,
            );
            insert_duration(
                &mut object,
                "idle_session_timeout",
                proxy.idle_session_timeout,
            );
            if let Some(value) = proxy.min_idle_session {
                object.insert("min_idle_session".into(), value.into());
            }
        }
        ProxyKind::Hysteria2 => {
            insert(&mut object, "type", "hysteria2");
            insert(&mut object, "password", &proxy.password);
            if !proxy.obfs.is_empty() {
                object.insert(
                    "obfs".into(),
                    json!({"type": proxy.obfs, "password": proxy.obfs_password}),
                );
            }
            if let Some(value) = proxy.up_mbps {
                object.insert("up_mbps".into(), value.into());
            }
            if let Some(value) = proxy.down_mbps {
                object.insert("down_mbps".into(), value.into());
            }
            add_tls(&mut object, proxy);
        }
        ProxyKind::Http | ProxyKind::Https => {
            insert(&mut object, "type", "http");
            insert_nonempty(&mut object, "username", &proxy.username);
            insert_nonempty(&mut object, "password", &proxy.password);
            if proxy.kind == ProxyKind::Https {
                object.insert("tls".into(), json!({"enabled": true}));
            }
        }
        ProxyKind::Socks5 => {
            insert(&mut object, "type", "socks");
            object.insert("version".into(), "5".into());
            insert_nonempty(&mut object, "username", &proxy.username);
            insert_nonempty(&mut object, "password", &proxy.password);
        }
        ProxyKind::Wireguard => insert(&mut object, "type", "wireguard"),
    }
    if proxy.udp == Some(false) {
        insert(&mut object, "network", "tcp");
    }
    if let Some(tfo) = proxy.tcp_fast_open {
        object.insert("tcp_fast_open".into(), tfo.into());
    }
    Value::Object(object)
}

fn add_transport(object: &mut Map<String, Value>, proxy: &Proxy) {
    match proxy.network.as_str() {
        "ws" => {
            let mut headers = Map::new();
            insert_nonempty(&mut headers, "Host", &proxy.host);
            object.insert(
                "transport".into(),
                json!({"type": "ws", "path": proxy.path, "headers": headers}),
            );
        }
        "grpc" => {
            object.insert(
                "transport".into(),
                json!({"type": "grpc", "service_name": proxy.path}),
            );
        }
        "http" => {
            object.insert(
                "transport".into(),
                json!({"type": "http", "host": [proxy.host], "path": proxy.path}),
            );
        }
        _ => {}
    }
}

fn add_tls(object: &mut Map<String, Value>, proxy: &Proxy) {
    if !proxy.tls {
        return;
    }
    let mut tls = Map::new();
    tls.insert("enabled".into(), true.into());
    insert_nonempty(&mut tls, "server_name", &proxy.server_name);
    if let Some(insecure) = proxy.skip_cert_verify {
        tls.insert("insecure".into(), insecure.into());
    }
    if !proxy.alpn.is_empty() {
        tls.insert("alpn".into(), json!(proxy.alpn));
    }
    if !proxy.fingerprint.is_empty() {
        tls.insert(
            "utls".into(),
            json!({"enabled": true, "fingerprint": proxy.fingerprint}),
        );
    }
    if !proxy.public_key.is_empty() {
        tls.insert(
            "reality".into(),
            json!({"enabled": true, "public_key": proxy.public_key, "short_id": proxy.short_id}),
        );
    }
    object.insert("tls".into(), Value::Object(tls));
}

fn insert(object: &mut Map<String, Value>, key: &str, value: &str) {
    object.insert(key.into(), Value::String(value.into()));
}

fn insert_nonempty(object: &mut Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        insert(object, key, value);
    }
}

fn insert_duration(object: &mut Map<String, Value>, key: &str, value: Option<u32>) {
    if let Some(value) = value {
        insert(object, key, &format!("{value}s"));
    }
}
