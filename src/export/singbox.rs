use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value, json};

use crate::{
    config::RulesetTransform,
    error::{AppError, Result},
    external::{GroupKind, LoadedRuleset, ProxyGroup},
    group,
    model::{Proxy, ProxyKind},
    rules::parse_common_rules,
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
    to_singbox_full(
        nodes,
        base,
        &[],
        &[],
        false,
        0,
        &HashMap::new(),
        0,
        append_type,
        sort,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn to_singbox_full(
    nodes: &[Proxy],
    base: Option<&str>,
    groups: &[ProxyGroup],
    rulesets: &[LoadedRuleset],
    overwrite_rules: bool,
    max_rules: usize,
    ruleset_transforms: &HashMap<String, RulesetTransform>,
    ruleset_update_interval: u64,
    append_type: bool,
    sort: bool,
) -> Result<String> {
    let nodes = prepare_nodes(nodes, append_type, sort);
    let mut outbounds = vec![
        json!({"type": "direct", "tag": "DIRECT"}),
        json!({"type": "block", "tag": "REJECT"}),
    ];
    outbounds.extend(nodes.iter().map(proxy_value));
    if groups.is_empty() {
        let names: Vec<_> = nodes
            .iter()
            .map(|node| node.name.clone())
            .chain(["DIRECT".into()])
            .collect();
        outbounds.push(json!({"type": "selector", "tag": "GLOBAL", "outbounds": names}));
    } else {
        outbounds.extend(groups.iter().map(|group_config| {
            let mut outbound = Map::new();
            outbound.insert(
                "type".into(),
                match group_config.kind {
                    GroupKind::Select | GroupKind::Relay => "selector",
                    GroupKind::UrlTest | GroupKind::Fallback | GroupKind::LoadBalance => "urltest",
                }
                .into(),
            );
            outbound.insert("tag".into(), group_config.name.clone().into());
            outbound.insert(
                "outbounds".into(),
                json!(group::members(group_config, &nodes)),
            );
            if matches!(
                group_config.kind,
                GroupKind::UrlTest | GroupKind::Fallback | GroupKind::LoadBalance
            ) {
                if !group_config.url.is_empty() {
                    outbound.insert("url".into(), group_config.url.clone().into());
                }
                outbound.insert(
                    "interval".into(),
                    if group_config.interval > 0 {
                        format!("{}s", group_config.interval)
                    } else {
                        "5m".into()
                    }
                    .into(),
                );
            }
            Value::Object(outbound)
        }));
    }
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
    let mut route_rules = if overwrite_rules {
        Vec::new()
    } else {
        route
            .get("rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let mut remote_rule_sets = route
        .get("rule_set")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut remote_tags: HashSet<String> = remote_rule_sets
        .iter()
        .filter_map(|ruleset| ruleset.get("tag").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect();
    let mut generated = 0usize;
    let mut final_outbound = None;
    for ruleset in rulesets {
        if max_rules > 0 && generated >= max_rules {
            break;
        }
        let remaining = if max_rules == 0 {
            0
        } else {
            max_rules - generated
        };
        let mut rule_objects = Vec::new();
        let mut rule_object = Map::new();
        for rule in parse_common_rules(&ruleset.content, ruleset.format, remaining) {
            if matches!(rule.kind.as_str(), "FINAL" | "MATCH") {
                final_outbound = Some(ruleset.group.clone());
                continue;
            }
            let Some(value) = rule.value else { continue };
            if let Some(transform) = ruleset_transforms.get(&rule.kind.to_ascii_lowercase()) {
                if !rule_object.is_empty() {
                    finish_rule(&mut rule_object, &ruleset.group);
                    rule_objects.push(Value::Object(std::mem::take(&mut rule_object)));
                }
                let kind = rule.kind.to_ascii_lowercase();
                let value = value.to_ascii_lowercase();
                let tag = format!("{kind}-{value}");
                if remote_tags.insert(tag.clone()) {
                    remote_rule_sets.push(json!({
                        "tag": tag,
                        "type": "remote",
                        "format": "binary",
                        "url": transform.url_format.replace("%s", &value),
                        "http_client": {"detour": "DIRECT"},
                        "update_interval": format_ruleset_interval(ruleset_update_interval)
                    }));
                }
                rule_objects.push(json!({
                    "action": "route",
                    "rule_set": tag,
                    "outbound": ruleset.group
                }));
                generated += 1;
                if max_rules > 0 && generated >= max_rules {
                    break;
                }
                continue;
            }
            let field = match rule.kind.as_str() {
                "DOMAIN" => "domain",
                "DOMAIN-SUFFIX" => "domain_suffix",
                "DOMAIN-KEYWORD" => "domain_keyword",
                "IP-CIDR" | "IP-CIDR6" => "ip_cidr",
                "SRC-IP-CIDR" => "source_ip_cidr",
                "PROCESS-NAME" => "process_name",
                "SRC-PORT" => "source_port",
                "DST-PORT" => "port",
                "NETWORK" => "network",
                "PROTOCOL" => "protocol",
                "GEOIP" => "geoip",
                "SRC-GEOIP" => "source_geoip",
                "GEOSITE" => "geosite",
                _ => continue,
            };
            rule_object
                .entry(field)
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .expect("sing-box rule field is always an array")
                .push(Value::String(value.to_ascii_lowercase()));
            generated += 1;
            if max_rules > 0 && generated >= max_rules {
                break;
            }
        }
        if !rule_object.is_empty() {
            finish_rule(&mut rule_object, &ruleset.group);
            rule_objects.push(Value::Object(rule_object));
        }
        route_rules.extend(rule_objects);
    }
    route.insert("rules".into(), Value::Array(route_rules));
    if !remote_rule_sets.is_empty() {
        route.insert("rule_set".into(), Value::Array(remote_rule_sets));
    }
    route.insert(
        "final".into(),
        final_outbound
            .unwrap_or_else(|| {
                groups
                    .first()
                    .map_or("GLOBAL", |group| group.name.as_str())
                    .to_owned()
            })
            .into(),
    );
    serde_json::to_string(&config).map_err(|error| {
        AppError::Conversion(format!("sing-box JSON serialization failed: {error}"))
    })
}

fn finish_rule(rule: &mut Map<String, Value>, outbound: &str) {
    rule.insert("action".into(), "route".into());
    rule.insert("outbound".into(), outbound.into());
}

fn format_ruleset_interval(seconds: u64) -> String {
    let seconds = if seconds == 0 {
        5 * 24 * 60 * 60
    } else {
        seconds
    };
    if seconds % (24 * 60 * 60) == 0 {
        format!("{}d", seconds / (24 * 60 * 60))
    } else if seconds % (60 * 60) == 0 {
        format!("{}h", seconds / (60 * 60))
    } else if seconds % 60 == 0 {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
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
            insert_nonempty(&mut object, "heartbeat", &proxy.heartbeat_interval);
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
            if let Some(value) = proxy.hop_interval {
                insert(&mut object, "hop_interval", &format!("{value}s"));
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
        "http" | "h2" => {
            let mut headers = Map::new();
            insert_nonempty(&mut headers, "Host", &proxy.host);
            object.insert(
                "transport".into(),
                json!({
                    "type": "http",
                    "host": [proxy.host],
                    "path": proxy.path,
                    "headers": headers
                }),
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
    } else if proxy.kind == ProxyKind::Trojan {
        tls.insert("alpn".into(), json!(["h2", "http/1.1"]));
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

#[cfg(test)]
mod tests {
    use crate::external::RulesetFormat;

    use super::*;

    #[test]
    fn converts_geo_rules_to_remote_binary_rulesets() {
        let rulesets = [
            LoadedRuleset {
                group: "DIRECT".into(),
                content: "[]GEOIP,CN".into(),
                format: RulesetFormat::Surge,
            },
            LoadedRuleset {
                group: "PROXY".into(),
                content: "[]GEOSITE,OPENAI".into(),
                format: RulesetFormat::Surge,
            },
        ];
        let transforms = HashMap::from([
            (
                "geoip".into(),
                RulesetTransform {
                    name: "geoip".into(),
                    behavior: "ipcidr".into(),
                    url_format: "https://example.test/geoip/%s.srs".into(),
                },
            ),
            (
                "geosite".into(),
                RulesetTransform {
                    name: "geosite".into(),
                    behavior: "domain".into(),
                    url_format: "https://example.test/geosite/%s.srs".into(),
                },
            ),
        ]);
        let output = to_singbox_full(
            &[],
            Some(
                r#"{"route":{"rules":[],"rule_set":[{"tag":"existing","type":"local","path":"existing.srs"}]}}"#,
            ),
            &[],
            &rulesets,
            false,
            0,
            &transforms,
            432_000,
            false,
            false,
        )
        .unwrap();
        let config: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(config["route"]["rules"][0]["rule_set"], "geoip-cn");
        assert_eq!(config["route"]["rules"][1]["rule_set"], "geosite-openai");
        let rule_sets = config["route"]["rule_set"].as_array().unwrap();
        assert!(rule_sets.iter().any(|ruleset| ruleset["tag"] == "existing"));
        let geoip = rule_sets
            .iter()
            .find(|ruleset| ruleset["tag"] == "geoip-cn")
            .unwrap();
        assert_eq!(geoip["url"], "https://example.test/geoip/cn.srs");
        assert_eq!(geoip["http_client"]["detour"], "DIRECT");
        assert_eq!(geoip["update_interval"], "5d");
        let geosite = rule_sets
            .iter()
            .find(|ruleset| ruleset["tag"] == "geosite-openai")
            .unwrap();
        assert_eq!(geosite["url"], "https://example.test/geosite/openai.srs");
    }

    #[test]
    fn exports_tuic_heartbeat_and_hysteria_hop_interval() {
        let mut tuic = Proxy::new(ProxyKind::Tuic, "tuic.example".into(), 443);
        tuic.name = "tuic".into();
        tuic.uuid = "uuid".into();
        tuic.password = "secret".into();
        tuic.heartbeat_interval = "10s".into();
        tuic.tls = true;
        let mut hysteria = Proxy::new(ProxyKind::Hysteria2, "hy.example".into(), 443);
        hysteria.name = "hy2".into();
        hysteria.password = "secret".into();
        hysteria.hop_interval = Some(30);
        hysteria.tls = true;
        let output = to_singbox(&[tuic, hysteria], false, false).unwrap();
        let config: Value = serde_json::from_str(&output).unwrap();
        let outbounds = config["outbounds"].as_array().unwrap();
        let tuic = outbounds
            .iter()
            .find(|outbound| outbound["tag"] == "tuic")
            .unwrap();
        let hysteria = outbounds
            .iter()
            .find(|outbound| outbound["tag"] == "hy2")
            .unwrap();
        assert_eq!(tuic["heartbeat"], "10s");
        assert_eq!(hysteria["hop_interval"], "30s");
    }
}
