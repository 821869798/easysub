use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value, json};

use crate::{
    config::RulesetTransform,
    error::{AppError, Result},
    external::{GroupKind, LoadedRuleset, ProxyGroup},
    group,
    model::{Proxy, ProxyKind},
    rules::{RuleLine, parse_common_rules_filtered},
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
    let mut nodes = prepare_nodes(nodes, append_type, sort);
    if nodes.iter().any(|node| node.kind == ProxyKind::Snell) {
        nodes.retain(|node| node.kind != ProxyKind::Snell);
    }
    let mut outbounds = vec![
        json!({"type": "direct", "tag": "DIRECT"}),
        json!({"type": "block", "tag": "REJECT"}),
    ];
    outbounds.extend(
        nodes
            .iter()
            .filter(|node| node.kind != ProxyKind::Wireguard)
            .map(proxy_value),
    );
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
                    GroupKind::Select | GroupKind::Relay | GroupKind::Ssid => "selector",
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
    let mut endpoints = object
        .get("endpoints")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    endpoints.extend(
        nodes
            .iter()
            .filter(|node| node.kind == ProxyKind::Wireguard)
            .map(wireguard_value),
    );
    if !endpoints.is_empty() {
        object.insert("endpoints".into(), Value::Array(endpoints));
    }
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
        for rule in
            parse_common_rules_filtered(&ruleset.content, ruleset.format, remaining, |rule| {
                is_singbox_rule(rule, ruleset_transforms)
            })
        {
            if matches!(rule.kind.as_str(), "FINAL" | "MATCH") {
                final_outbound = Some(ruleset.group.clone());
                continue;
            }
            let Some(value) = rule.value else { continue };
            if let Some(transform) = ruleset_transforms.get(&rule.kind.to_ascii_lowercase()) {
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
            let Some((field, value, scalar)) = singbox_rule_value(&rule.kind, &value) else {
                continue;
            };
            push_singbox_rule(&mut rule_objects, field, value, scalar);
            generated += 1;
            if max_rules > 0 && generated >= max_rules {
                break;
            }
        }
        for rule in &mut rule_objects {
            let object = rule
                .as_object_mut()
                .expect("generated sing-box rule is always an object");
            if !object.contains_key("action") {
                finish_rule(object, &ruleset.group);
            }
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

fn is_singbox_rule(
    rule: &RuleLine,
    ruleset_transforms: &HashMap<String, RulesetTransform>,
) -> bool {
    if matches!(rule.kind.as_str(), "FINAL" | "MATCH") {
        return true;
    }
    let Some(value) = rule.value.as_deref() else {
        return false;
    };
    ruleset_transforms.contains_key(&rule.kind.to_ascii_lowercase())
        || singbox_rule_value(&rule.kind, value).is_some()
}

fn singbox_rule_value(kind: &str, value: &str) -> Option<(&'static str, Value, bool)> {
    let string = |field, value: String| Some((field, Value::String(value), false));
    let lowered = || value.to_ascii_lowercase();
    match kind {
        "DOMAIN" => string("domain", lowered()),
        "DOMAIN-SUFFIX" => string("domain_suffix", lowered()),
        "DOMAIN-KEYWORD" => string("domain_keyword", lowered()),
        "DOMAIN-REGEX" => string("domain_regex", value.to_owned()),
        "IP-CIDR" | "IP-CIDR6" => string("ip_cidr", value.to_owned()),
        "SRC-IP-CIDR" => string("source_ip_cidr", value.to_owned()),
        "PROCESS-NAME" => string("process_name", value.to_owned()),
        "PROCESS-PATH" => string("process_path", value.to_owned()),
        "PROCESS-PATH-REGEX" => string("process_path_regex", value.to_owned()),
        "PACKAGE-NAME" => string("package_name", value.to_owned()),
        "PACKAGE-NAME-REGEX" => string("package_name_regex", value.to_owned()),
        "SRC-PORT" => value
            .parse::<u16>()
            .ok()
            .map(|value| ("source_port", value.into(), false)),
        "DST-PORT" | "PORT" => value
            .parse::<u16>()
            .ok()
            .map(|value| ("port", value.into(), false)),
        "SRC-PORT-RANGE" => {
            normalize_port_range(value).map(|value| ("source_port_range", value.into(), false))
        }
        "PORT-RANGE" => {
            normalize_port_range(value).map(|value| ("port_range", value.into(), false))
        }
        "NETWORK" => string("network", lowered()),
        "PROTOCOL" => string("protocol", lowered()),
        "INBOUND" => string("inbound", value.to_owned()),
        "IP-VERSION" => value
            .parse::<u8>()
            .ok()
            .filter(|value| matches!(value, 4 | 6))
            .map(|value| ("ip_version", value.into(), true)),
        "USER" => string("user", value.to_owned()),
        "USER-ID" => value
            .parse::<i32>()
            .ok()
            .map(|value| ("user_id", value.into(), false)),
        "GEOIP" => string("geoip", lowered()),
        "SRC-GEOIP" => string("source_geoip", lowered()),
        "GEOSITE" => string("geosite", lowered()),
        _ => None,
    }
}

fn push_singbox_rule(rules: &mut Vec<Value>, field: &'static str, value: Value, scalar: bool) {
    if scalar {
        let mut rule = Map::new();
        rule.insert(field.into(), value);
        rules.push(Value::Object(rule));
        return;
    }
    if let Some(values) = rules
        .iter_mut()
        .filter_map(Value::as_object_mut)
        .find_map(|rule| rule.get_mut(field).and_then(Value::as_array_mut))
    {
        values.push(value);
        return;
    }
    let mut rule = Map::new();
    rule.insert(field.into(), Value::Array(vec![value]));
    rules.push(Value::Object(rule));
}

fn normalize_port_range(value: &str) -> Option<String> {
    let normalized = if value.contains(':') {
        value.to_owned()
    } else {
        value.replacen('-', ":", 1)
    };
    let (start, end) = normalized.split_once(':')?;
    if start.is_empty() && end.is_empty() {
        return None;
    }
    if (!start.is_empty() && start.parse::<u16>().is_err())
        || (!end.is_empty() && end.parse::<u16>().is_err())
    {
        return None;
    }
    Some(normalized)
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
        ProxyKind::Snell => return Value::Null,
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

fn wireguard_value(proxy: &Proxy) -> Value {
    let mut peer = Map::new();
    insert(&mut peer, "address", &proxy.server);
    peer.insert("port".into(), proxy.port.into());
    insert_nonempty(&mut peer, "public_key", &proxy.public_key);
    insert_nonempty(&mut peer, "pre_shared_key", &proxy.pre_shared_key);
    if !proxy.allowed_ips.is_empty() {
        peer.insert("allowed_ips".into(), json!(proxy.allowed_ips));
    }
    if let Some(keepalive) = proxy.persistent_keepalive {
        insert(&mut peer, "persistent_keepalive", &format!("{keepalive}s"));
    }
    if !proxy.reserved.is_empty() {
        peer.insert("reserved".into(), json!(proxy.reserved));
    }

    let mut endpoint = Map::new();
    insert(&mut endpoint, "type", "wireguard");
    insert(&mut endpoint, "tag", &proxy.name);
    endpoint.insert("address".into(), json!(proxy.wireguard_address));
    insert_nonempty(&mut endpoint, "private_key", &proxy.private_key);
    endpoint.insert("peers".into(), Value::Array(vec![Value::Object(peer)]));
    if let Some(mtu) = proxy.mtu {
        endpoint.insert("mtu".into(), mtu.into());
    }
    Value::Object(endpoint)
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
                source: String::new(),
                content: "[]GEOIP,CN".into(),
                format: RulesetFormat::Surge,
            },
            LoadedRuleset {
                group: "PROXY".into(),
                source: String::new(),
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

    #[test]
    fn exports_extended_rules_with_native_types_and_or_semantics() {
        let rulesets = [LoadedRuleset {
            group: "PROXY".into(),
            source: String::new(),
            content: [
                "DOMAIN,Example.COM",
                "IP-VERSION,6",
                "INBOUND,Mixed-In",
                r"DOMAIN-REGEX,^https?://API\..+$",
                "PROCESS-PATH,/Opt/MyApp/Bin",
                r"PROCESS-PATH-REGEX,^/Opt/.+$",
                "PACKAGE-NAME,Com.Example.App",
                r"PACKAGE-NAME-REGEX,^Com\.Example\..+$",
                "PORT,443",
                "DEST-PORT,8443",
                "PORT-RANGE,1000-2000",
                "SRC-PORT,5353",
                "SRC-PORT-RANGE,:1024",
                "USER,ServiceUser",
                "USER-ID,1000",
            ]
            .join("\n"),
            format: RulesetFormat::Surge,
        }];
        let output = to_singbox_full(
            &[],
            None,
            &[],
            &rulesets,
            true,
            0,
            &HashMap::new(),
            0,
            false,
            false,
        )
        .unwrap();
        let config: Value = serde_json::from_str(&output).unwrap();
        let rules = config["route"]["rules"].as_array().unwrap();
        let field = |name: &str| {
            rules
                .iter()
                .find_map(|rule| rule.get(name))
                .unwrap_or_else(|| panic!("missing sing-box rule field {name}"))
        };

        assert_eq!(field("domain"), &json!(["example.com"]));
        assert_eq!(field("ip_version"), 6);
        assert_eq!(field("inbound"), &json!(["Mixed-In"]));
        assert_eq!(field("domain_regex"), &json!([r"^https?://API\..+$"]));
        assert_eq!(field("process_path"), &json!(["/Opt/MyApp/Bin"]));
        assert_eq!(field("process_path_regex"), &json!([r"^/Opt/.+$"]));
        assert_eq!(field("package_name"), &json!(["Com.Example.App"]));
        assert_eq!(field("package_name_regex"), &json!([r"^Com\.Example\..+$"]));
        assert_eq!(field("port"), &json!([443, 8443]));
        assert_eq!(field("port_range"), &json!(["1000:2000"]));
        assert_eq!(field("source_port"), &json!([5353]));
        assert_eq!(field("source_port_range"), &json!([":1024"]));
        assert_eq!(field("user"), &json!(["ServiceUser"]));
        assert_eq!(field("user_id"), &json!([1000]));
        assert!(
            rules
                .iter()
                .all(|rule| { !(rule.get("domain").is_some() && rule.get("port").is_some()) })
        );
        assert!(rules.iter().all(|rule| rule["outbound"] == "PROXY"));
    }
}
