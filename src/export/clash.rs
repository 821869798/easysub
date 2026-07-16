use serde_json::{Map, Value, json};

use crate::{
    error::{AppError, Result},
    external::{GroupKind, LoadedRuleset, ProxyGroup},
    group,
    model::{Proxy, ProxyKind},
    rules::parse_common_rules,
};

use super::prepare_nodes;

pub fn to_clash(nodes: &[Proxy], append_type: bool, sort: bool) -> Result<String> {
    to_clash_with_base(nodes, None, append_type, sort)
}

pub fn to_clash_with_base(
    nodes: &[Proxy],
    base: Option<&str>,
    append_type: bool,
    sort: bool,
) -> Result<String> {
    to_clash_full(nodes, base, &[], &[], false, 0, append_type, sort)
}

#[allow(clippy::too_many_arguments)]
pub fn to_clash_full(
    nodes: &[Proxy],
    base: Option<&str>,
    groups: &[ProxyGroup],
    rulesets: &[LoadedRuleset],
    overwrite_rules: bool,
    max_rules: usize,
    append_type: bool,
    sort: bool,
) -> Result<String> {
    let nodes = prepare_nodes(nodes, append_type, sort);
    let proxies: Vec<Value> = nodes.iter().map(proxy_value).collect();
    let names: Vec<Value> = nodes
        .iter()
        .map(|node| Value::String(node.name.clone()))
        .chain([Value::String("DIRECT".into())])
        .collect();
    let mut config = match base {
        Some(base) => serde_yaml::from_str::<Value>(base).map_err(|error| {
            AppError::Conversion(format!("Clash base YAML is invalid: {error}"))
        })?,
        None => json!({
            "mixed-port": 7890,
            "allow-lan": false,
            "mode": "rule",
            "log-level": "info"
        }),
    };
    let object = config
        .as_object_mut()
        .ok_or_else(|| AppError::Conversion("Clash base must be a YAML object".into()))?;
    object.insert("proxies".into(), Value::Array(proxies));
    let proxy_groups = if groups.is_empty() {
        json!([{"name": "GLOBAL", "type": "select", "proxies": names}])
    } else {
        Value::Array(
            groups
                .iter()
                .map(|group_config| {
                    let mut group_value = Map::new();
                    insert(&mut group_value, "name", &group_config.name);
                    insert(
                        &mut group_value,
                        "type",
                        match group_config.kind {
                            GroupKind::Select => "select",
                            GroupKind::UrlTest => "url-test",
                            GroupKind::Fallback => "fallback",
                            GroupKind::LoadBalance => "load-balance",
                            GroupKind::Relay => "relay",
                        },
                    );
                    group_value.insert(
                        "proxies".into(),
                        json!(group::members(group_config, &nodes)),
                    );
                    insert_nonempty(&mut group_value, "url", &group_config.url);
                    if group_config.interval > 0 {
                        group_value.insert("interval".into(), group_config.interval.into());
                    }
                    if group_config.tolerance > 0 {
                        group_value.insert("tolerance".into(), group_config.tolerance.into());
                    }
                    Value::Object(group_value)
                })
                .collect(),
        )
    };
    object.insert("proxy-groups".into(), proxy_groups);
    if rulesets.is_empty() {
        if object.get("rules").is_none_or(Value::is_null) {
            let final_group = groups.first().map_or("GLOBAL", |group| group.name.as_str());
            object.insert("rules".into(), json!([format!("MATCH,{final_group}")]));
        }
    } else {
        let mut output_rules = if overwrite_rules {
            Vec::new()
        } else {
            object
                .get("rules")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        };
        let mut generated = 0usize;
        for ruleset in rulesets {
            let remaining = if max_rules == 0 {
                0
            } else {
                max_rules.saturating_sub(generated)
            };
            if max_rules > 0 && remaining == 0 {
                break;
            }
            for rule in parse_common_rules(&ruleset.content, ruleset.format, remaining) {
                let kind = if rule.kind == "FINAL" {
                    "MATCH"
                } else {
                    &rule.kind
                };
                let mut rendered = kind.to_owned();
                if let Some(value) = rule.value {
                    rendered.push(',');
                    rendered.push_str(&value);
                }
                rendered.push(',');
                rendered.push_str(&ruleset.group);
                if rule.no_resolve {
                    rendered.push_str(",no-resolve");
                }
                output_rules.push(Value::String(rendered));
                generated += 1;
                if max_rules > 0 && generated >= max_rules {
                    break;
                }
            }
        }
        object.insert("rules".into(), Value::Array(output_rules));
    }
    serde_yaml::to_string(&config)
        .map_err(|error| AppError::Conversion(format!("Clash YAML serialization failed: {error}")))
}

fn proxy_value(proxy: &Proxy) -> Value {
    let mut object = Map::new();
    insert(&mut object, "name", &proxy.name);
    insert(&mut object, "server", &proxy.server);
    object.insert("port".into(), proxy.port.into());
    match proxy.kind {
        ProxyKind::Shadowsocks => {
            insert(&mut object, "type", "ss");
            insert(&mut object, "cipher", &proxy.method);
            insert(&mut object, "password", &proxy.password);
            insert_nonempty(&mut object, "plugin", &proxy.plugin);
            insert_nonempty(&mut object, "plugin-opts", &proxy.plugin_opts);
        }
        ProxyKind::Vmess => {
            insert(&mut object, "type", "vmess");
            insert(&mut object, "uuid", &proxy.uuid);
            object.insert("alterId".into(), proxy.alter_id.into());
            insert(
                &mut object,
                "cipher",
                if proxy.method.is_empty() {
                    "auto"
                } else {
                    &proxy.method
                },
            );
            add_transport(&mut object, proxy);
        }
        ProxyKind::Vless => {
            insert(&mut object, "type", "vless");
            insert(&mut object, "uuid", &proxy.uuid);
            insert_nonempty(&mut object, "flow", &proxy.flow);
            add_transport(&mut object, proxy);
        }
        ProxyKind::Trojan => {
            insert(&mut object, "type", "trojan");
            insert(&mut object, "password", &proxy.password);
            add_transport(&mut object, proxy);
        }
        ProxyKind::Tuic => {
            insert(&mut object, "type", "tuic");
            insert(&mut object, "uuid", &proxy.uuid);
            insert(&mut object, "password", &proxy.password);
            insert_nonempty(
                &mut object,
                "congestion-controller",
                &proxy.congestion_control,
            );
            insert_nonempty(&mut object, "udp-relay-mode", &proxy.udp_relay_mode);
            add_tls(&mut object, proxy);
        }
        ProxyKind::Anytls => {
            insert(&mut object, "type", "anytls");
            insert(&mut object, "password", &proxy.password);
            add_tls(&mut object, proxy);
            insert_option(
                &mut object,
                "idle-session-check-interval",
                proxy.idle_session_check_interval,
            );
            insert_option(
                &mut object,
                "idle-session-timeout",
                proxy.idle_session_timeout,
            );
            insert_option(&mut object, "min-idle-session", proxy.min_idle_session);
        }
        ProxyKind::Hysteria2 => {
            insert(&mut object, "type", "hysteria2");
            insert(&mut object, "password", &proxy.password);
            insert_nonempty(&mut object, "obfs", &proxy.obfs);
            insert_nonempty(&mut object, "obfs-password", &proxy.obfs_password);
            insert_option(&mut object, "up", proxy.up_mbps);
            insert_option(&mut object, "down", proxy.down_mbps);
            add_tls(&mut object, proxy);
        }
        ProxyKind::Http | ProxyKind::Https => {
            insert(&mut object, "type", "http");
            insert_nonempty(&mut object, "username", &proxy.username);
            insert_nonempty(&mut object, "password", &proxy.password);
            if proxy.kind == ProxyKind::Https {
                object.insert("tls".into(), true.into());
            }
        }
        ProxyKind::Socks5 => {
            insert(&mut object, "type", "socks5");
            insert_nonempty(&mut object, "username", &proxy.username);
            insert_nonempty(&mut object, "password", &proxy.password);
        }
        ProxyKind::Wireguard => insert(&mut object, "type", "wireguard"),
    }
    if let Some(udp) = proxy.udp {
        object.insert("udp".into(), udp.into());
    }
    if let Some(tfo) = proxy.tcp_fast_open {
        object.insert("tfo".into(), tfo.into());
    }
    Value::Object(object)
}

fn add_transport(object: &mut Map<String, Value>, proxy: &Proxy) {
    insert_nonempty(object, "network", &proxy.network);
    if proxy.network == "ws" {
        let mut ws = Map::new();
        insert_nonempty(&mut ws, "path", &proxy.path);
        if !proxy.host.is_empty() {
            ws.insert("headers".into(), json!({"Host": proxy.host}));
        }
        object.insert("ws-opts".into(), Value::Object(ws));
    } else if proxy.network == "grpc" {
        object.insert("grpc-opts".into(), json!({"grpc-service-name": proxy.path}));
    }
    if proxy.tls {
        object.insert("tls".into(), true.into());
        add_tls(object, proxy);
    }
}

fn add_tls(object: &mut Map<String, Value>, proxy: &Proxy) {
    insert_nonempty(object, "servername", &proxy.server_name);
    insert_nonempty(object, "client-fingerprint", &proxy.fingerprint);
    if let Some(insecure) = proxy.skip_cert_verify {
        object.insert("skip-cert-verify".into(), insecure.into());
    }
    if !proxy.public_key.is_empty() {
        object.insert(
            "reality-opts".into(),
            json!({"public-key": proxy.public_key, "short-id": proxy.short_id}),
        );
    }
    if !proxy.alpn.is_empty() {
        object.insert("alpn".into(), json!(proxy.alpn));
    }
}

fn insert(object: &mut Map<String, Value>, key: &str, value: &str) {
    object.insert(key.into(), Value::String(value.into()));
}

fn insert_nonempty(object: &mut Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        insert(object, key, value);
    }
}

fn insert_option(object: &mut Map<String, Value>, key: &str, value: Option<u32>) {
    if let Some(value) = value {
        object.insert(key.into(), value.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_first_custom_group_without_generated_rules() {
        let groups = [ProxyGroup {
            name: "PROXY".into(),
            kind: GroupKind::Select,
            selectors: vec!["[]DIRECT".into()],
            url: String::new(),
            interval: 0,
            tolerance: 0,
        }];
        let output = to_clash_full(&[], None, &groups, &[], false, 0, false, false).unwrap();
        let config: Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(config["rules"][0], "MATCH,PROXY");
    }
}
