use std::{collections::HashMap, path::Path};

use serde_json::{Map, Value, json};

use crate::{
    config::RulesetTransform,
    error::{AppError, Result},
    external::{GroupKind, LoadedRuleset, ProxyGroup},
    group,
    model::{Proxy, ProxyKind},
    rules::parse_common_rules_filtered,
};

use super::prepare_nodes;

const OPTIMIZE_MIN_COUNT: usize = 8;

#[derive(Debug, Clone)]
pub struct ClashRulesetOptions {
    pub proxies_style: String,
    pub proxy_groups_style: String,
    pub optimize: bool,
    pub optimize_to_http: bool,
    pub geo_convert: bool,
    pub provider_base_url: Option<String>,
    pub access_token: Option<String>,
    pub update_interval: u64,
    pub geo_transforms: HashMap<String, RulesetTransform>,
}

impl Default for ClashRulesetOptions {
    fn default() -> Self {
        Self {
            proxies_style: "flow".into(),
            proxy_groups_style: "block".into(),
            optimize: false,
            optimize_to_http: false,
            geo_convert: false,
            provider_base_url: None,
            access_token: None,
            update_interval: 0,
            geo_transforms: HashMap::new(),
        }
    }
}

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
    to_clash_full_with_options(
        nodes,
        base,
        groups,
        rulesets,
        overwrite_rules,
        max_rules,
        append_type,
        sort,
        &ClashRulesetOptions::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn to_clash_full_with_options(
    nodes: &[Proxy],
    base: Option<&str>,
    groups: &[ProxyGroup],
    rulesets: &[LoadedRuleset],
    overwrite_rules: bool,
    max_rules: usize,
    append_type: bool,
    sort: bool,
    ruleset_options: &ClashRulesetOptions,
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
                            GroupKind::Ssid => "ssid",
                        },
                    );
                    if !group_config.selectors.is_empty() || group_config.providers.is_empty() {
                        group_value.insert(
                            "proxies".into(),
                            json!(group::members(group_config, &nodes)),
                        );
                    }
                    if !group_config.providers.is_empty() {
                        group_value.insert("use".into(), json!(group_config.providers));
                    }
                    if group_config.kind == GroupKind::LoadBalance {
                        insert(&mut group_value, "strategy", "consistent-hashing");
                    }
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
        let mut providers = object
            .get("rule-providers")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut generated = 0usize;
        let merged_rulesets = merge_adjacent_rulesets(rulesets);
        for (ruleset_index, ruleset) in merged_rulesets.iter().enumerate() {
            let remaining = if max_rules == 0 {
                0
            } else {
                max_rules.saturating_sub(generated)
            };
            if max_rules > 0 && remaining == 0 {
                break;
            }
            let rules = parse_common_rules_filtered(
                &ruleset.content,
                ruleset.format,
                remaining,
                is_clash_rule,
            );
            generated += rules.len();
            if ruleset_options.geo_convert
                && ruleset.content.starts_with("[]")
                && rules.len() == 1
                && append_geo_provider(
                    &rules[0],
                    &ruleset.group,
                    ruleset_options,
                    &mut providers,
                    &mut output_rules,
                )
            {
                continue;
            }
            append_ruleset(
                ruleset,
                ruleset_index,
                &rules,
                ruleset_options,
                &mut providers,
                &mut output_rules,
            )?;
        }
        object.insert("rules".into(), Value::Array(output_rules));
        if !providers.is_empty() {
            object.insert("rule-providers".into(), Value::Object(providers));
        }
    }
    serialize_clash_yaml(&config, ruleset_options)
}

fn merge_adjacent_rulesets(rulesets: &[LoadedRuleset]) -> Vec<LoadedRuleset> {
    let mut merged: Vec<LoadedRuleset> = Vec::with_capacity(rulesets.len());
    for ruleset in rulesets {
        if let Some(previous) = merged.last_mut()
            && !previous.source.is_empty()
            && !ruleset.source.is_empty()
            && previous.group == ruleset.group
            && previous.format == ruleset.format
        {
            previous.source.push('|');
            previous.source.push_str(&ruleset.source);
            previous.content.push('\n');
            previous.content.push_str(&ruleset.content);
        } else {
            merged.push(ruleset.clone());
        }
    }
    merged
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CollectionStyle {
    Block,
    Flow,
    Compact,
}

impl CollectionStyle {
    fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "flow" => Self::Flow,
            "compact" => Self::Compact,
            _ => Self::Block,
        }
    }
}

fn serialize_clash_yaml(config: &Value, options: &ClashRulesetOptions) -> Result<String> {
    let object = config
        .as_object()
        .ok_or_else(|| AppError::Conversion("Clash output must be a YAML object".into()))?;
    let mut output = String::new();
    for (key, value) in object {
        let style = match key.as_str() {
            "proxies" => Some(CollectionStyle::parse(&options.proxies_style)),
            "proxy-groups" => Some(CollectionStyle::parse(&options.proxy_groups_style)),
            _ => None,
        };
        if let (Some(style), Some(values)) = (style, value.as_array()) {
            write_styled_sequence(&mut output, key, values, style)?;
        } else {
            write_map_entry(&mut output, key, value, 0, &[key.as_str()])?;
        }
    }
    Ok(output)
}

fn write_styled_sequence(
    output: &mut String,
    key: &str,
    values: &[Value],
    style: CollectionStyle,
) -> Result<()> {
    match style {
        CollectionStyle::Block => {
            output.push_str(key);
            if values.is_empty() {
                output.push_str(": []\n");
            } else {
                output.push_str(":\n");
                write_sequence(output, values, 2, &[key])?;
            }
        }
        CollectionStyle::Flow => {
            output.push_str(key);
            output.push_str(":\n");
            for value in values {
                output.push_str("  - ");
                output.push_str(&flow_yaml(value)?);
                output.push('\n');
            }
        }
        CollectionStyle::Compact => {
            output.push_str(key);
            output.push_str(": ");
            output.push_str(&flow_yaml(&Value::Array(values.to_vec()))?);
            output.push('\n');
        }
    }
    Ok(())
}

fn write_map_entry(
    output: &mut String,
    key: &str,
    value: &Value,
    indent: usize,
    path: &[&str],
) -> Result<()> {
    write_indent(output, indent);
    output.push_str(&flow_yaml(&json!(key))?);
    output.push(':');
    match value {
        Value::Array(values) if values.is_empty() => output.push_str(" []\n"),
        Value::Array(values) => {
            output.push('\n');
            let sequence_indent =
                if path.first() == Some(&"proxy-groups") && matches!(key, "proxies" | "use") {
                    indent + 4
                } else {
                    indent + 2
                };
            write_sequence(output, values, sequence_indent, path)?;
        }
        Value::Object(object) if object.is_empty() => output.push_str(" {}\n"),
        Value::Object(object) => {
            output.push('\n');
            for (child_key, child_value) in object {
                let mut child_path = path.to_vec();
                child_path.push(child_key);
                write_map_entry(output, child_key, child_value, indent + 2, &child_path)?;
            }
        }
        _ => {
            output.push(' ');
            output.push_str(&scalar_for_path(value, path)?);
            output.push('\n');
        }
    }
    Ok(())
}

fn write_sequence(
    output: &mut String,
    values: &[Value],
    indent: usize,
    path: &[&str],
) -> Result<()> {
    for value in values {
        write_indent(output, indent);
        output.push('-');
        match value {
            Value::Object(object) if object.is_empty() => output.push_str(" {}\n"),
            Value::Object(object) => {
                let mut fields = object.iter();
                let (first_key, first_value) = fields.next().expect("object is not empty");
                output.push(' ');
                write_map_item_first(output, first_key, first_value, indent + 2, path)?;
                for (key, value) in fields {
                    let mut child_path = path.to_vec();
                    child_path.push(key);
                    write_map_entry(output, key, value, indent + 2, &child_path)?;
                }
            }
            Value::Array(values) => {
                output.push('\n');
                write_sequence(output, values, indent + 2, path)?;
            }
            _ => {
                output.push(' ');
                output.push_str(&scalar_for_path(value, path)?);
                output.push('\n');
            }
        }
    }
    Ok(())
}

fn write_map_item_first(
    output: &mut String,
    key: &str,
    value: &Value,
    indent: usize,
    path: &[&str],
) -> Result<()> {
    output.push_str(&flow_yaml(&json!(key))?);
    output.push(':');
    match value {
        Value::Array(values) if values.is_empty() => output.push_str(" []\n"),
        Value::Array(values) => {
            output.push('\n');
            write_sequence(output, values, indent + 2, path)?;
        }
        Value::Object(object) if object.is_empty() => output.push_str(" {}\n"),
        Value::Object(object) => {
            output.push('\n');
            for (key, value) in object {
                let mut child_path = path.to_vec();
                child_path.push(key);
                write_map_entry(output, key, value, indent + 2, &child_path)?;
            }
        }
        _ => {
            output.push(' ');
            output.push_str(&scalar_for_path(value, path)?);
            output.push('\n');
        }
    }
    Ok(())
}

fn write_indent(output: &mut String, indent: usize) {
    output.extend(std::iter::repeat_n(' ', indent));
}

fn scalar_for_path(value: &Value, path: &[&str]) -> Result<String> {
    if path.first() == Some(&"rule-providers")
        && path.last() == Some(&"payload")
        && let Some(value) = value.as_str()
    {
        return serde_json::to_string(value)
            .map_err(|error| AppError::Conversion(error.to_string()));
    }
    scalar_yaml(value)
}

fn flow_yaml(value: &Value) -> Result<String> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => scalar_yaml(value),
        Value::String(value)
            if value.is_empty()
                || value.contains(['?', ':', ',', '[', ']', '{', '}', '\n', '\r']) =>
        {
            serde_json::to_string(value).map_err(|error| AppError::Conversion(error.to_string()))
        }
        Value::String(_) => scalar_yaml(value),
        Value::Array(values) => values
            .iter()
            .map(flow_yaml)
            .collect::<Result<Vec<_>>>()
            .map(|values| format!("[{}]", values.join(", "))),
        Value::Object(object) => object
            .iter()
            .map(|(key, value)| {
                Ok(format!(
                    "{}: {}",
                    flow_yaml(&json!(key))?,
                    flow_yaml(value)?
                ))
            })
            .collect::<Result<Vec<_>>>()
            .map(|fields| format!("{{{}}}", fields.join(", "))),
    }
}

fn scalar_yaml(value: &Value) -> Result<String> {
    if value.as_str() == Some("") {
        return Ok("\"\"".into());
    }
    serde_yaml::to_string(value)
        .map(|value| {
            value
                .strip_prefix("---\n")
                .unwrap_or(&value)
                .trim_end()
                .to_owned()
        })
        .map_err(|error| AppError::Conversion(format!("YAML scalar serialization failed: {error}")))
}

fn append_ruleset(
    ruleset: &LoadedRuleset,
    ruleset_index: usize,
    rules: &[crate::rules::RuleLine],
    options: &ClashRulesetOptions,
    providers: &mut Map<String, Value>,
    output: &mut Vec<Value>,
) -> Result<()> {
    let domain_payload: Vec<String> = rules
        .iter()
        .filter_map(|rule| match (rule.kind.as_str(), rule.value.as_deref()) {
            ("DOMAIN", Some(value)) if !value.is_empty() => Some(value.to_owned()),
            ("DOMAIN-SUFFIX", Some(value)) if !value.is_empty() => Some(format!(
                "+.{}",
                value.trim_start_matches("+.").trim_start_matches('.')
            )),
            _ => None,
        })
        .collect();
    let ipcidr_payload: Vec<String> = rules
        .iter()
        .filter_map(|rule| {
            (matches!(rule.kind.as_str(), "IP-CIDR" | "IP-CIDR6") && rule.no_resolve)
                .then(|| rule.value.clone())
                .flatten()
        })
        .collect();
    let optimize_domain = options.optimize && domain_payload.len() >= OPTIMIZE_MIN_COUNT;
    let optimize_ipcidr = options.optimize && ipcidr_payload.len() >= OPTIMIZE_MIN_COUNT;
    if optimize_domain {
        let name = insert_optimized_provider(
            ruleset,
            ruleset_index,
            "domain",
            domain_payload,
            options,
            providers,
        )?;
        output.push(Value::String(format!("RULE-SET,{name},{}", ruleset.group)));
    }
    if optimize_ipcidr {
        let name = insert_optimized_provider(
            ruleset,
            ruleset_index,
            "ipcidr",
            ipcidr_payload,
            options,
            providers,
        )?;
        output.push(Value::String(format!(
            "RULE-SET,{name},{},no-resolve",
            ruleset.group
        )));
    }
    for rule in rules {
        let optimized = (optimize_domain
            && matches!(rule.kind.as_str(), "DOMAIN" | "DOMAIN-SUFFIX")
            && rule.value.is_some())
            || (optimize_ipcidr
                && matches!(rule.kind.as_str(), "IP-CIDR" | "IP-CIDR6")
                && rule.no_resolve
                && rule.value.is_some());
        if !optimized {
            output.push(Value::String(render_rule(rule, &ruleset.group)));
        }
    }
    Ok(())
}

fn insert_optimized_provider(
    ruleset: &LoadedRuleset,
    ruleset_index: usize,
    behavior: &str,
    payload: Vec<String>,
    options: &ClashRulesetOptions,
    providers: &mut Map<String, Value>,
) -> Result<String> {
    let base_name = format!(
        "{behavior}_{}",
        ruleset_source_name(&ruleset.source, ruleset_index)
    );
    let name = unique_provider_name(&base_name, providers);
    let interval = options.update_interval.max(1);
    let provider = if options.optimize_to_http {
        if ruleset.source.is_empty() {
            return Err(AppError::Conversion(
                "clashRSOH requires a source URL for every optimized ruleset".into(),
            ));
        }
        let base_url = options
            .provider_base_url
            .as_deref()
            .ok_or_else(|| AppError::Conversion("clashRSOH requires a provider base URL".into()))?;
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("target", "clash")
            .append_pair("behavior", behavior)
            .append_pair("url", &ruleset.source);
        if let Some(token) = options
            .access_token
            .as_deref()
            .filter(|token| !token.is_empty())
        {
            query.append_pair("token", token);
        }
        json!({
            "type": "http",
            "format": "mrs",
            "url": format!("{}/ruleset?{}", base_url.trim_end_matches('/'), query.finish()),
            "behavior": behavior,
            "interval": interval,
            "proxy": "DIRECT",
            "path": format!("./mrs/ruleset/{name}.mrs")
        })
    } else {
        json!({
            "type": "inline",
            "format": "text",
            "behavior": behavior,
            "payload": payload
        })
    };
    providers.insert(name.clone(), provider);
    Ok(name)
}

fn append_geo_provider(
    rule: &crate::rules::RuleLine,
    group: &str,
    options: &ClashRulesetOptions,
    providers: &mut Map<String, Value>,
    output: &mut Vec<Value>,
) -> bool {
    let kind = rule.kind.to_ascii_lowercase();
    let Some(transform) = options.geo_transforms.get(&kind) else {
        return false;
    };
    let Some(value) = rule.value.as_deref().filter(|value| !value.is_empty()) else {
        return false;
    };
    if !matches!(kind.as_str(), "geoip" | "geosite") {
        return false;
    }
    let argument = value.to_ascii_lowercase();
    let base_name = sanitize_provider_name(&format!("{kind}_{argument}"));
    let name = unique_provider_name(&base_name, providers);
    let behavior = if transform.behavior.is_empty() {
        if kind == "geoip" { "ipcidr" } else { "domain" }
    } else {
        &transform.behavior
    };
    providers.insert(
        name.clone(),
        json!({
            "type": "http",
            "format": "mrs",
            "url": transform.url_format.replace("%s", &argument),
            "behavior": behavior,
            "interval": options.update_interval.max(1),
            "proxy": "DIRECT",
            "path": format!("./mrs/{kind}/{argument}.mrs")
        }),
    );
    output.push(Value::String(format!("RULE-SET,{name},{group}")));
    true
}

fn render_rule(rule: &crate::rules::RuleLine, group: &str) -> String {
    let kind = if rule.kind == "FINAL" {
        "MATCH"
    } else {
        &rule.kind
    };
    let mut rendered = kind.to_owned();
    if let Some(value) = rule.value.as_deref() {
        rendered.push(',');
        rendered.push_str(value);
    }
    rendered.push(',');
    rendered.push_str(group);
    if rule.no_resolve {
        rendered.push_str(",no-resolve");
    }
    rendered
}

fn ruleset_source_name(source: &str, index: usize) -> String {
    let stems: Vec<_> = source
        .split('|')
        .filter_map(|source| {
            let without_query = source.split(['?', '#']).next().unwrap_or(source);
            let file_name = without_query
                .trim_end_matches('/')
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or_default();
            Path::new(file_name)
                .file_stem()
                .and_then(|value| value.to_str())
                .filter(|value| !value.is_empty())
                .map(sanitize_provider_name)
        })
        .collect();
    if stems.is_empty() {
        format!("ruleset_{}", index + 1)
    } else {
        stems.join("_")
    }
}

fn sanitize_provider_name(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn unique_provider_name(base: &str, providers: &Map<String, Value>) -> String {
    if !providers.contains_key(base) {
        return base.to_owned();
    }
    (1..)
        .map(|index| format!("{base}_{index}"))
        .find(|name| !providers.contains_key(name))
        .expect("provider suffix space is unbounded")
}

fn is_clash_rule(rule: &crate::rules::RuleLine) -> bool {
    matches!(
        rule.kind.as_str(),
        "DOMAIN"
            | "DOMAIN-SUFFIX"
            | "DOMAIN-KEYWORD"
            | "IP-CIDR"
            | "IP-CIDR6"
            | "SRC-IP-CIDR"
            | "GEOIP"
            | "SRC-GEOIP"
            | "GEOSITE"
            | "MATCH"
            | "FINAL"
            | "PROCESS-NAME"
            | "SRC-PORT"
            | "DST-PORT"
            | "NETWORK"
            | "PROTOCOL"
    )
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
            object.remove("tls");
            object.remove("servername");
            if proxy.network == "tcp" {
                object.remove("network");
            }
            insert_nonempty(&mut object, "sni", &proxy.server_name);
        }
        ProxyKind::Tuic => {
            insert(&mut object, "type", "tuic");
            object.insert("version".into(), 5.into());
            insert(&mut object, "uuid", &proxy.uuid);
            insert(&mut object, "password", &proxy.password);
            insert_nonempty(&mut object, "heartbeat-interval", &proxy.heartbeat_interval);
            if let Some(value) = proxy.disable_sni {
                object.insert("disable-sni".into(), value.into());
            }
            if let Some(value) = proxy.reduce_rtt {
                object.insert("reduce-rtt".into(), value.into());
            }
            insert_option(&mut object, "request-timeout", proxy.request_timeout);
            insert_nonempty(
                &mut object,
                "congestion-controller",
                &proxy.congestion_control,
            );
            insert_nonempty(&mut object, "udp-relay-mode", &proxy.udp_relay_mode);
            insert_option(
                &mut object,
                "max-udp-relay-packet-size",
                proxy.max_udp_relay_packet_size,
            );
            insert_option(&mut object, "max-open-streams", proxy.max_open_streams);
            if let Some(value) = proxy.fast_open {
                object.insert("fast-open".into(), value.into());
            }
            add_native_tls(&mut object, proxy);
        }
        ProxyKind::Anytls => {
            insert(&mut object, "type", "anytls");
            insert(&mut object, "password", &proxy.password);
            add_native_tls(&mut object, proxy);
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
            insert_nonempty(&mut object, "ports", &proxy.ports);
            insert_option(&mut object, "up", proxy.up_mbps);
            insert_option(&mut object, "down", proxy.down_mbps);
            insert_nonempty(&mut object, "ca", &proxy.ca);
            insert_nonempty(&mut object, "ca-str", &proxy.ca_str);
            insert_option(&mut object, "cwnd", proxy.cwnd);
            insert_option(&mut object, "hop-interval", proxy.hop_interval);
            add_native_tls(&mut object, proxy);
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
        ProxyKind::Snell => {
            insert(&mut object, "type", "snell");
            insert(&mut object, "psk", &proxy.password);
            if let Some(version) = proxy.snell_version {
                object.insert("version".into(), version.into());
            }
            if !proxy.obfs.is_empty() || !proxy.host.is_empty() {
                object.insert(
                    "obfs-opts".into(),
                    json!({"mode": proxy.obfs, "host": proxy.host}),
                );
            }
        }
        ProxyKind::Wireguard => {
            insert(&mut object, "type", "wireguard");
            if let Some(address) = proxy
                .wireguard_address
                .iter()
                .find(|address| !address.contains(':'))
            {
                insert(&mut object, "ip", address);
            }
            if let Some(address) = proxy
                .wireguard_address
                .iter()
                .find(|address| address.contains(':'))
            {
                insert(&mut object, "ipv6", address);
            }
            insert_nonempty(&mut object, "private-key", &proxy.private_key);
            insert_nonempty(&mut object, "public-key", &proxy.public_key);
            insert_nonempty(&mut object, "pre-shared-key", &proxy.pre_shared_key);
            if !proxy.allowed_ips.is_empty() {
                object.insert("allowed-ips".into(), json!(proxy.allowed_ips));
            }
            if !proxy.dns_servers.is_empty() {
                object.insert("dns".into(), json!(proxy.dns_servers));
            }
            if let Some(mtu) = proxy.mtu {
                object.insert("mtu".into(), mtu.into());
            }
            if let Some(keepalive) = proxy.persistent_keepalive {
                object.insert("persistent-keepalive".into(), keepalive.into());
            }
            if !proxy.reserved.is_empty() {
                object.insert("reserved".into(), json!(proxy.reserved));
            }
        }
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
        // Match the Go exporter: Mihomo accepts an empty WS path, and keeping
        // the key makes block/flow output stable across both implementations.
        insert(&mut ws, "path", &proxy.path);
        if !proxy.host.is_empty() {
            ws.insert("headers".into(), json!({"Host": proxy.host}));
        }
        object.insert("ws-opts".into(), Value::Object(ws));
    } else if proxy.network == "http" {
        let mut headers = Map::new();
        if !proxy.host.is_empty() {
            headers.insert("Host".into(), json!([proxy.host]));
        }
        object.insert(
            "http-opts".into(),
            json!({
                "method": "GET",
                "path": [proxy.path],
                "headers": headers,
            }),
        );
    } else if proxy.network == "grpc" {
        object.insert("grpc-opts".into(), json!({"grpc-service-name": proxy.path}));
    } else if proxy.network == "h2" {
        object.insert(
            "h2-opts".into(),
            json!({"host": [proxy.host], "path": proxy.path}),
        );
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

fn add_native_tls(object: &mut Map<String, Value>, proxy: &Proxy) {
    insert_nonempty(object, "sni", &proxy.server_name);
    insert_nonempty(object, "fingerprint", &proxy.fingerprint);
    if let Some(insecure) = proxy.skip_cert_verify {
        object.insert("skip-cert-verify".into(), insecure.into());
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
            providers: Vec::new(),
            url: String::new(),
            interval: 0,
            tolerance: 0,
        }];
        let output = to_clash_full(&[], None, &groups, &[], false, 0, false, false).unwrap();
        let config: Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(config["rules"][0], "MATCH,PROXY");
    }

    #[test]
    fn exports_extended_tuic_fields() {
        let mut proxy = Proxy::new(ProxyKind::Tuic, "tuic.example".into(), 443);
        proxy.name = "tuic".into();
        proxy.uuid = "uuid".into();
        proxy.password = "secret".into();
        proxy.heartbeat_interval = "10s".into();
        proxy.disable_sni = Some(true);
        proxy.reduce_rtt = Some(true);
        proxy.request_timeout = Some(8000);
        proxy.max_udp_relay_packet_size = Some(1500);
        proxy.max_open_streams = Some(100);
        proxy.fast_open = Some(true);
        proxy.server_name = "tls.example".into();
        let output = to_clash(&[proxy], false, false).unwrap();
        let config: Value = serde_yaml::from_str(&output).unwrap();
        let proxy = &config["proxies"][0];
        assert_eq!(proxy["version"], 5);
        assert_eq!(proxy["heartbeat-interval"], "10s");
        assert_eq!(proxy["disable-sni"], true);
        assert_eq!(proxy["request-timeout"], 8000);
        assert_eq!(proxy["max-open-streams"], 100);
        assert_eq!(proxy["sni"], "tls.example");
    }

    #[test]
    fn exports_trojan_sni_with_mihomo_field_name() {
        let mut proxy = Proxy::new(ProxyKind::Trojan, "edge.example".into(), 443);
        proxy.name = "trojan".into();
        proxy.password = "secret".into();
        proxy.network = "ws".into();
        proxy.tls = true;
        proxy.server_name = "certificate.example".into();
        proxy.fingerprint = "chrome".into();
        let output = to_clash(&[proxy], false, false).unwrap();
        let config: Value = serde_yaml::from_str(&output).unwrap();
        let proxy = &config["proxies"][0];
        assert_eq!(proxy["sni"], "certificate.example");
        assert_eq!(proxy["client-fingerprint"], "chrome");
        assert_eq!(proxy["ws-opts"]["path"], "");
        assert!(proxy.get("servername").is_none());
        assert!(proxy.get("tls").is_none());
    }

    #[test]
    fn applies_flow_and_compact_collection_styles() {
        let mut proxy = Proxy::new(ProxyKind::Trojan, "edge.example".into(), 443);
        proxy.name = "edge".into();
        proxy.password = "secret".into();
        proxy.network = "ws".into();
        proxy.tls = true;
        let flow = to_clash_full_with_options(
            &[proxy.clone()],
            None,
            &[],
            &[],
            false,
            0,
            false,
            false,
            &ClashRulesetOptions {
                proxies_style: "flow".into(),
                proxy_groups_style: "block".into(),
                ..ClashRulesetOptions::default()
            },
        )
        .unwrap();
        assert!(flow.contains("proxies:\n  - {name: edge,"));
        assert!(flow.contains("path: \"\""));
        assert!(flow.contains("proxy-groups:\n  - name: GLOBAL"));
        assert!(flow.contains("    proxies:\n        - edge"));
        let parsed: Value = serde_yaml::from_str(&flow).unwrap();
        assert_eq!(parsed["proxies"][0]["name"], "edge");

        let compact = to_clash_full_with_options(
            &[proxy],
            None,
            &[],
            &[],
            false,
            0,
            false,
            false,
            &ClashRulesetOptions {
                proxies_style: "compact".into(),
                proxy_groups_style: "compact".into(),
                ..ClashRulesetOptions::default()
            },
        )
        .unwrap();
        assert!(compact.contains("proxies: [{name: edge,"));
        assert!(compact.contains("proxy-groups: [{name: GLOBAL,"));
        serde_yaml::from_str::<Value>(&compact).unwrap();
    }

    #[test]
    fn exports_provider_and_load_balance_groups() {
        let groups = [
            ProxyGroup {
                name: "PROVIDER".into(),
                kind: GroupKind::Select,
                selectors: Vec::new(),
                providers: vec!["one".into(), "two".into()],
                url: String::new(),
                interval: 0,
                tolerance: 0,
            },
            ProxyGroup {
                name: "BALANCE".into(),
                kind: GroupKind::LoadBalance,
                selectors: vec!["[]DIRECT".into()],
                providers: Vec::new(),
                url: "https://example.test/generate_204".into(),
                interval: 300,
                tolerance: 0,
            },
        ];
        let output = to_clash_full(&[], None, &groups, &[], false, 0, false, false).unwrap();
        let config: Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(config["proxy-groups"][0]["use"], json!(["one", "two"]));
        assert!(config["proxy-groups"][0].get("proxies").is_none());
        assert_eq!(config["proxy-groups"][1]["strategy"], "consistent-hashing");
    }

    #[test]
    fn filters_singbox_only_rules_before_applying_clash_limit() {
        let rulesets = [LoadedRuleset {
            group: "PROXY".into(),
            source: String::new(),
            content: "IP-VERSION,6\nDOMAIN,kept.example".into(),
            format: crate::external::RulesetFormat::Surge,
        }];
        let output = to_clash_full(&[], None, &[], &rulesets, true, 1, false, false).unwrap();
        let config: Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(config["rules"], json!(["DOMAIN,kept.example,PROXY"]));
    }

    fn optimizable_ruleset() -> LoadedRuleset {
        LoadedRuleset {
            group: "PROXY".into(),
            source: "https://rules.example/domain.list".into(),
            content: (0..8)
                .map(|index| format!("DOMAIN-SUFFIX,domain{index}.example"))
                .chain(["IP-CIDR,10.0.0.0/8,no-resolve".into()])
                .collect::<Vec<_>>()
                .join("\n"),
            format: crate::external::RulesetFormat::Surge,
        }
    }

    #[test]
    fn optimizes_large_domains_into_inline_provider() {
        let output = to_clash_full_with_options(
            &[],
            None,
            &[],
            &[optimizable_ruleset()],
            true,
            0,
            false,
            false,
            &ClashRulesetOptions {
                optimize: true,
                update_interval: 432_000,
                ..ClashRulesetOptions::default()
            },
        )
        .unwrap();
        let config: Value = serde_yaml::from_str(&output).unwrap();
        let provider = &config["rule-providers"]["domain_domain"];
        assert_eq!(provider["type"], "inline");
        assert_eq!(provider["format"], "text");
        assert_eq!(provider["payload"].as_array().unwrap().len(), 8);
        assert_eq!(config["rules"][0], "RULE-SET,domain_domain,PROXY");
        assert_eq!(config["rules"][1], "IP-CIDR,10.0.0.0/8,PROXY,no-resolve");
    }

    #[test]
    fn merges_adjacent_same_group_sources_before_provider_optimization() {
        let rulesets = [
            LoadedRuleset {
                group: "PROXY".into(),
                source: "https://rules.example/one.list".into(),
                content: (0..4)
                    .map(|index| format!("DOMAIN,one{index}.example"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                format: crate::external::RulesetFormat::Surge,
            },
            LoadedRuleset {
                group: "PROXY".into(),
                source: "https://rules.example/two.list".into(),
                content: (0..4)
                    .map(|index| format!("DOMAIN,two{index}.example"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                format: crate::external::RulesetFormat::Surge,
            },
        ];
        let output = to_clash_full_with_options(
            &[],
            None,
            &[],
            &rulesets,
            true,
            0,
            false,
            false,
            &ClashRulesetOptions {
                optimize: true,
                update_interval: 432_000,
                ..ClashRulesetOptions::default()
            },
        )
        .unwrap();
        let config: Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(config["rules"], json!(["RULE-SET,domain_one_two,PROXY"]));
        assert_eq!(
            config["rule-providers"]["domain_one_two"]["payload"]
                .as_array()
                .unwrap()
                .len(),
            8
        );
    }

    #[test]
    fn emits_http_mrs_provider_without_payload() {
        let output = to_clash_full_with_options(
            &[],
            None,
            &[],
            &[optimizable_ruleset()],
            true,
            0,
            false,
            false,
            &ClashRulesetOptions {
                optimize: true,
                optimize_to_http: true,
                provider_base_url: Some("https://sub.example".into()),
                access_token: Some("secret".into()),
                update_interval: 432_000,
                ..ClashRulesetOptions::default()
            },
        )
        .unwrap();
        let config: Value = serde_yaml::from_str(&output).unwrap();
        let provider = &config["rule-providers"]["domain_domain"];
        assert_eq!(provider["type"], "http");
        assert_eq!(provider["format"], "mrs");
        assert!(provider.get("payload").is_none());
        let url = url::Url::parse(provider["url"].as_str().unwrap()).unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(url.origin().ascii_serialization(), "https://sub.example");
        assert_eq!(query["behavior"], "domain");
        assert_eq!(query["url"], "https://rules.example/domain.list");
        assert_eq!(query["token"], "secret");
    }

    #[test]
    fn converts_inline_geo_rule_to_remote_mrs_provider() {
        let ruleset = LoadedRuleset {
            group: "PROXY".into(),
            source: String::new(),
            content: "[]GEOSITE,Google".into(),
            format: crate::external::RulesetFormat::Surge,
        };
        let output = to_clash_full_with_options(
            &[],
            None,
            &[],
            &[ruleset],
            true,
            0,
            false,
            false,
            &ClashRulesetOptions {
                geo_convert: true,
                update_interval: 432_000,
                geo_transforms: HashMap::from([(
                    "geosite".into(),
                    RulesetTransform {
                        name: "geosite".into(),
                        behavior: "domain".into(),
                        url_format: "https://rules.example/%s.mrs".into(),
                    },
                )]),
                ..ClashRulesetOptions::default()
            },
        )
        .unwrap();
        let config: Value = serde_yaml::from_str(&output).unwrap();
        assert_eq!(config["rules"][0], "RULE-SET,geosite_google,PROXY");
        assert_eq!(
            config["rule-providers"]["geosite_google"]["url"],
            "https://rules.example/google.mrs"
        );
    }
}
