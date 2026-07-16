use crate::error::{AppError, Result};

#[derive(Debug, Clone, Default)]
pub struct ExternalConfig {
    pub groups: Vec<ProxyGroup>,
    pub rulesets: Vec<RulesetSpec>,
    pub clash_rule_base: Option<String>,
    pub singbox_rule_base: Option<String>,
    pub overwrite_original_rules: bool,
    pub enable_rule_generator: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
    Relay,
    Ssid,
}

#[derive(Debug, Clone)]
pub struct ProxyGroup {
    pub name: String,
    pub kind: GroupKind,
    pub selectors: Vec<String>,
    pub providers: Vec<String>,
    pub url: String,
    pub interval: u64,
    pub tolerance: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesetFormat {
    Surge,
    QuanX,
    ClashDomain,
    ClashIpCidr,
    ClashClassical,
}

#[derive(Debug, Clone)]
pub struct RulesetSpec {
    pub group: String,
    pub source: String,
    pub interval: u64,
    pub format: RulesetFormat,
    pub inline: bool,
}

#[derive(Debug, Clone)]
pub struct LoadedRuleset {
    pub group: String,
    pub content: String,
    pub format: RulesetFormat,
}

pub fn parse(content: &str) -> Result<ExternalConfig> {
    let mut output = ExternalConfig {
        enable_rule_generator: true,
        ..ExternalConfig::default()
    };
    let mut in_custom = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_custom = line[1..line.len() - 1]
                .trim()
                .eq_ignore_ascii_case("custom");
            continue;
        }
        if !in_custom {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "ruleset" | "surge_ruleset" => {
                if let Some(spec) = parse_ruleset(value) {
                    output.rulesets.push(spec);
                }
            }
            "custom_proxy_group" => {
                if let Some(group) = parse_group(value) {
                    output.groups.push(group);
                }
            }
            "clash_rule_base" => output.clash_rule_base = Some(value.to_owned()),
            "singbox_rule_base" => output.singbox_rule_base = Some(value.to_owned()),
            "overwrite_original_rules" => {
                output.overwrite_original_rules = value.parse().unwrap_or(false)
            }
            "enable_rule_generator" => output.enable_rule_generator = value.parse().unwrap_or(true),
            _ => {}
        }
    }
    if output.groups.is_empty() && output.rulesets.is_empty() {
        return Err(AppError::BadRequest(
            "external config has no custom groups or rulesets".into(),
        ));
    }
    Ok(output)
}

fn parse_ruleset(value: &str) -> Option<RulesetSpec> {
    let (group, remainder) = value.split_once(',')?;
    let group = group.trim();
    let remainder = remainder.trim();
    if group.is_empty() || remainder.is_empty() {
        return None;
    }
    if remainder.starts_with("[]") {
        return Some(RulesetSpec {
            group: group.to_owned(),
            source: remainder.to_owned(),
            interval: 0,
            format: RulesetFormat::Surge,
            inline: true,
        });
    }
    let (source, interval) = remainder
        .rsplit_once(',')
        .filter(|(_, interval)| interval.trim().parse::<u64>().is_ok())
        .map_or((remainder, 0), |(source, interval)| {
            (source.trim(), interval.trim().parse().unwrap_or(0))
        });
    let (format, source) = [
        ("clash-domain:", RulesetFormat::ClashDomain),
        ("clash-ipcidr:", RulesetFormat::ClashIpCidr),
        ("clash:", RulesetFormat::ClashClassical),
        ("quanx:", RulesetFormat::QuanX),
        ("surge:", RulesetFormat::Surge),
    ]
    .into_iter()
    .find_map(|(prefix, format)| source.strip_prefix(prefix).map(|source| (format, source)))
    .unwrap_or((RulesetFormat::Surge, source));
    Some(RulesetSpec {
        group: group.to_owned(),
        source: source.to_owned(),
        interval,
        format,
        inline: false,
    })
}

fn parse_group(value: &str) -> Option<ProxyGroup> {
    let parts: Vec<_> = value.split('`').collect();
    if parts.len() < 3 {
        return None;
    }
    let kind = match parts[1] {
        "select" => GroupKind::Select,
        "url-test" => GroupKind::UrlTest,
        "fallback" => GroupKind::Fallback,
        "load-balance" => GroupKind::LoadBalance,
        "relay" => GroupKind::Relay,
        "ssid" => GroupKind::Ssid,
        _ => return None,
    };
    let timed = matches!(
        kind,
        GroupKind::UrlTest | GroupKind::Fallback | GroupKind::LoadBalance
    );
    let selector_end = if timed {
        parts.len().checked_sub(2)?
    } else {
        parts.len()
    };
    if selector_end < 3 {
        return None;
    }
    let (url, interval, tolerance) = if timed {
        let timings: Vec<_> = parts[parts.len() - 1].split(',').collect();
        (
            parts[parts.len() - 2].to_owned(),
            timings
                .first()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            timings
                .get(2)
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
        )
    } else {
        (String::new(), 0, 0)
    };
    let mut providers = Vec::new();
    let selectors = parts[2..selector_end]
        .iter()
        .filter_map(|value| {
            value.strip_prefix("!!PROVIDER=").map_or_else(
                || Some((*value).to_owned()),
                |names| {
                    providers.extend(
                        names
                            .split(',')
                            .map(str::trim)
                            .filter(|name| !name.is_empty())
                            .map(ToOwned::to_owned),
                    );
                    None
                },
            )
        })
        .collect();
    Some(ProxyGroup {
        name: parts[0].to_owned(),
        kind,
        selectors,
        providers,
        url,
        interval,
        tolerance,
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn malformed_external_configs_never_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..4096)
        ) {
            let input = String::from_utf8_lossy(&bytes);
            let _ = parse(&input);
        }
    }

    #[test]
    fn parses_shadowed_ini_keys_in_order() {
        let config = parse(
            "[custom]\nruleset=DIRECT,[]FINAL\nruleset=PROXY,clash-domain:https://example.test/a.yaml,600\ncustom_proxy_group=PROXY`select`[]DIRECT`.*\noverwrite_original_rules=true",
        )
        .unwrap();
        assert_eq!(config.rulesets.len(), 2);
        assert_eq!(config.rulesets[1].format, RulesetFormat::ClashDomain);
        assert_eq!(config.groups[0].name, "PROXY");
        assert!(config.overwrite_original_rules);
    }

    #[test]
    fn parses_proxy_providers_and_ssid_groups() {
        let config = parse(
            "[custom]\ncustom_proxy_group=PROVIDER`select`!!PROVIDER=one,two\ncustom_proxy_group=WIFI`ssid`[]DIRECT",
        )
        .unwrap();
        assert_eq!(config.groups[0].providers, ["one", "two"]);
        assert!(config.groups[0].selectors.is_empty());
        assert_eq!(config.groups[1].kind, GroupKind::Ssid);
    }
}
