use ipnet::IpNet;
use serde::Deserialize;

use crate::{
    error::{AppError, Result},
    external::RulesetFormat,
    model::RuleBehavior,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleLine {
    pub kind: String,
    pub value: Option<String>,
    pub no_resolve: bool,
}

pub fn parse_common_rules(content: &str, format: RulesetFormat, limit: usize) -> Vec<RuleLine> {
    if let Some(inline) = content.strip_prefix("[]") {
        return parse_common_line(inline, RulesetFormat::Surge)
            .into_iter()
            .collect();
    }
    let payload = serde_yaml::from_str::<RulePayload>(content).ok();
    let yaml_values = payload
        .as_ref()
        .filter(|payload| !payload.payload.is_empty() || !payload.rules.is_empty());
    let lines: Box<dyn Iterator<Item = &str> + '_> = match yaml_values {
        Some(payload) => Box::new(
            payload
                .payload
                .iter()
                .chain(&payload.rules)
                .map(String::as_str),
        ),
        None => Box::new(content.lines()),
    };
    lines
        .filter_map(|line| {
            let line = line
                .split_once("//")
                .map_or(line, |(rule, _)| rule)
                .trim()
                .trim_matches(['\'', '"']);
            if line.is_empty() || line.starts_with(['#', ';']) || line.starts_with("//") {
                None
            } else {
                parse_common_line(line, format)
            }
        })
        .take(if limit == 0 { usize::MAX } else { limit })
        .collect()
}

fn parse_common_line(line: &str, format: RulesetFormat) -> Option<RuleLine> {
    match format {
        RulesetFormat::ClashDomain => {
            let value = line.trim_start_matches("+.").trim_start_matches('.');
            if value.is_empty() {
                return None;
            }
            Some(RuleLine {
                kind: if line.starts_with("+.") || line.starts_with('.') {
                    "DOMAIN-SUFFIX".into()
                } else {
                    "DOMAIN".into()
                },
                value: Some(value.to_owned()),
                no_resolve: false,
            })
        }
        RulesetFormat::ClashIpCidr => line.parse::<IpNet>().ok().map(|network| RuleLine {
            kind: if network.addr().is_ipv6() {
                "IP-CIDR6"
            } else {
                "IP-CIDR"
            }
            .into(),
            value: Some(line.to_owned()),
            no_resolve: true,
        }),
        _ => {
            let mut parts = line.split(',').map(str::trim);
            let mut kind = parts.next()?.to_ascii_uppercase();
            if format == RulesetFormat::QuanX {
                kind = match kind.as_str() {
                    "HOST" => "DOMAIN".into(),
                    "HOST-SUFFIX" => "DOMAIN-SUFFIX".into(),
                    "HOST-KEYWORD" => "DOMAIN-KEYWORD".into(),
                    "IP6-CIDR" => "IP-CIDR6".into(),
                    _ => kind,
                };
            }
            let value = parts
                .next()
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            let no_resolve = parts.any(|part| part.eq_ignore_ascii_case("no-resolve"));
            let supported = [
                "DOMAIN",
                "DOMAIN-SUFFIX",
                "DOMAIN-KEYWORD",
                "IP-CIDR",
                "IP-CIDR6",
                "SRC-IP-CIDR",
                "GEOIP",
                "SRC-GEOIP",
                "GEOSITE",
                "MATCH",
                "FINAL",
                "PROCESS-NAME",
                "SRC-PORT",
                "DST-PORT",
                "NETWORK",
                "PROTOCOL",
            ];
            supported.contains(&kind.as_str()).then_some(RuleLine {
                kind,
                value,
                no_resolve,
            })
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct RulePayload {
    #[serde(default)]
    payload: Vec<String>,
    #[serde(default)]
    rules: Vec<String>,
}

pub fn normalize_rules(
    content: &str,
    behavior: RuleBehavior,
    max_rules: usize,
) -> Result<Vec<String>> {
    let yaml = serde_yaml::from_str::<RulePayload>(content).ok();
    let owned;
    let candidates: Box<dyn Iterator<Item = &str> + '_> = if let Some(payload) = yaml
        .as_ref()
        .filter(|payload| !payload.payload.is_empty() || !payload.rules.is_empty())
    {
        Box::new(
            payload
                .payload
                .iter()
                .chain(&payload.rules)
                .map(String::as_str),
        )
    } else {
        owned = content.lines().collect::<Vec<_>>();
        Box::new(owned.into_iter())
    };

    let limit = if max_rules == 0 {
        usize::MAX
    } else {
        max_rules
    };
    let mut result = Vec::new();
    for raw in candidates {
        if result.len() >= limit {
            break;
        }
        let line = raw.trim().trim_matches(['\'', '"']);
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
        {
            continue;
        }
        if let Some(rule) = normalize_rule(line, behavior) {
            result.push(rule);
        }
    }
    if result.is_empty() {
        return Err(AppError::Conversion(
            "ruleset contains no compatible rules".into(),
        ));
    }
    Ok(result)
}

fn normalize_rule(line: &str, behavior: RuleBehavior) -> Option<String> {
    let mut parts = line.split(',').map(str::trim);
    let kind = parts.next()?.to_ascii_uppercase();
    let value = parts.next().unwrap_or_default();
    match behavior {
        RuleBehavior::Domain => match kind.as_str() {
            "DOMAIN" if valid_domain(value) => Some(value.to_ascii_lowercase()),
            "DOMAIN-SUFFIX" if valid_domain(value) => Some(format!(
                "+.{}",
                value
                    .trim_start_matches("+.")
                    .trim_start_matches('.')
                    .to_ascii_lowercase()
            )),
            _ if !line.contains(',') && valid_domain(line) => Some(line.to_ascii_lowercase()),
            _ => None,
        },
        RuleBehavior::IpCidr => match kind.as_str() {
            "IP-CIDR" | "IP-CIDR6" if value.parse::<IpNet>().is_ok() => Some(value.to_owned()),
            _ if !line.contains(',') && line.parse::<IpNet>().is_ok() => Some(line.to_owned()),
            _ => None,
        },
    }
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('/')
        && !value.starts_with(char::is_whitespace)
        && !value.ends_with(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_domain_rules() {
        let input = "DOMAIN,one.example\nDOMAIN-SUFFIX,Example.COM\nIP-CIDR,10.0.0.0/8";
        let rules = normalize_rules(input, RuleBehavior::Domain, 10).unwrap();
        assert_eq!(rules, ["one.example", "+.example.com"]);
    }

    #[test]
    fn enforces_exact_limit() {
        let rules =
            normalize_rules("DOMAIN,a.test\nDOMAIN,b.test", RuleBehavior::Domain, 1).unwrap();
        assert_eq!(rules, ["a.test"]);
    }
}
