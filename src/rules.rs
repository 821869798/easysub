use ipnet::IpNet;
use serde::Deserialize;

use crate::{
    error::{AppError, Result},
    model::RuleBehavior,
};

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
