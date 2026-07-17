//! Proxy group selection.

use std::collections::HashSet;

use regex::Regex;

use crate::{external::ProxyGroup, model::Proxy};

pub fn members(group: &ProxyGroup, nodes: &[Proxy]) -> Vec<String> {
    let mut selected = Vec::new();
    let mut used = HashSet::new();
    for selector in &group.selectors {
        if let Some(literal) = selector.strip_prefix("[]") {
            if used.insert(literal.to_owned()) {
                selected.push(literal.to_owned());
            }
            continue;
        }
        let matcher = SelectorMatcher::compile(selector);
        for node in nodes {
            if !used.contains(&node.name) && matcher.matches(node) {
                used.insert(node.name.clone());
                selected.push(node.name.clone());
            }
        }
    }
    if selected.is_empty() {
        selected.push("DIRECT".into());
    }
    selected
}

enum SelectorMatcher<'a> {
    Name(Option<Regex>),
    Field {
        field: RegexField,
        pattern: Option<Regex>,
        tail: TailMatcher,
    },
    Range {
        field: RangeField,
        expression: &'a str,
        tail: TailMatcher,
    },
}

enum RegexField {
    Group,
    Type,
    Server,
}

enum RangeField {
    Port,
    GroupId,
    Insert,
}

enum TailMatcher {
    None,
    Regex(Option<Regex>),
}

impl TailMatcher {
    fn compile(pattern: Option<&str>) -> Self {
        match pattern.filter(|pattern| !pattern.is_empty()) {
            Some(pattern) => Self::Regex(Regex::new(pattern).ok()),
            None => Self::None,
        }
    }

    fn matches(&self, name: &str) -> bool {
        match self {
            Self::None => true,
            Self::Regex(regex) => regex.as_ref().is_some_and(|regex| regex.is_match(name)),
        }
    }
}

impl<'a> SelectorMatcher<'a> {
    fn compile(selector: &'a str) -> Self {
        for (prefix, field) in [
            ("!!GROUP=", RegexField::Group),
            ("!!TYPE=", RegexField::Type),
            ("!!SERVER=", RegexField::Server),
        ] {
            if let Some(value) = selector.strip_prefix(prefix) {
                let (pattern, tail) = split_special(value);
                return Self::Field {
                    field,
                    pattern: Regex::new(pattern).ok(),
                    tail: TailMatcher::compile(tail),
                };
            }
        }
        for (prefix, field) in [
            ("!!PORT=", RangeField::Port),
            ("!!GROUPID=", RangeField::GroupId),
            ("!!INSERT=", RangeField::Insert),
        ] {
            if let Some(value) = selector.strip_prefix(prefix) {
                let (expression, tail) = split_special(value);
                return Self::Range {
                    field,
                    expression,
                    tail: TailMatcher::compile(tail),
                };
            }
        }
        Self::Name(Regex::new(selector).ok())
    }

    fn matches(&self, node: &Proxy) -> bool {
        let (matched, tail) = match self {
            Self::Name(regex) => {
                return regex
                    .as_ref()
                    .is_some_and(|regex| regex.is_match(&node.name));
            }
            Self::Field {
                field,
                pattern,
                tail,
            } => {
                let matched = pattern.as_ref().is_some_and(|regex| match field {
                    RegexField::Group => regex.is_match(&node.group),
                    RegexField::Type => regex.is_match(&node.kind.label().to_ascii_uppercase()),
                    RegexField::Server => regex.is_match(&node.server),
                });
                (matched, tail)
            }
            Self::Range {
                field,
                expression,
                tail,
            } => {
                let target = match field {
                    RangeField::Port => i64::from(node.port),
                    RangeField::GroupId => i64::from(node.group_id),
                    RangeField::Insert => -i64::from(node.group_id),
                };
                (match_range(expression, target), tail)
            }
        };
        matched && tail.matches(&node.name)
    }
}

fn split_special(value: &str) -> (&str, Option<&str>) {
    value
        .split_once("!!")
        .map_or((value, None), |(head, tail)| (head, Some(tail)))
}

fn match_range(expression: &str, target: i64) -> bool {
    let mut has_positive = false;
    let mut matched_positive = false;
    for item in expression.split(',').map(str::trim) {
        let (negated, item) = item
            .strip_prefix('!')
            .map_or((false, item), |item| (true, item));
        let matched = match_range_item(item, target);
        if negated && matched {
            return false;
        }
        if !negated {
            has_positive = true;
            matched_positive |= matched;
        }
    }
    !has_positive || matched_positive
}

fn match_range_item(item: &str, target: i64) -> bool {
    if let Some(value) = item.strip_suffix('+') {
        return value.parse::<i64>().is_ok_and(|minimum| target >= minimum);
    }
    if let Some(value) = item.strip_suffix('-').filter(|_| !item.starts_with('-')) {
        return value.parse::<i64>().is_ok_and(|maximum| target <= maximum);
    }
    if let Some((begin, end)) = item
        .split_once('-')
        .filter(|(begin, end)| !begin.is_empty() && !end.is_empty())
    {
        return begin
            .parse::<i64>()
            .ok()
            .zip(end.parse::<i64>().ok())
            .is_some_and(|(begin, end)| target >= begin && target <= end);
    }
    item.parse::<i64>() == Ok(target)
}

#[cfg(test)]
mod tests {
    use crate::{external::GroupKind, model::ProxyKind};

    use super::*;

    #[test]
    fn preserves_selector_order_and_deduplicates() {
        let mut one = Proxy::new(ProxyKind::Vmess, "one.test".into(), 443);
        one.name = "alpha".into();
        let mut two = Proxy::new(ProxyKind::Trojan, "two.test".into(), 443);
        two.name = "beta".into();
        let group = ProxyGroup {
            name: "g".into(),
            kind: GroupKind::Select,
            selectors: vec!["[]DIRECT".into(), ".*".into(), "alpha".into()],
            providers: Vec::new(),
            url: String::new(),
            interval: 0,
            tolerance: 0,
        };
        assert_eq!(members(&group, &[one, two]), ["DIRECT", "alpha", "beta"]);
    }

    #[test]
    fn supports_ranges_and_negation() {
        assert!(match_range("1-3,!2", 3));
        assert!(!match_range("1-3,!2", 2));
        assert!(match_range("!1,!2", 3));
    }

    #[test]
    fn compiled_special_selectors_preserve_matching_semantics() {
        let mut node = Proxy::new(ProxyKind::Trojan, "edge.example".into(), 443);
        node.name = "alpha-edge".into();
        node.group = "premium".into();
        node.group_id = 7;

        for selector in [
            "^alpha",
            "!!GROUP=^premium$!!edge$",
            "!!TYPE=^TROJAN$",
            "!!SERVER=example$",
            "!!PORT=443",
            "!!GROUPID=7",
            "!!INSERT=-7",
        ] {
            assert!(
                SelectorMatcher::compile(selector).matches(&node),
                "selector should match: {selector}"
            );
        }
        assert!(!SelectorMatcher::compile("[").matches(&node));
        assert!(!SelectorMatcher::compile("!!GROUP=premium!![").matches(&node));
    }
}
