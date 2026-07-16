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
        for node in nodes {
            if !used.contains(&node.name) && matches_selector(selector, node) {
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

fn matches_selector(selector: &str, node: &Proxy) -> bool {
    let (matched, tail) = if let Some(value) = selector.strip_prefix("!!GROUP=") {
        special_regex(value, &node.group)
    } else if let Some(value) = selector.strip_prefix("!!TYPE=") {
        special_regex(value, &node.kind.label().to_ascii_uppercase())
    } else if let Some(value) = selector.strip_prefix("!!SERVER=") {
        special_regex(value, &node.server)
    } else if let Some(value) = selector.strip_prefix("!!PORT=") {
        special_range(value, i64::from(node.port))
    } else if let Some(value) = selector.strip_prefix("!!GROUPID=") {
        special_range(value, i64::from(node.group_id))
    } else if let Some(value) = selector.strip_prefix("!!INSERT=") {
        special_range(value, -i64::from(node.group_id))
    } else {
        return Regex::new(selector).is_ok_and(|regex| regex.is_match(&node.name));
    };
    matched
        && tail
            .filter(|tail| !tail.is_empty())
            .is_none_or(|tail| Regex::new(tail).is_ok_and(|regex| regex.is_match(&node.name)))
}

fn special_regex<'a>(value: &'a str, input: &str) -> (bool, Option<&'a str>) {
    let (pattern, tail) = value
        .split_once("!!")
        .map_or((value, None), |(head, tail)| (head, Some(tail)));
    (
        Regex::new(pattern).is_ok_and(|regex| regex.is_match(input)),
        tail,
    )
}

fn special_range(value: &str, target: i64) -> (bool, Option<&str>) {
    let (range, tail) = value
        .split_once("!!")
        .map_or((value, None), |(head, tail)| (head, Some(tail)));
    (match_range(range, target), tail)
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
}
