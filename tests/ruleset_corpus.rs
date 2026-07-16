use easysub_rs::{
    export::{to_clash_full, to_singbox_full},
    external::{LoadedRuleset, RulesetFormat},
};
use serde_json::Value;

const SOURCE_RULES: usize = 25_000;
const OUTPUT_LIMIT: usize = 4_096;

#[test]
fn large_mixed_ruleset_is_deterministic_and_strictly_bounded() {
    let (content, expected_clash) = mixed_ruleset(SOURCE_RULES);
    assert!(expected_clash.len() > OUTPUT_LIMIT);
    let rulesets = [LoadedRuleset {
        group: "PROXY".into(),
        content,
        format: RulesetFormat::Surge,
    }];

    let clash: Value = serde_yaml::from_str(
        &to_clash_full(&[], None, &[], &rulesets, true, OUTPUT_LIMIT, false, false).unwrap(),
    )
    .unwrap();
    let clash_rules = clash["rules"].as_array().unwrap();
    assert_eq!(clash_rules.len(), OUTPUT_LIMIT);
    for (actual, expected) in clash_rules.iter().zip(&expected_clash) {
        assert_eq!(actual.as_str(), Some(expected.as_str()));
    }

    let singbox_text = to_singbox_full(
        &[],
        None,
        &[],
        &rulesets,
        true,
        OUTPUT_LIMIT,
        &Default::default(),
        432_000,
        false,
        false,
    )
    .unwrap();
    let singbox: Value = serde_json::from_str(&singbox_text).unwrap();
    let singbox_rules = singbox["route"]["rules"].as_array().unwrap();
    assert_eq!(singbox_value_count(singbox_rules), OUTPUT_LIMIT);

    // The input is intentionally much larger than the configured rule limit.
    // Keep a generous serialized-output ceiling so a regression cannot retain
    // all 25k rules while still reporting the expected logical count.
    assert!(singbox_text.len() < 512 * 1024);
}

fn mixed_ruleset(count: usize) -> (String, Vec<String>) {
    let mut content = String::new();
    let mut expected = Vec::new();
    for index in 0..count {
        let rule = match index % 12 {
            0 => format!("DOMAIN,exact-{index}.example"),
            1 => format!("DOMAIN-SUFFIX,suffix-{index}.example"),
            2 => format!("DOMAIN-KEYWORD,keyword-{index}"),
            3 => format!(
                "IP-CIDR,10.{}.{}.0/24,no-resolve",
                index % 256,
                index / 256 % 256
            ),
            4 => format!("IP-CIDR6,2001:db8:{index:x}::/64,no-resolve"),
            5 => format!("SRC-IP-CIDR,172.16.{}.0/24", index % 256),
            6 => format!("PROCESS-NAME,process-{index}"),
            7 => format!("SRC-PORT,{}", 10_000 + index % 50_000),
            8 => format!("DST-PORT,{}", 10_000 + index % 50_000),
            9 => "NETWORK,tcp".into(),
            10 => "PROTOCOL,dns".into(),
            _ if index % 24 == 11 => format!("UNSUPPORTED,ignored-{index}"),
            _ => format!("# comment {index}"),
        };
        if !rule.starts_with(['#']) && !rule.starts_with("UNSUPPORTED") {
            let mut parts = rule.split(',');
            let kind = parts.next().unwrap();
            let value = parts.next().unwrap();
            let no_resolve = rule
                .split(',')
                .any(|part| part.eq_ignore_ascii_case("no-resolve"));
            expected.push(format!(
                "{kind},{value},PROXY{}",
                if no_resolve { ",no-resolve" } else { "" }
            ));
        }
        content.push_str(&rule);
        content.push('\n');
    }
    (content, expected)
}

fn singbox_value_count(rules: &[Value]) -> usize {
    const FIELDS: &[&str] = &[
        "domain",
        "domain_suffix",
        "domain_keyword",
        "ip_cidr",
        "source_ip_cidr",
        "process_name",
        "source_port",
        "port",
        "network",
        "protocol",
    ];
    rules
        .iter()
        .flat_map(|rule| FIELDS.iter().filter_map(|field| rule.get(*field)))
        .map(|values| values.as_array().map_or(1, Vec::len))
        .sum()
}
