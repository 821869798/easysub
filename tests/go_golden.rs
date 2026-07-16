use std::{collections::HashMap, path::PathBuf};

use easysub_rs::{
    config::AppConfig,
    export::to_singbox_full,
    external::{LoadedRuleset, RulesetFormat},
    model::{Proxy, ProxyKind},
    template,
};
use serde_json::Value;

#[tokio::test]
async fn matches_go_singbox_golden_semantics() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config = AppConfig::load(root.join("workdir/pref.toml"))
        .await
        .unwrap();
    let request = HashMap::from([
        ("target".into(), "singbox".into()),
        ("singbox.enable_tun".into(), "true".into()),
        ("singbox.ipv6".into(), "true".into()),
    ]);
    let base = template::render(
        include_str!("../workdir/base/singbox.liquid"),
        &request,
        &config,
        true,
    )
    .unwrap();

    let mut vmess = Proxy::new(ProxyKind::Vmess, "vmess.test.com".into(), 443);
    vmess.name = "TestVMessHTTP".into();
    vmess.uuid = "e52002f2-d8de-48dc-b620-7b2f6b4a6829".into();
    vmess.method = "auto".into();
    vmess.network = "http".into();
    vmess.host = "vmess.host.com".into();
    vmess.path = "/vmess-path".into();

    let mut trojan = Proxy::new(ProxyKind::Trojan, "trojan.test.com".into(), 443);
    trojan.name = "TestTrojan".into();
    trojan.password = "trojan-password".into();
    trojan.tls = true;
    trojan.server_name = "trojan.sni.com".into();
    trojan.fingerprint = "chrome".into();

    let mut hysteria = Proxy::new(ProxyKind::Hysteria2, "hy2.test.com".into(), 443);
    hysteria.name = "TestHysteria2".into();
    hysteria.password = "hy2-password".into();
    hysteria.up_mbps = Some(100);
    hysteria.down_mbps = Some(100);
    hysteria.tls = true;
    hysteria.server_name = "hy2.sni.com".into();
    hysteria.fingerprint = "firefox".into();

    let rulesets = [
        LoadedRuleset {
            group: "proxy".into(),
            content: "[]GEOSITE,google".into(),
            format: RulesetFormat::Surge,
        },
        LoadedRuleset {
            group: "DIRECT".into(),
            content: "[]GEOIP,cn".into(),
            format: RulesetFormat::Surge,
        },
        LoadedRuleset {
            group: "proxy".into(),
            content: "[]FINAL,proxy".into(),
            format: RulesetFormat::Surge,
        },
    ];
    let rust: Value = serde_json::from_str(
        &to_singbox_full(
            &[vmess, trojan, hysteria],
            Some(&base),
            &[],
            &rulesets,
            false,
            0,
            &config.node_pref.singbox_rulesets,
            config.managed_config.ruleset_update_interval,
            false,
            false,
        )
        .unwrap(),
    )
    .unwrap();
    let go: Value =
        serde_json::from_str(include_str!("../scratch/generated_test_full.json")).unwrap();

    for tag in ["TestVMessHTTP", "TestTrojan", "TestHysteria2"] {
        let rust_outbound = tagged(&rust["outbounds"], tag);
        let go_outbound = tagged(&go["outbounds"], tag);
        for field in ["type", "server", "server_port"] {
            assert_eq!(rust_outbound[field], go_outbound[field], "{tag}.{field}");
        }
    }
    assert_eq!(
        tagged(&rust["outbounds"], "TestVMessHTTP")["transport"],
        tagged(&go["outbounds"], "TestVMessHTTP")["transport"]
    );
    assert_eq!(
        tagged(&rust["outbounds"], "TestTrojan")["tls"]["alpn"],
        tagged(&go["outbounds"], "TestTrojan")["tls"]["alpn"]
    );
    assert_eq!(rust["route"]["final"], go["route"]["final"]);

    for tag in ["geosite-google", "geoip-cn"] {
        let rust_ruleset = tagged(&rust["route"]["rule_set"], tag);
        let go_ruleset = tagged(&go["route"]["rule_set"], tag);
        assert_eq!(rust_ruleset["type"], go_ruleset["type"]);
        assert_eq!(rust_ruleset["format"], go_ruleset["format"]);
        assert_eq!(rust_ruleset["url"], go_ruleset["url"]);
    }
}

fn tagged<'a>(values: &'a Value, tag: &str) -> &'a Value {
    values
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["tag"] == tag)
        .unwrap_or_else(|| panic!("missing tag {tag}"))
}
