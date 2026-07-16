use std::{collections::HashMap, path::PathBuf};

use easysub_rs::{
    config::AppConfig,
    export::{to_clash_full, to_singbox_full},
    external::{GroupKind, LoadedRuleset, ProxyGroup, RulesetFormat},
    model::{Proxy, ProxyKind},
    template,
};
use serde_json::Value;

#[tokio::test]
async fn matches_go_singbox_golden_semantics() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config = AppConfig::load(root.join("workdir/pref.example.toml"))
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

    let proxies = golden_proxies();

    let rulesets = [
        LoadedRuleset {
            group: "proxy".into(),
            source: String::new(),
            content: "[]GEOSITE,google".into(),
            format: RulesetFormat::Surge,
        },
        LoadedRuleset {
            group: "DIRECT".into(),
            source: String::new(),
            content: "[]GEOIP,cn".into(),
            format: RulesetFormat::Surge,
        },
        LoadedRuleset {
            group: "proxy".into(),
            source: String::new(),
            content: "[]FINAL,proxy".into(),
            format: RulesetFormat::Surge,
        },
    ];
    let rust: Value = serde_json::from_str(
        &to_singbox_full(
            &proxies,
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
    assert_eq!(rust["ntp"]["server"], go["ntp"]["server"]);

    let rust_wireguard = tagged(&rust["endpoints"], "TestWG");
    let go_wireguard = tagged(&go["endpoints"], "TestWG");
    assert_eq!(rust_wireguard["address"], go_wireguard["address"]);
    assert_eq!(rust_wireguard["private_key"], go_wireguard["private_key"]);
    assert_eq!(rust_wireguard["mtu"], go_wireguard["mtu"]);
    assert_eq!(
        rust_wireguard["peers"][0]["allowed_ips"],
        go_wireguard["peers"][0]["allowed_ips"]
    );
    assert_eq!(
        rust_wireguard["peers"][0]["reserved"],
        go_wireguard["peers"][0]["reserved"]
    );
    assert!(
        rust["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|outbound| outbound["tag"] != "TestSnell")
    );

    for tag in ["geosite-google", "geoip-cn"] {
        let rust_ruleset = tagged(&rust["route"]["rule_set"], tag);
        let go_ruleset = tagged(&go["route"]["rule_set"], tag);
        assert_eq!(rust_ruleset["type"], go_ruleset["type"]);
        assert_eq!(rust_ruleset["format"], go_ruleset["format"]);
        assert_eq!(rust_ruleset["url"], go_ruleset["url"]);
        assert_eq!(rust_ruleset["http_client"], go_ruleset["http_client"]);
    }
}

#[tokio::test]
async fn matches_go_clash_golden_semantics() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config = AppConfig::load(root.join("workdir/pref.example.toml"))
        .await
        .unwrap();
    let request = HashMap::from([
        ("target".into(), "clash".into()),
        ("clash.dns".into(), "false".into()),
    ]);
    let base = template::render(
        include_str!("../workdir/base/clash.liquid"),
        &request,
        &config,
        false,
    )
    .unwrap();
    let groups = [ProxyGroup {
        name: "proxy".into(),
        kind: GroupKind::Select,
        selectors: vec!["[]DIRECT".into(), ".*".into()],
        providers: Vec::new(),
        url: String::new(),
        interval: 0,
        tolerance: 0,
    }];
    let rulesets = [
        LoadedRuleset {
            group: "proxy".into(),
            source: String::new(),
            content: "DOMAIN-SUFFIX,example.com\nIP-CIDR,10.0.0.0/8,no-resolve".into(),
            format: RulesetFormat::Surge,
        },
        LoadedRuleset {
            group: "DIRECT".into(),
            source: String::new(),
            content: "[]FINAL".into(),
            format: RulesetFormat::Surge,
        },
    ];
    let rust: Value = serde_yaml::from_str(
        &to_clash_full(
            &golden_proxies(),
            Some(&base),
            &groups,
            &rulesets,
            true,
            0,
            false,
            false,
        )
        .unwrap(),
    )
    .unwrap();
    let go: Value =
        serde_yaml::from_str(include_str!("../scratch/generated_test_clash.yml")).unwrap();

    for field in ["mixed-port", "allow-lan", "mode", "log-level"] {
        assert_eq!(rust[field], go[field], "base field {field}");
    }
    let rust_vmess = named(&rust["proxies"], "TestVMessHTTP");
    let go_vmess = named(&go["proxies"], "TestVMessHTTP");
    for field in [
        "type",
        "server",
        "port",
        "uuid",
        "alterId",
        "cipher",
        "network",
        "http-opts",
    ] {
        assert_eq!(rust_vmess[field], go_vmess[field], "VMess.{field}");
    }
    for name in ["TestTrojan", "TestHysteria2"] {
        let rust_proxy = named(&rust["proxies"], name);
        let go_proxy = named(&go["proxies"], name);
        for field in ["type", "server", "port", "password"] {
            assert_eq!(rust_proxy[field], go_proxy[field], "{name}.{field}");
        }
    }
    assert_eq!(
        rust["proxy-groups"][0]["proxies"],
        go["proxy-groups"][0]["proxies"]
    );
    assert_eq!(rust["rules"], go["rules"]);
}

fn golden_proxies() -> Vec<Proxy> {
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

    let mut wireguard = Proxy::new(ProxyKind::Wireguard, "1.2.3.4".into(), 51820);
    wireguard.name = "TestWG".into();
    wireguard.wireguard_address = vec!["10.0.0.2/32".into(), "fd00::2/128".into()];
    wireguard.private_key = "aGFoYWhhaGFoYWhhaGFoYWhhaGFoYWhhaGFoYWhhaGE=".into();
    wireguard.public_key = "d293b3d3b3d3b3d3b3d3b3d3b3d3b3d3b3d3b3d2b2c=".into();
    wireguard.allowed_ips = vec!["0.0.0.0/0".into(), "::/0".into()];
    wireguard.mtu = Some(1420);
    wireguard.reserved = vec![1, 2, 3];

    let mut snell = Proxy::new(ProxyKind::Snell, "snell.test.com".into(), 8080);
    snell.name = "TestSnell".into();
    snell.password = "snell-password".into();

    vec![wireguard, vmess, trojan, hysteria, snell]
}

fn tagged<'a>(values: &'a Value, tag: &str) -> &'a Value {
    values
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["tag"] == tag)
        .unwrap_or_else(|| panic!("missing tag {tag}"))
}

fn named<'a>(values: &'a Value, name: &str) -> &'a Value {
    values
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["name"] == name)
        .unwrap_or_else(|| panic!("missing proxy {name}"))
}
