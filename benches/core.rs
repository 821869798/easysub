use std::{env, hint::black_box, time::Instant};

use easysub_rs::{
    export::{to_clash, to_singbox},
    external::RulesetFormat,
    model::RuleBehavior,
    mrs,
    parser::parse_subscription,
    rules::parse_common_rules,
};

fn main() {
    if cfg!(debug_assertions) && env::var_os("EASYSUB_RUN_DEBUG_BENCH").is_none() {
        println!("core benchmark skipped in debug test builds");
        return;
    }
    let subscription = (0..1_000)
        .map(|index| {
            format!("trojan://password@node{index}.example:443?sni=edge.example#node-{index}")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let nodes = parse_subscription(&subscription, 0).expect("benchmark fixture must parse");
    let domains = (0..10_000)
        .map(|index| format!("domain-{index}.example"))
        .collect::<Vec<_>>();
    let mixed_rules = (0..10_000)
        .map(|index| match index % 5 {
            0 => format!("DOMAIN,domain-{index}.example"),
            1 => format!("DOMAIN-SUFFIX,suffix-{index}.example"),
            2 => format!("IP-CIDR,10.{}.{}.0/24", index % 256, index / 256 % 256),
            3 => format!("PROCESS-NAME,process-{index}"),
            _ => format!("DST-PORT,{}", 10_000 + index),
        })
        .collect::<Vec<_>>()
        .join("\n");

    bench("parse_1000_nodes", 100, || {
        black_box(parse_subscription(black_box(&subscription), 0).unwrap());
    });
    bench("clash_export_1000_nodes", 100, || {
        black_box(to_clash(black_box(&nodes), false, false).unwrap());
    });
    bench("singbox_export_1000_nodes", 100, || {
        black_box(to_singbox(black_box(&nodes), false, false).unwrap());
    });
    bench("mrs_10000_domains", 30, || {
        black_box(mrs::encode(black_box(&domains), RuleBehavior::Domain).unwrap());
    });
    bench("parse_10000_mixed_rules", 100, || {
        black_box(parse_common_rules(
            black_box(&mixed_rules),
            RulesetFormat::Surge,
            10_000,
        ));
    });
}

fn bench(name: &str, iterations: u32, mut operation: impl FnMut()) {
    for _ in 0..3 {
        operation();
    }
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    let elapsed = started.elapsed();
    let milliseconds = elapsed.as_secs_f64() * 1_000.0 / f64::from(iterations);
    let throughput = match name {
        "mrs_10000_domains" | "parse_10000_mixed_rules" => 10_000.0 / (milliseconds / 1_000.0),
        _ => 1_000.0 / (milliseconds / 1_000.0),
    };
    println!("{name}: {milliseconds:.3} ms/op, {throughput:.0} items/s ({iterations} iterations)");

    let key = format!("EASYSUB_BENCH_MAX_{}_MS", name.to_ascii_uppercase());
    if let Some(limit) = env::var(&key)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
    {
        assert!(
            milliseconds <= limit,
            "{name} took {milliseconds:.3} ms/op, exceeding {key}={limit:.3}"
        );
    }
}
