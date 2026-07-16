# easysub Rust rewrite progress

Last updated: 2026-07-16

Branch: `feat/rust-rewrite`

Target: replace the Go service only after every P0 acceptance item below passes.

## Status legend

- `[x]` implemented and covered by an automated or recorded real-service test.
- `[-]` usable, but compatibility or verification work remains.
- `[ ]` not implemented.
- `[~]` intentionally different from Go; the decision and safety boundary are recorded.

## Overall acceptance gates

- [-] Feature parity: all production inputs and routes used by the current deployment work.
- [-] Correctness: Rust output has a maintained Go/Rust golden corpus.
- [x] Reliability: bounded property fuzz smoke and configured upstream-failure policy are tested.
- [x] Performance: release throughput, latency, peak memory, and binary size have repeatable measurements and optional gates.
- [ ] Cutover: Rust has completed a shadow/canary period before the Go binary is removed.

The rewrite is currently a usable development implementation, not yet a complete Go replacement.

## HTTP and runtime

| ID | Status | Item | Acceptance evidence |
|---|---|---|---|
| HTTP-01 | [x] | Axum + Tokio service, graceful shutdown | Real listener smoke test |
| HTTP-02 | [x] | `GET /healthz` | Returns 204 |
| HTTP-03 | [x] | `GET /sub` for Clash and sing-box | YAML/JSON endpoint tests |
| HTTP-04 | [x] | `GET /ruleset` MRS response | Unit and compatibility fixtures |
| HTTP-05 | [x] | `GET /p/*path` private subscriptions | Real `private_sub.toml` smoke test |
| HTTP-06 | [x] | API-mode token and local-source authorization boundary | Default/local sources require token; explicit nodes and trusted private rewrites tested |
| HTTP-07 | [x] | Core query flags | insert/append_type/sort/scv/fdn/udp/tfo support true/false overrides; optional rule-provider flags track EXP-08 |
| HTTP-08 | [ ] | Response metadata parity | Subscription user-info and managed headers |

## Resource and concurrency model

| ID | Status | Item | Acceptance evidence |
|---|---|---|---|
| RES-01 | [~] | No Go-style global concurrency limit of 3 | 16 concurrent full-ACL requests passed |
| RES-02 | [x] | Maximum upstream response bytes | Stream stops at configured byte limit |
| RES-03 | [x] | Byte-weighted bounded cache | Moka cache uses response body weight |
| RES-04 | [x] | Request coalescing | Same upstream key shares in-flight fetch |
| RES-05 | [x] | URL/ruleset/rule-count limits | Exact-limit tests |
| RES-06 | [x] | Heavy-task semaphore | MRS/zstd work only |
| RES-07 | [x] | Repeatable peak-memory measurement | 16 full-ACL requests peaked at 36.52 MiB on the current machine |

## Subscription parsing

| ID | Status | Item | Notes |
|---|---|---|---|
| PARSE-01 | [x] | SIP002 Shadowsocks | Base64 and plugin fields |
| PARSE-02 | [x] | VMess / VMess1 | JSON, standard URL, Kitsunebi, Quan and Shadowrocket fixtures |
| PARSE-03 | [x] | VLESS / VLESS1 | TCP/WS/H2/gRPC, TLS/Reality and fingerprint fields tested |
| PARSE-04 | [x] | Trojan | Common URL and websocket aliases tested |
| PARSE-05 | [x] | TUIC | Authentication, timing, relay, congestion and stream fields tested |
| PARSE-06 | [x] | AnyTLS | Core and session fields tested |
| PARSE-07 | [x] | Hysteria2 | Authentication, obfs, bandwidth, port hopping, CA and CWND fields tested |
| PARSE-08 | [x] | HTTP/HTTPS/SOCKS5 URL nodes | Basic authentication supported |
| PARSE-09 | [x] | Telegram SOCKS/HTTP links | tg:// and t.me parsing plus endpoint test |
| PARSE-10 | [x] | Netch links | Base64 JSON fields for Go-supported protocols plus WireGuard tested |
| PARSE-11 | [x] | Snell and WireGuard inputs | Snell URLs plus Clash/sing-box WireGuard structures and exports tested |
| PARSE-12 | [x] | Subscription containers | Plain/base64 URI lists, Clash YAML, sing-box JSON and Surge `[Proxy]` configs tested |

## Exporters

| ID | Status | Item | Notes |
|---|---|---|---|
| EXP-01 | [x] | Deterministic node names and ordering | Duplicate-name tests |
| EXP-02 | [x] | Clash node output | Modern URI protocols plus structured Snell/WireGuard fields tested |
| EXP-03 | [x] | sing-box node output | Modern URI protocols and WireGuard endpoints tested; Snell intentionally skipped as unsupported |
| EXP-04 | [x] | Custom groups and ordered matchers | Literal/regex/special/range tests |
| EXP-05 | [x] | Group types | select/url-test/fallback/load-balance/relay/SSID and Clash provider `use` tested; sing-box uses valid selector fallback where no native equivalent exists |
| EXP-06 | [-] | Rule injection | Common domain/IP/process/port rules done |
| EXP-07 | [x] | sing-box GEOIP/GEOSITE transformations | Remote binary rule-sets and existing-base preservation tested |
| EXP-08 | [ ] | Clash rule-provider optimization | Optional performance feature; correctness must not depend on it |

## External configuration and rulesets

| ID | Status | Item | Notes |
|---|---|---|---|
| RULE-01 | [x] | Shadowed/repeated external INI keys | Order preserved |
| RULE-02 | [x] | Liquid rendering and Go-compatible bool filter | Template tests |
| RULE-03 | [x] | Surge, QuanX, Clash domain/IPCIDR/classical inputs | Basic conversion implemented |
| RULE-04 | [x] | Inline rules including `[]FINAL` | Clash MATCH and sing-box final tests |
| RULE-05 | [x] | Configured skip-on-fetch-failure behavior | Subscription/ruleset tests cover skip and strict modes |
| RULE-06 | [ ] | Full uncommon INI/group/provider syntax | Fixture-driven implementation |
| RULE-07 | [x] | MRS v1 Domain/IPCIDR encoder | Decompressed bytes match Mihomo fixtures |
| RULE-08 | [ ] | Large/mixed ruleset golden and memory corpus | Include exact limit behavior |

## Private subscriptions

| ID | Status | Item | Notes |
|---|---|---|---|
| PRIV-01 | [x] | `private_sub.toml` loading | Relative to main config |
| PRIV-02 | [x] | Ordered nested variables and form encoding | Unit test |
| PRIV-03 | [x] | `EASYSUB_PRIVATE` content override | Same startup path as file content |
| PRIV-04 | [x] | Internal `/p/*path` rewrite | No loopback HTTP request |

## Verification and release

| ID | Status | Item | Acceptance evidence |
|---|---|---|---|
| TEST-01 | [x] | Rust unit/integration suite | 48 tests including Netch, structured subscriptions and WireGuard golden semantics |
| TEST-02 | [x] | Go regression suite | `go test ./...` and `go vet ./...` |
| TEST-03 | [-] | Go/Rust golden-output corpus | sing-box VMess HTTP/Trojan/Hysteria2/WireGuard/geo/final semantics covered; expand to Clash |
| TEST-04 | [x] | Parser/ruleset/external-config property fuzz smoke | 128 bounded random cases per target on every test run |
| TEST-05 | [x] | Core and real-service performance harnesses | Structured support: 1k parse 1.511 ms; Clash 3.933 ms; sing-box 1.827 ms; 10k MRS 3.586 ms; 16 full-ACL requests 0.697 s |
| TEST-06 | [x] | Release binary-size baseline | 7.69 MiB on Windows x86-64 with latest dependencies |
| TEST-07 | [-] | CI gates | Rust 1.96 fmt/clippy/tests/Go regression/performance/size workflow added; awaiting first remote run |
| DOC-01 | [ ] | Rust deployment/operations README | Config, limits, logging, shutdown, upgrade |
| CUT-01 | [ ] | Shadow/canary deployment | Compare output and runtime metrics |

## Toolchain and dependencies

| ID | Status | Item | Evidence |
|---|---|---|---|
| DEP-01 | [x] | Rust version floor | Rust 1.96.0; no older toolchain compatibility target |
| DEP-02 | [x] | Direct crates at latest stable versions | crates.io API audit on 2026-07-16; tower-http upgraded to 0.7.0 |
| DEP-03 | [x] | Transitive lockfile update | `cargo update` selected the newest versions allowed by direct dependencies |
| DEP-04 | [-] | YAML implementation | `serde_yaml 0.9.34+deprecated` is still crates.io latest; replacement needs a separate compatibility decision |

Axum 0.8.9 pins `matchit = 0.8.4` exactly, so Cargo correctly rejects the
newer matchit 0.8.6 until Axum itself updates that constraint.

## Work order

1. P0 correctness: RULE-05, RULE-07 edge corpus, EXP-07, HTTP-06.
2. P0 input parity: PARSE-02/03/04/05/07 fixtures and fields used in production.
3. P1 verification: TEST-03, TEST-04, TEST-05, TEST-07.
4. P1 compatibility: remaining query flags, group/provider syntax, response metadata.
5. P2 optional features: Netch and Clash rule-provider optimization if measurements justify them.
6. Release: DOC-01, CUT-01, then remove Go only after all P0 gates are `[x]`.

## Milestone log

| Commit | Milestone |
|---|---|
| `9ed5a4c` | Axum runtime, core parsers/exporters, bounded fetch/cache, MRS encoder |
| `fc31113` | External INI configs, custom groups, and rulesets |
| `6a92641` | Private subscription rewrites |

Every later implementation commit must update the relevant status/evidence row in this file.

## Reproduce the verification

```powershell
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
go test ./...
go vet ./...
cargo bench --bench core
cargo build --release
.\scripts\measure-release.ps1 -Concurrency 16
```

Core benchmark limits are opt-in environment variables named like
`EASYSUB_BENCH_MAX_PARSE_1000_NODES_MS`. Release memory and size limits can be
enabled with `-MaxPeakMiB` and `-MaxBinaryMiB`.
