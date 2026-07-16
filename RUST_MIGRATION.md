# easysub Rust migration plan

The Go implementation remains the compatibility oracle until the Rust service
passes the same fixtures and can serve production traffic independently.

## Design goals

- Preserve `/sub`, `/ruleset`, and private-subscription URL compatibility.
- Keep the conversion core independent of Axum and Tokio.
- Bound memory by input size and work-unit budgets, not by a global request
  concurrency limit.
- Generate MRS v1 without linking or copying Mihomo GPL implementation code.
- Prefer deterministic output and golden tests over line-by-line source ports.

## Resource model

Ordinary HTTP requests are not globally restricted to three concurrent
requests. Network fetches are asynchronous and use connection pooling.
Protection is applied at the actual allocation boundaries:

- maximum bytes per upstream response;
- maximum URLs and rules per request;
- bounded in-memory cache weighted by bytes;
- configurable semaphore for CPU/memory-heavy MRS and zstd work;
- request deadlines and cancellation through Axum/Tokio.

Defaults are conservative but can be raised without recompiling.

## Delivery phases

1. Core models, protocol parsers, ruleset normalization, and MRS v1 encoder.
2. Clash and sing-box exporters with deterministic name/group handling.
3. Axum endpoints, bounded fetch/cache, tracing, and graceful shutdown.
4. External INI configuration and Liquid template compatibility.
5. Private subscriptions, full golden corpus, fuzzing, and performance gates.
6. Remove the Go build only after parity is documented and verified.

## Compatibility policy

Bug fixes covered by Go commit `9d8c581` are treated as required behavior:
rule limits are exact, invalid/skipped proxies do not reserve names, mixed
ruleset formats are not merged, and group matching preserves input order.

