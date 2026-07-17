# easysub-core

`easysub-core` is the HTTP-server-independent subscription conversion library used by
`easysub-rs`. It owns the complete conversion workflow:

- subscription, external config, base template, and ruleset fetching;
- bounded Moka caching and request concurrency;
- proxy parsing, filtering, grouping, and rule generation;
- Clash/Mihomo YAML and sing-box JSON output.

It intentionally does not depend on Axum or expose server request/response types.

```rust
use easysub_core::{
    config::AppConfig,
    subscription::{
        SubscriptionInput, SubscriptionRequest, SubscriptionService, SubscriptionTarget,
    },
};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = AppConfig::load("workdir/pref.toml").await?;
let service = SubscriptionService::new(config)?;
let mut request = SubscriptionRequest::new(SubscriptionTarget::Clash);
request
    .sources
    .push(SubscriptionInput::source("https://example.com/subscription"));
let output = service.convert(request).await?;
println!("{}", output.content);
# Ok(())
# }
```
