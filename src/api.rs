use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::{Path, Query, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt, stream};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{
    config::AppConfig,
    error::{AppError, Result},
    fetch::{FetchMetadata, Fetcher},
    model::RuleBehavior,
    mrs,
    rules::normalize_rules_allow_empty,
    subscription::{
        ClashSubscriptionOptions, NodeConversionOptions, SubscriptionInput, SubscriptionRequest,
        SubscriptionService, SubscriptionTarget,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub fetcher: Fetcher,
    pub subscriptions: SubscriptionService,
    heavy_tasks: Arc<Semaphore>,
}

impl AppState {
    pub fn new(config: Arc<AppConfig>) -> Result<Self> {
        let fetcher = Fetcher::new(&config)?;
        Ok(Self {
            subscriptions: SubscriptionService::with_fetcher(config.clone(), fetcher.clone()),
            fetcher,
            heavy_tasks: Arc::new(Semaphore::new(config.advance.heavy_task_concurrency)),
            config,
        })
    }
}

pub fn router(state: AppState) -> Router {
    let timeout = state.config.request_timeout() + Duration::from_secs(5);
    let request_id = header::HeaderName::from_static("x-request-id");
    let app = Router::new()
        .route("/", get(root))
        .route("/healthz", get(health))
        .route("/sub", get(subscription))
        .route("/ruleset", get(ruleset));
    let app = if state.config.private_subscriptions.is_some() {
        app.route("/p/{*path}", get(private_subscription))
    } else {
        app
    };
    app.with_state(state)
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        .layer(CatchPanicLayer::new())
        .layer(TraceLayer::new_for_http())
}

async fn root() -> &'static str {
    "hello easysub-rs"
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn private_subscription(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let requested = format!("/{}", path.trim_start_matches('/'));
    let target = state
        .config
        .private_subscriptions
        .as_ref()
        .and_then(|private| private.route(&requested))
        .ok_or_else(|| AppError::NotFound(requested.clone()))?
        .to_owned();
    let (path, raw_query) = target
        .split_once('?')
        .ok_or_else(|| AppError::BadRequest("private rewrite has no query string".into()))?;
    if !path.trim_matches('/').eq_ignore_ascii_case("sub") {
        return Err(AppError::BadRequest(format!(
            "private rewrite target is unsupported: {path}"
        )));
    }
    let mut fields: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(raw_query.as_bytes())
            .into_owned()
            .collect();
    let query = SubscriptionQuery {
        target: fields
            .remove("target")
            .ok_or_else(|| AppError::BadRequest("private rewrite has no target".into()))?,
        url: fields.remove("url"),
        config: fields.remove("config"),
        token: fields.remove("token"),
        insert: fields.remove("insert"),
        append_type: fields.remove("append_type"),
        sort: fields.remove("sort"),
        scv: fields.remove("scv"),
        fdn: fields.remove("fdn"),
        udp: fields.remove("udp"),
        tfo: fields.remove("tfo"),
        clash_rso: fields.remove("clashRSO"),
        clash_rsoh: fields.remove("clashRSOH"),
        clash_gvr: fields.remove("clashGVR"),
    };
    subscription_impl(
        State(state),
        RawQuery(Some(raw_query.to_owned())),
        Query(query),
        headers,
        true,
    )
    .await
}

#[derive(Debug, Deserialize)]
struct SubscriptionQuery {
    target: String,
    url: Option<String>,
    config: Option<String>,
    token: Option<String>,
    insert: Option<String>,
    append_type: Option<String>,
    sort: Option<String>,
    scv: Option<String>,
    fdn: Option<String>,
    udp: Option<String>,
    tfo: Option<String>,
    #[serde(rename = "clashRSO")]
    clash_rso: Option<String>,
    #[serde(rename = "clashRSOH")]
    clash_rsoh: Option<String>,
    #[serde(rename = "clashGVR")]
    clash_gvr: Option<String>,
}

async fn subscription(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<SubscriptionQuery>,
    headers: HeaderMap,
) -> Result<Response> {
    subscription_impl(
        State(state),
        RawQuery(raw_query),
        Query(query),
        headers,
        false,
    )
    .await
}

async fn subscription_impl(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<SubscriptionQuery>,
    headers: HeaderMap,
    trusted: bool,
) -> Result<Response> {
    let target: SubscriptionTarget = query.target.parse()?;
    let optimize_to_http = query_flag(query.clash_rsoh.as_deref())
        .unwrap_or(state.config.node_pref.clash_ruleset_optimize_to_http);
    let provider_base_url = (target.is_clash() && optimize_to_http)
        .then(|| request_base_url(&headers))
        .transpose()?;
    let sources = query
        .url
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(split_sources)
        .unwrap_or_default()
        .into_iter()
        .map(SubscriptionInput::Source)
        .collect();
    let mut request = SubscriptionRequest::new(target);
    request.sources = sources;
    request.external_config = query.config;
    request.access_token = query.token;
    request.trusted = trusted;
    request.insert = query_flag(query.insert.as_deref());
    request.nodes = NodeConversionOptions {
        udp: query_flag(query.udp.as_deref()),
        tcp_fast_open: query_flag(query.tfo.as_deref()),
        skip_cert_verify: query_flag(query.scv.as_deref()),
        filter_deprecated: query_flag(query.fdn.as_deref()),
        append_proxy_type: query_flag(query.append_type.as_deref()),
        sort: query_flag(query.sort.as_deref()),
    };
    request.clash = ClashSubscriptionOptions {
        ruleset_optimize: query_flag(query.clash_rso.as_deref()),
        ruleset_optimize_to_http: query_flag(query.clash_rsoh.as_deref()),
        geo_convert_ruleset: query_flag(query.clash_gvr.as_deref()),
        provider_base_url,
    };
    request.template_variables = query_variables(raw_query.as_deref());

    let output = state.subscriptions.convert(request).await?;
    let mut response = text_response(output.content, output.content_type)?;
    if state.config.node_pref.append_sub_userinfo {
        apply_fetch_metadata(&mut response, &output.metadata);
    }
    Ok(response)
}

#[derive(Debug, Deserialize)]
struct RulesetQuery {
    target: String,
    url: String,
    behavior: String,
    token: Option<String>,
}

async fn ruleset(
    State(state): State<AppState>,
    Query(query): Query<RulesetQuery>,
) -> Result<Response> {
    if !query.target.eq_ignore_ascii_case("clash") {
        return Err(AppError::BadRequest(
            "only target=clash supports MRS".into(),
        ));
    }
    let behavior = match query.behavior.to_ascii_lowercase().as_str() {
        "domain" => RuleBehavior::Domain,
        "ipcidr" | "ip-cidr" => RuleBehavior::IpCidr,
        value => {
            return Err(AppError::BadRequest(format!(
                "unsupported behavior: {value}"
            )));
        }
    };
    let sources = split_sources(&query.url);
    let authorized = request_is_authorized(&state.config, query.token.as_deref());
    reject_sensitive_sources(&sources, authorized, "ruleset")?;
    enforce_source_limit(&sources, &state.config)?;
    let concurrency = state
        .config
        .advance
        .fetch_concurrency
        .min(sources.len())
        .max(1);
    let ttl = Duration::from_secs(state.config.advance.cache_ruleset);
    let contents: Vec<Bytes> = stream::iter(sources)
        .map(|source| {
            let fetcher = state.fetcher.clone();
            async move { fetcher.get(&source, ttl, false).await }
        })
        .buffer_unordered(concurrency)
        .try_collect()
        .await?;

    let max_rules = state.config.advance.max_allowed_rules;
    let permit = state
        .heavy_tasks
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| AppError::Internal("heavy-task semaphore closed".into()))?;
    let encoded = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut rules = Vec::new();
        for content in contents {
            let text = std::str::from_utf8(&content)
                .map_err(|_| AppError::BadRequest("ruleset is not UTF-8".into()))?;
            let remaining = if max_rules == 0 {
                0
            } else {
                max_rules.saturating_sub(rules.len())
            };
            if max_rules > 0 && remaining == 0 {
                break;
            }
            rules.extend(normalize_rules_allow_empty(text, behavior, remaining));
        }
        mrs::encode(&rules, behavior)
    })
    .await
    .map_err(|error| AppError::Internal(format!("MRS worker failed: {error}")))??;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=ruleset.mrs",
        )
        .body(Body::from(encoded))
        .map_err(|error| AppError::Internal(error.to_string()))
}

fn split_sources(value: &str) -> Vec<String> {
    value
        .split('|')
        .map(str::trim)
        .filter(|source| !source.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn request_is_authorized(config: &AppConfig, token: Option<&str>) -> bool {
    !config.common.api_mode || token.is_some_and(|token| token == config.common.api_access_token)
}

fn query_flag(value: Option<&str>) -> Option<bool> {
    match value?.to_ascii_lowercase().as_str() {
        "1" | "t" | "true" | "y" | "yes" | "on" => Some(true),
        "0" | "f" | "false" | "n" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn request_base_url(headers: &HeaderMap) -> Result<String> {
    let header_text = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let host = header_text("x-forwarded-host")
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .ok_or_else(|| AppError::BadRequest("Host header is required for clashRSOH".into()))?;
    if host.contains(['/', '\\', '#', '?']) {
        return Err(AppError::BadRequest(
            "Host header is invalid for clashRSOH".into(),
        ));
    }
    let force_https = std::env::var("SUB_FORCE_HTTPS")
        .ok()
        .as_deref()
        .and_then(|value| query_flag(Some(value)))
        .unwrap_or(false);
    let scheme = if force_https {
        "https"
    } else {
        match header_text("x-forwarded-proto") {
            Some("https") => "https",
            Some("http") | None => "http",
            Some(_) => {
                return Err(AppError::BadRequest(
                    "x-forwarded-proto must be http or https".into(),
                ));
            }
        }
    };
    Ok(format!("{scheme}://{host}"))
}

fn is_sensitive_source(source: &str) -> bool {
    source.starts_with("file://") || source.starts_with("env:") || !source.contains("://")
}

fn reject_sensitive_sources(sources: &[String], authorized: bool, kind: &str) -> Result<()> {
    if !authorized && sources.iter().any(|source| is_sensitive_source(source)) {
        return Err(AppError::Unauthorized(format!(
            "token is required for local {kind} sources"
        )));
    }
    Ok(())
}

fn enforce_source_limit(sources: &[String], config: &AppConfig) -> Result<()> {
    if sources.is_empty() {
        return Err(AppError::BadRequest("no source provided".into()));
    }
    if sources.len() > config.advance.max_allowed_rulesets {
        return Err(AppError::Limit(format!(
            "source count {} exceeds limit {}",
            sources.len(),
            config.advance.max_allowed_rulesets
        )));
    }
    Ok(())
}

#[cfg(test)]
fn merge_fetch_metadata(
    loaded: &[(usize, Vec<crate::model::Proxy>, FetchMetadata)],
) -> FetchMetadata {
    crate::subscription::merge_fetch_metadata(loaded)
}

fn apply_fetch_metadata(response: &mut Response, metadata: &FetchMetadata) {
    let headers = [
        ("subscription-userinfo", &metadata.subscription_userinfo),
        ("profile-web-page-url", &metadata.profile_web_page_url),
        ("profile-update-interval", &metadata.profile_update_interval),
    ];
    for (name, value) in headers {
        let Some(value) = value else {
            continue;
        };
        match HeaderValue::from_str(value) {
            Ok(value) => {
                response
                    .headers_mut()
                    .insert(header::HeaderName::from_static(name), value);
            }
            Err(error) => {
                tracing::warn!(%error, header = name, "ignoring invalid upstream response header");
            }
        }
    }
}

#[cfg(test)]
async fn load_rulesets(
    state: &AppState,
    specs: &[crate::external::RulesetSpec],
    authorized: bool,
) -> Result<Vec<crate::external::LoadedRuleset>> {
    state.subscriptions.load_rulesets(specs, authorized).await
}

fn query_variables(raw_query: Option<&str>) -> std::collections::HashMap<String, String> {
    raw_query
        .map(|raw| {
            url::form_urlencoded::parse(raw.as_bytes())
                .into_owned()
                .collect()
        })
        .unwrap_or_default()
}

fn text_response(body: String, content_type: &'static str) -> Result<Response> {
    let mut response = body.into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use std::{
        io::Read,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use crate::external;
    use axum::{body::to_bytes, http::Request, routing::get};
    use serde_json::Value;
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn serves_direct_proxy_as_clash_yaml() {
        let mut config = AppConfig::default();
        config.common.clash_rule_base.clear();
        let state = AppState::new(Arc::new(config)).unwrap();
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("target", "clash")
            .append_pair(
                "url",
                "trojan://secret@example.com:443?sni=edge.example.com#edge",
            )
            .finish();
        let response = router(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/sub?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let yaml = std::str::from_utf8(&body).unwrap();
        assert!(yaml.contains("type: trojan"));
        assert!(yaml.contains("name: edge"));
    }

    #[tokio::test]
    async fn health_endpoint_is_lightweight() {
        let state = AppState::new(Arc::new(AppConfig::default())).unwrap();
        let response = router(state)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn ruleset_combines_http_sources_when_one_has_no_matching_behavior() {
        let upstream = Router::new()
            .route("/domains", get(|| async { "DOMAIN,example.com" }))
            .route("/networks", get(|| async { "IP-CIDR,10.0.0.0/8" }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

        let sources = format!("http://{address}/domains|http://{address}/networks");
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("target", "clash")
            .append_pair("url", &sources)
            .append_pair("behavior", "ipcidr")
            .finish();
        let response = router(AppState::new(Arc::new(fixture_config())).unwrap())
            .oneshot(
                Request::builder()
                    .uri(format!("/ruleset?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/octet-stream"
        );
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let mut decoder = zstd::stream::Decoder::new(body.as_ref()).unwrap();
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert!(decoded.starts_with(b"MRS\x01\x01"));

        server.abort();
    }

    #[tokio::test]
    async fn preserves_upstream_subscription_metadata_in_cached_responses() {
        let upstream_hits = Arc::new(AtomicUsize::new(0));
        let upstream = Router::new().route(
            "/subscription",
            get({
                let upstream_hits = upstream_hits.clone();
                move || async move {
                    upstream_hits.fetch_add(1, Ordering::Relaxed);
                    (
                        [
                            (
                                "subscription-userinfo",
                                "upload=1; download=2; total=3; expire=4",
                            ),
                            ("profile-web-page-url", "https://portal.example.com/profile"),
                            ("profile-update-interval", "24"),
                        ],
                        "trojan://secret@example.com:443#edge",
                    )
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

        let mut config = fixture_config();
        config.node_pref.append_sub_userinfo = true;
        config.advance.cache_subscription = 60;
        let app = router(AppState::new(Arc::new(config)).unwrap());
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("target", "clash")
            .append_pair("url", &format!("http://{address}/subscription"))
            .finish();

        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/sub?{query}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()["subscription-userinfo"],
                "upload=1; download=2; total=3; expire=4"
            );
            assert_eq!(
                response.headers()["profile-web-page-url"],
                "https://portal.example.com/profile"
            );
            assert_eq!(response.headers()["profile-update-interval"], "24");
        }
        assert_eq!(upstream_hits.load(Ordering::Relaxed), 1);

        server.abort();
    }

    #[test]
    fn merges_each_metadata_field_in_source_order() {
        let loaded = vec![
            (
                0,
                Vec::new(),
                FetchMetadata {
                    subscription_userinfo: Some("upload=1".into()),
                    ..FetchMetadata::default()
                },
            ),
            (
                1,
                Vec::new(),
                FetchMetadata {
                    subscription_userinfo: Some("upload=2".into()),
                    profile_web_page_url: Some("https://portal.example.com".into()),
                    profile_update_interval: Some("24".into()),
                },
            ),
        ];
        let metadata = merge_fetch_metadata(&loaded);
        assert_eq!(metadata.subscription_userinfo.as_deref(), Some("upload=1"));
        assert_eq!(
            metadata.profile_web_page_url.as_deref(),
            Some("https://portal.example.com")
        );
        assert_eq!(metadata.profile_update_interval.as_deref(), Some("24"));
    }

    fn fixture_config() -> AppConfig {
        let mut config = AppConfig {
            base_dir: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("workdir"),
            ..AppConfig::default()
        };
        config.common.clash_rule_base.clear();
        config.common.singbox_rule_base.clear();
        config
    }

    fn external_query(target: &str) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("target", target)
            .append_pair(
                "url",
                "trojan://secret@example.com:443?sni=edge.example.com#edge",
            )
            .append_pair("config", "file:///ACL4SSR_NoRule.ini")
            .finish()
    }

    #[tokio::test]
    async fn applies_file_shared_external_config_to_clash_and_singbox() {
        let clash_response = router(AppState::new(Arc::new(fixture_config())).unwrap())
            .oneshot(
                Request::builder()
                    .uri(format!("/sub?{}", external_query("clash")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clash_response.status(), StatusCode::OK);
        let clash_body = to_bytes(clash_response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let clash: serde_yaml::Value = serde_yaml::from_slice(&clash_body).unwrap();
        assert_eq!(clash["proxy-groups"][0]["name"], "🚀 节点选择");
        assert_eq!(clash["proxy-groups"][0]["proxies"][0], "edge");
        assert_eq!(clash["rules"][0], "MATCH,🚀 节点选择");

        let mut singbox_config = fixture_config();
        singbox_config.node_pref.singbox_add_clash_modes = true;
        let singbox_response = router(AppState::new(Arc::new(singbox_config)).unwrap())
            .oneshot(
                Request::builder()
                    .uri(format!("/sub?{}", external_query("singbox")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(singbox_response.status(), StatusCode::OK);
        let singbox_body = to_bytes(singbox_response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let singbox: Value = serde_json::from_slice(&singbox_body).unwrap();
        let selector = singbox["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|outbound| outbound["tag"] == "🚀 节点选择")
            .unwrap();
        assert_eq!(selector["outbounds"][0], "edge");
        assert!(selector.get("url").is_none());
        assert!(selector.get("interval").is_none());
        assert!(
            singbox["outbounds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|outbound| outbound["tag"] == "GLOBAL")
        );
        assert_eq!(singbox["route"]["rules"][0]["clash_mode"], "Global");
        assert_eq!(singbox["route"]["rules"][1]["clash_mode"], "Direct");
        assert_eq!(singbox["route"]["rules"][2]["action"], "sniff");
        assert_eq!(singbox["route"]["rules"][3]["action"], "hijack-dns");
        assert_eq!(singbox["route"]["final"], "🚀 节点选择");
    }

    #[tokio::test]
    async fn serves_private_subscription_by_internal_rewrite() {
        let mut config = fixture_config();
        config.common.api_mode = true;
        config.common.api_access_token = "api-secret".into();
        config.private_subscriptions = Some(
            crate::private::PrivateSubscriptions::parse(
                r#"
[[vars]]
key = "node"
value = "trojan://secret@example.com:443?sni=edge.example.com#edge"

[[vars]]
key = "external"
value = "file:///ACL4SSR_NoRule.ini"

[[rewrites]]
key = "/clash/token"
value = "sub?target=clash&url={node}&config={external}"
"#,
            )
            .unwrap(),
        );
        let response = router(AppState::new(Arc::new(config)).unwrap())
            .oneshot(
                Request::builder()
                    .uri("/p/clash/token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let clash: serde_yaml::Value = serde_yaml::from_slice(&body).unwrap();
        assert_eq!(clash["proxies"][0]["name"], "edge");
        assert_eq!(clash["rules"][0], "MATCH,🚀 节点选择");
    }

    #[tokio::test]
    async fn checked_in_stash_rewrite_uses_downloadable_http_mrs_providers() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let config = AppConfig::load(root.join("workdir/pref.example.toml"))
            .await
            .unwrap();
        let app = router(AppState::new(config).unwrap());
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/p/stash/445566")
                    .header("host", "subscriptions.example")
                    .header("x-forwarded-proto", "https")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let clash: serde_yaml::Value = serde_yaml::from_slice(&body).unwrap();
        let providers = clash["rule-providers"].as_mapping().unwrap();
        assert!(!providers.is_empty());
        for provider in providers.values() {
            assert_eq!(provider["type"], "http");
            assert_eq!(provider["format"], "mrs");
            assert!(provider.get("payload").is_none());
        }
        assert!(
            clash["rules"]
                .as_sequence()
                .unwrap()
                .iter()
                .any(|rule| rule.as_str().unwrap_or_default().starts_with("RULE-SET,"))
        );

        let provider_url = providers
            .values()
            .find_map(|provider| provider["url"].as_str())
            .unwrap();
        let provider_url = url::Url::parse(provider_url).unwrap();
        assert_eq!(
            provider_url.origin().ascii_serialization(),
            "https://subscriptions.example"
        );
        let provider_uri = match provider_url.query() {
            Some(query) => format!("{}?{query}", provider_url.path()),
            None => provider_url.path().to_owned(),
        };
        let mrs_response = app
            .oneshot(
                Request::builder()
                    .uri(provider_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mrs_response.status(), StatusCode::OK);
        assert_eq!(
            mrs_response.headers()[header::CONTENT_TYPE],
            "application/octet-stream"
        );
        assert!(
            !to_bytes(mrs_response.into_body(), 1024 * 1024)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn api_mode_protects_local_sources_but_allows_explicit_nodes() {
        let mut config = fixture_config();
        config.common.api_mode = true;
        config.common.api_access_token = "api-secret".into();

        let unauthorized = router(AppState::new(Arc::new(config.clone())).unwrap())
            .oneshot(
                Request::builder()
                    .uri(format!("/sub?{}", external_query("clash")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let authorized = router(AppState::new(Arc::new(config.clone())).unwrap())
            .oneshot(
                Request::builder()
                    .uri(format!("/sub?{}&token=api-secret", external_query("clash")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);

        let node_query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("target", "clash")
            .append_pair("url", "trojan://secret@example.com:443#edge")
            .finish();
        let explicit_node = router(AppState::new(Arc::new(config)).unwrap())
            .oneshot(
                Request::builder()
                    .uri(format!("/sub?{node_query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(explicit_node.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn api_mode_protects_default_subscriptions_and_local_rulesets() {
        let mut config = fixture_config();
        config.common.api_mode = true;
        config.common.api_access_token = "api-secret".into();
        config.common.default_url = vec!["trojan://secret@example.com:443#edge".into()];

        let default_source = router(AppState::new(Arc::new(config.clone())).unwrap())
            .oneshot(
                Request::builder()
                    .uri("/sub?target=clash")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(default_source.status(), StatusCode::UNAUTHORIZED);

        let ruleset_query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("target", "clash")
            .append_pair("url", "file:///custom_direct.plist")
            .append_pair("behavior", "domain")
            .finish();
        let local_ruleset = router(AppState::new(Arc::new(config)).unwrap())
            .oneshot(
                Request::builder()
                    .uri(format!("/ruleset?{ruleset_query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(local_ruleset.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn query_flags_override_node_and_output_defaults() {
        let mut config = fixture_config();
        config.common.append_proxy_type = true;
        config.node_pref.sort_flag = true;
        config.node_pref.udp_flag = Some(true);
        config.node_pref.tcp_fast_open_flag = Some(false);
        config.node_pref.skip_cert_verify_flag = Some(false);
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("target", "clash")
            .append_pair(
                "url",
                "trojan://secret@z.example:443#z|ss://Y2hhY2hhMjA6cGFzcw@deprecated.example:443#deprecated|trojan://secret@a.example:443#a",
            )
            .append_pair("append_type", "false")
            .append_pair("sort", "0")
            .append_pair("udp", "false")
            .append_pair("tfo", "1")
            .append_pair("scv", "true")
            .append_pair("fdn", "true")
            .finish();
        let response = router(AppState::new(Arc::new(config)).unwrap())
            .oneshot(
                Request::builder()
                    .uri(format!("/sub?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let clash: serde_yaml::Value = serde_yaml::from_slice(&body).unwrap();
        assert_eq!(clash["proxies"][0]["name"], "z");
        assert_eq!(clash["proxies"][1]["name"], "a");
        assert_eq!(clash["proxies"].as_sequence().unwrap().len(), 2);
        assert_eq!(clash["proxies"][0]["udp"], false);
        assert_eq!(clash["proxies"][0]["tfo"], true);
        assert_eq!(clash["proxies"][0]["skip-cert-verify"], true);
    }

    #[tokio::test]
    async fn configured_insert_sources_can_be_disabled_per_request() {
        let mut config = fixture_config();
        config.common.insert_url = vec!["trojan://secret@insert.example:443#insert".into()];
        config.common.enable_insert = true;
        config.common.prepend_insert_url = true;
        let query = |insert: &str| {
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("target", "clash")
                .append_pair("url", "trojan://secret@main.example:443#main")
                .append_pair("insert", insert)
                .finish()
        };
        let enabled = router(AppState::new(Arc::new(config.clone())).unwrap())
            .oneshot(
                Request::builder()
                    .uri(format!("/sub?{}", query("true")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(enabled.into_body(), 1024 * 1024).await.unwrap();
        let clash: serde_yaml::Value = serde_yaml::from_slice(&body).unwrap();
        assert_eq!(clash["proxies"][0]["name"], "insert");
        assert_eq!(clash["proxies"][1]["name"], "main");

        let disabled = router(AppState::new(Arc::new(config)).unwrap())
            .oneshot(
                Request::builder()
                    .uri(format!("/sub?{}", query("false")))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(disabled.into_body(), 1024 * 1024).await.unwrap();
        let clash: serde_yaml::Value = serde_yaml::from_slice(&body).unwrap();
        assert_eq!(clash["proxies"].as_sequence().unwrap().len(), 1);
        assert_eq!(clash["proxies"][0]["name"], "main");
    }

    #[tokio::test]
    async fn telegram_proxy_links_are_not_fetched_as_subscriptions() {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("target", "clash")
            .append_pair(
                "url",
                "https://t.me/socks?server=socks.example&port=1080&user=test&pass=secret&remarks=Telegram",
            )
            .finish();
        let response = router(AppState::new(Arc::new(fixture_config())).unwrap())
            .oneshot(
                Request::builder()
                    .uri(format!("/sub?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let clash: serde_yaml::Value = serde_yaml::from_slice(&body).unwrap();
        assert_eq!(clash["proxies"][0]["type"], "socks5");
        assert_eq!(clash["proxies"][0]["name"], "Telegram");
    }

    #[tokio::test]
    async fn skips_failed_subscription_sources_when_enabled() {
        let mut config = fixture_config();
        config.advance.skip_failed_links = true;
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("target", "clash")
            .append_pair(
                "url",
                "unsupported://bad|trojan://secret@example.com:443#edge",
            )
            .finish();
        let response = router(AppState::new(Arc::new(config)).unwrap())
            .oneshot(
                Request::builder()
                    .uri(format!("/sub?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let clash: serde_yaml::Value = serde_yaml::from_slice(&body).unwrap();
        assert_eq!(clash["proxies"].as_sequence().unwrap().len(), 1);
        assert_eq!(clash["proxies"][0]["name"], "edge");
    }

    #[tokio::test]
    async fn preserves_ruleset_order_while_skipping_failures() {
        let state = AppState::new(Arc::new(fixture_config())).unwrap();
        let specs = [
            external::RulesetSpec {
                group: "BROKEN".into(),
                source: "unsupported://rules".into(),
                interval: 0,
                format: external::RulesetFormat::Surge,
                inline: false,
            },
            external::RulesetSpec {
                group: "FINAL".into(),
                source: "[]FINAL".into(),
                interval: 0,
                format: external::RulesetFormat::Surge,
                inline: true,
            },
        ];
        let loaded = load_rulesets(&state, &specs, true).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].group, "FINAL");

        let mut strict_config = fixture_config();
        strict_config.advance.skip_failed_links = false;
        let strict_state = AppState::new(Arc::new(strict_config)).unwrap();
        assert!(load_rulesets(&strict_state, &specs, true).await.is_err());
    }
}
