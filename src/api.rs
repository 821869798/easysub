use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::{Path, Query, RawQuery, State},
    http::{HeaderValue, StatusCode, header},
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
    export::{to_clash, to_clash_full, to_singbox, to_singbox_full},
    external::{self, ExternalConfig, LoadedRuleset},
    fetch::Fetcher,
    model::{Proxy, RuleBehavior},
    mrs,
    parser::{looks_like_proxy, parse_node, parse_subscription},
    rules::normalize_rules,
    template,
};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub fetcher: Fetcher,
    heavy_tasks: Arc<Semaphore>,
}

impl AppState {
    pub fn new(config: Arc<AppConfig>) -> Result<Self> {
        Ok(Self {
            fetcher: Fetcher::new(&config)?,
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
    };
    subscription_impl(
        State(state),
        RawQuery(Some(raw_query.to_owned())),
        Query(query),
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
}

async fn subscription(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<SubscriptionQuery>,
) -> Result<Response> {
    subscription_impl(State(state), RawQuery(raw_query), Query(query), false).await
}

async fn subscription_impl(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<SubscriptionQuery>,
    trusted: bool,
) -> Result<Response> {
    let authorized = trusted || request_is_authorized(&state.config, query.token.as_deref());
    let uses_default_sources = query.url.as_deref().is_none_or(str::is_empty);
    if state.config.common.api_mode && uses_default_sources && !authorized {
        return Err(AppError::Unauthorized(
            "token is required to use default subscription sources".into(),
        ));
    }
    let mut sources = sources_or_default(query.url.as_deref(), &state.config)?;
    reject_sensitive_sources(&sources, authorized, "subscription")?;
    let insert = query_flag(query.insert.as_deref()).unwrap_or(state.config.common.enable_insert);
    if insert && !state.config.common.insert_url.is_empty() {
        if state.config.common.prepend_insert_url {
            let mut combined = state.config.common.insert_url.clone();
            combined.extend(sources);
            sources = combined;
        } else {
            sources.extend(state.config.common.insert_url.iter().cloned());
        }
    }
    enforce_source_limit(&sources, &state.config)?;
    let concurrency = state
        .config
        .advance
        .fetch_concurrency
        .min(sources.len())
        .max(1);
    let ttl = Duration::from_secs(state.config.advance.cache_subscription);

    let skip_failed = state.config.advance.skip_failed_links;
    let mut loaded: Vec<(usize, Vec<Proxy>)> = stream::iter(sources.into_iter().enumerate())
        .map(|(index, source)| {
            let state = state.clone();
            async move {
                let result = async {
                    if looks_like_proxy(&source) {
                        return parse_node(&source, index as u32).map(|node| vec![node]);
                    }
                    let bytes = state.fetcher.get(&source, ttl, false).await?;
                    let text = std::str::from_utf8(&bytes)
                        .map_err(|_| AppError::BadRequest("subscription is not UTF-8".into()))?;
                    parse_subscription(text, index as u32)
                }
                .await;
                match result {
                    Ok(nodes) => Ok((index, nodes)),
                    Err(error) if skip_failed => {
                        tracing::warn!(%error, %source, "skipping failed subscription source");
                        Ok((index, Vec::new()))
                    }
                    Err(error) => Err(error),
                }
            }
        })
        .buffer_unordered(concurrency)
        .try_collect()
        .await?;
    loaded.sort_by_key(|(index, _)| *index);
    let mut nodes: Vec<Proxy> = loaded.into_iter().flat_map(|(_, nodes)| nodes).collect();
    if nodes.is_empty() {
        return Err(AppError::BadRequest(
            "all subscription sources failed or contained no supported nodes".into(),
        ));
    }

    let udp = query_flag(query.udp.as_deref()).or(state.config.node_pref.udp_flag);
    let tfo = query_flag(query.tfo.as_deref()).or(state.config.node_pref.tcp_fast_open_flag);
    let skip_cert_verify =
        query_flag(query.scv.as_deref()).or(state.config.node_pref.skip_cert_verify_flag);
    for node in &mut nodes {
        if let Some(value) = udp {
            node.udp = Some(value);
        }
        if let Some(value) = tfo {
            node.tcp_fast_open = Some(value);
        }
        if let Some(value) = skip_cert_verify {
            node.skip_cert_verify = Some(value);
        }
    }
    if query_flag(query.fdn.as_deref()).unwrap_or(state.config.node_pref.filter_deprecated_nodes) {
        nodes.retain(|node| {
            node.kind != crate::model::ProxyKind::Shadowsocks || node.method != "chacha20"
        });
    }
    if nodes.is_empty() {
        return Err(AppError::BadRequest(
            "all subscription nodes were filtered".into(),
        ));
    }
    let append_type = query_flag(query.append_type.as_deref()).unwrap_or(
        state.config.common.append_proxy_type || state.config.node_pref.append_proxy_type,
    );
    let sort = query_flag(query.sort.as_deref()).unwrap_or(state.config.node_pref.sort_flag);
    let request_variables = query_variables(raw_query.as_deref());
    let external = load_external_config(
        &state,
        query.config.as_deref(),
        &request_variables,
        authorized,
    )
    .await?;
    let loaded_rulesets = if external
        .as_ref()
        .is_some_and(|external| external.enable_rule_generator)
    {
        load_rulesets(
            &state,
            &external.as_ref().expect("checked above").rulesets,
            authorized,
        )
        .await?
    } else {
        Vec::new()
    };
    let groups = external
        .as_ref()
        .map(|external| external.groups.as_slice())
        .unwrap_or_default();
    let overwrite_rules = external
        .as_ref()
        .is_some_and(|external| external.overwrite_original_rules);
    match query.target.to_ascii_lowercase().as_str() {
        "clash" | "clashr" => {
            let base_source = external
                .as_ref()
                .and_then(|external| external.clash_rule_base.as_deref())
                .unwrap_or(&state.config.common.clash_rule_base);
            if external
                .as_ref()
                .and_then(|external| external.clash_rule_base.as_deref())
                .is_some_and(is_sensitive_source)
                && !authorized
            {
                return Err(AppError::Unauthorized(
                    "token is required for a local Clash rule base".into(),
                ));
            }
            let base = rendered_base(&state, base_source, &request_variables, false).await?;
            text_response(
                match base.as_deref() {
                    Some(base) => to_clash_full(
                        &nodes,
                        Some(base),
                        groups,
                        &loaded_rulesets,
                        overwrite_rules,
                        state.config.advance.max_allowed_rules,
                        append_type,
                        sort,
                    )?,
                    None if external.is_some() => to_clash_full(
                        &nodes,
                        None,
                        groups,
                        &loaded_rulesets,
                        overwrite_rules,
                        state.config.advance.max_allowed_rules,
                        append_type,
                        sort,
                    )?,
                    None => to_clash(&nodes, append_type, sort)?,
                },
                "text/yaml; charset=utf-8",
            )
        }
        "singbox" | "sing-box" => {
            let base_source = external
                .as_ref()
                .and_then(|external| external.singbox_rule_base.as_deref())
                .unwrap_or(&state.config.common.singbox_rule_base);
            if external
                .as_ref()
                .and_then(|external| external.singbox_rule_base.as_deref())
                .is_some_and(is_sensitive_source)
                && !authorized
            {
                return Err(AppError::Unauthorized(
                    "token is required for a local sing-box rule base".into(),
                ));
            }
            let base = rendered_base(&state, base_source, &request_variables, true).await?;
            text_response(
                match base.as_deref() {
                    Some(base) => to_singbox_full(
                        &nodes,
                        Some(base),
                        groups,
                        &loaded_rulesets,
                        overwrite_rules,
                        state.config.advance.max_allowed_rules,
                        &state.config.node_pref.singbox_rulesets,
                        state.config.managed_config.ruleset_update_interval,
                        append_type,
                        sort,
                    )?,
                    None if external.is_some() => to_singbox_full(
                        &nodes,
                        None,
                        groups,
                        &loaded_rulesets,
                        overwrite_rules,
                        state.config.advance.max_allowed_rules,
                        &state.config.node_pref.singbox_rulesets,
                        state.config.managed_config.ruleset_update_interval,
                        append_type,
                        sort,
                    )?,
                    None => to_singbox(&nodes, append_type, sort)?,
                },
                "application/json; charset=utf-8",
            )
        }
        target => Err(AppError::BadRequest(format!(
            "unsupported target: {target}"
        ))),
    }
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
            rules.extend(normalize_rules(text, behavior, remaining)?);
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

fn sources_or_default(url: Option<&str>, config: &AppConfig) -> Result<Vec<String>> {
    match url {
        Some(url) if !url.is_empty() => Ok(split_sources(url)),
        _ if !config.common.default_url.is_empty() => Ok(config.common.default_url.clone()),
        _ => Err(AppError::BadRequest("no subscription URL provided".into())),
    }
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

async fn rendered_base(
    state: &AppState,
    source: &str,
    request: &std::collections::HashMap<String, String>,
    singbox: bool,
) -> Result<Option<String>> {
    if source.is_empty() {
        return Ok(None);
    }
    let source = state.config.resolve_source(source);
    let bytes = state
        .fetcher
        .get(
            &source,
            Duration::from_secs(state.config.advance.cache_config),
            true,
        )
        .await?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| AppError::BadRequest("base template is not UTF-8".into()))?;
    template::render(text, request, &state.config, singbox).map(Some)
}

async fn load_external_config(
    state: &AppState,
    requested: Option<&str>,
    request: &std::collections::HashMap<String, String>,
    authorized: bool,
) -> Result<Option<ExternalConfig>> {
    let source = requested.filter(|source| !source.is_empty()).or_else(|| {
        (!state.config.common.default_external_config.is_empty())
            .then_some(state.config.common.default_external_config.as_str())
    });
    let Some(source) = source else {
        return Ok(None);
    };
    if requested.is_some() && is_sensitive_source(source) && !authorized {
        return Err(AppError::Unauthorized(
            "token is required for a local external config".into(),
        ));
    }
    let source = state.config.resolve_source(source);
    let bytes = state
        .fetcher
        .get(
            &source,
            Duration::from_secs(state.config.advance.cache_config),
            true,
        )
        .await?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| AppError::BadRequest("external config is not UTF-8".into()))?;
    let rendered = template::render(text, request, &state.config, false)?;
    external::parse(&rendered).map(Some)
}

async fn load_rulesets(
    state: &AppState,
    specs: &[external::RulesetSpec],
    authorized: bool,
) -> Result<Vec<LoadedRuleset>> {
    if specs.len() > state.config.advance.max_allowed_rulesets {
        return Err(AppError::Limit(format!(
            "ruleset count {} exceeds limit {}",
            specs.len(),
            state.config.advance.max_allowed_rulesets
        )));
    }
    if !authorized
        && specs
            .iter()
            .any(|spec| !spec.inline && is_sensitive_source(&spec.source))
    {
        return Err(AppError::Unauthorized(
            "token is required for local rulesets".into(),
        ));
    }
    let concurrency = state
        .config
        .advance
        .fetch_concurrency
        .min(specs.len())
        .max(1);
    let ttl = Duration::from_secs(state.config.advance.cache_ruleset);
    let skip_failed = state.config.advance.skip_failed_links;
    let mut loaded: Vec<(usize, Option<LoadedRuleset>)> = stream::iter(
        specs.iter().cloned().enumerate(),
    )
    .map(|(index, spec)| {
        let state = state.clone();
        async move {
            let result = async {
                let content = if spec.inline {
                    spec.source.clone()
                } else {
                    let bytes = state.fetcher.get(&spec.source, ttl, false).await?;
                    std::str::from_utf8(&bytes)
                        .map_err(|_| AppError::BadRequest("ruleset is not UTF-8".into()))?
                        .to_owned()
                };
                Ok::<_, AppError>(LoadedRuleset {
                    group: spec.group,
                    content,
                    format: spec.format,
                })
            }
            .await;
            match result {
                Ok(ruleset) => Ok((index, Some(ruleset))),
                Err(error) if skip_failed => {
                    tracing::warn!(%error, source = %spec.source, "skipping failed ruleset");
                    Ok((index, None))
                }
                Err(error) => Err(error),
            }
        }
    })
    .buffer_unordered(concurrency)
    .try_collect()
    .await?;
    loaded.sort_by_key(|(index, _)| *index);
    Ok(loaded
        .into_iter()
        .filter_map(|(_, ruleset)| ruleset)
        .collect())
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
    use std::path::PathBuf;

    use axum::{body::to_bytes, http::Request};
    use serde_json::Value;
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

        let singbox_response = router(AppState::new(Arc::new(fixture_config())).unwrap())
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
