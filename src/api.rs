use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::{Query, RawQuery, State},
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
    Router::new()
        .route("/", get(root))
        .route("/healthz", get(health))
        .route("/sub", get(subscription))
        .route("/ruleset", get(ruleset))
        .with_state(state)
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

#[derive(Debug, Deserialize)]
struct SubscriptionQuery {
    target: String,
    url: Option<String>,
    config: Option<String>,
    #[serde(default)]
    append_type: bool,
    #[serde(default)]
    sort: bool,
}

async fn subscription(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<SubscriptionQuery>,
) -> Result<Response> {
    let sources = sources_or_default(query.url.as_deref(), &state.config)?;
    enforce_source_limit(&sources, &state.config)?;
    let concurrency = state
        .config
        .advance
        .fetch_concurrency
        .min(sources.len())
        .max(1);
    let ttl = Duration::from_secs(state.config.advance.cache_subscription);

    let mut loaded: Vec<(usize, Vec<Proxy>)> = stream::iter(sources.into_iter().enumerate())
        .map(|(index, source)| {
            let state = state.clone();
            async move {
                if looks_like_proxy(&source) {
                    return parse_node(&source, index as u32).map(|node| (index, vec![node]));
                }
                let bytes = state.fetcher.get(&source, ttl, false).await?;
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| AppError::BadRequest("subscription is not UTF-8".into()))?;
                parse_subscription(text, index as u32).map(|nodes| (index, nodes))
            }
        })
        .buffer_unordered(concurrency)
        .try_collect()
        .await?;
    loaded.sort_by_key(|(index, _)| *index);
    let nodes: Vec<Proxy> = loaded.into_iter().flat_map(|(_, nodes)| nodes).collect();

    let append_type = query.append_type
        || state.config.common.append_proxy_type
        || state.config.node_pref.append_proxy_type;
    let sort = query.sort || state.config.node_pref.sort_flag;
    let request_variables = query_variables(raw_query.as_deref());
    let external =
        load_external_config(&state, query.config.as_deref(), &request_variables).await?;
    let loaded_rulesets = if external
        .as_ref()
        .is_some_and(|external| external.enable_rule_generator)
    {
        load_rulesets(&state, &external.as_ref().expect("checked above").rulesets).await?
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
) -> Result<Option<ExternalConfig>> {
    let source = requested.filter(|source| !source.is_empty()).or_else(|| {
        (!state.config.common.default_external_config.is_empty())
            .then_some(state.config.common.default_external_config.as_str())
    });
    let Some(source) = source else {
        return Ok(None);
    };
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
) -> Result<Vec<LoadedRuleset>> {
    if specs.len() > state.config.advance.max_allowed_rulesets {
        return Err(AppError::Limit(format!(
            "ruleset count {} exceeds limit {}",
            specs.len(),
            state.config.advance.max_allowed_rulesets
        )));
    }
    let concurrency = state
        .config
        .advance
        .fetch_concurrency
        .min(specs.len())
        .max(1);
    let ttl = Duration::from_secs(state.config.advance.cache_ruleset);
    let mut loaded: Vec<(usize, LoadedRuleset)> = stream::iter(specs.iter().cloned().enumerate())
        .map(|(index, spec)| {
            let state = state.clone();
            async move {
                let content = if spec.inline {
                    spec.source.clone()
                } else {
                    let bytes = state.fetcher.get(&spec.source, ttl, false).await?;
                    std::str::from_utf8(&bytes)
                        .map_err(|_| AppError::BadRequest("ruleset is not UTF-8".into()))?
                        .to_owned()
                };
                Ok::<_, AppError>((
                    index,
                    LoadedRuleset {
                        group: spec.group,
                        content,
                        format: spec.format,
                    },
                ))
            }
        })
        .buffer_unordered(concurrency)
        .try_collect()
        .await?;
    loaded.sort_by_key(|(index, _)| *index);
    Ok(loaded.into_iter().map(|(_, ruleset)| ruleset).collect())
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
}
