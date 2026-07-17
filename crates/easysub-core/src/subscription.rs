//! Complete reusable subscription conversion workflow.

use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};

use futures_util::{StreamExt, TryStreamExt, stream};

use crate::{
    config::AppConfig,
    error::{AppError, Result},
    export::{
        ClashRulesetOptions, SingboxExportOptions, to_clash, to_clash_full_with_options,
        to_singbox_full_with_options,
    },
    external::{self, ExternalConfig, LoadedRuleset},
    fetch::{FetchMetadata, Fetcher},
    model::{Proxy, ProxyKind},
    parser::{looks_like_proxy, parse_node, parse_subscription},
    template,
};

/// Output format produced by a subscription conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionTarget {
    Clash,
    SingBox,
}

impl SubscriptionTarget {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Clash => "text/yaml; charset=utf-8",
            Self::SingBox => "application/json; charset=utf-8",
        }
    }

    pub fn is_clash(self) -> bool {
        matches!(self, Self::Clash)
    }
}

impl FromStr for SubscriptionTarget {
    type Err = AppError;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "clash" | "clashr" => Ok(Self::Clash),
            "singbox" | "sing-box" => Ok(Self::SingBox),
            target => Err(AppError::BadRequest(format!(
                "unsupported target: {target}"
            ))),
        }
    }
}

/// A subscription can be fetched from a URL/path or supplied directly by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionInput {
    Source(String),
    Content(String),
}

impl SubscriptionInput {
    pub fn source(value: impl Into<String>) -> Self {
        Self::Source(value.into())
    }

    pub fn content(value: impl Into<String>) -> Self {
        Self::Content(value.into())
    }

    fn description(&self) -> &str {
        match self {
            Self::Source(source) => source,
            Self::Content(_) => "<inline subscription>",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NodeConversionOptions {
    pub udp: Option<bool>,
    pub tcp_fast_open: Option<bool>,
    pub skip_cert_verify: Option<bool>,
    pub filter_deprecated: Option<bool>,
    pub append_proxy_type: Option<bool>,
    pub sort: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct ClashSubscriptionOptions {
    pub ruleset_optimize: Option<bool>,
    pub ruleset_optimize_to_http: Option<bool>,
    pub geo_convert_ruleset: Option<bool>,
    /// Public service base URL used when `ruleset_optimize_to_http` is enabled.
    pub provider_base_url: Option<String>,
}

/// Complete input for the `/sub` business workflow, independent of Axum.
#[derive(Debug, Clone)]
pub struct SubscriptionRequest {
    pub target: SubscriptionTarget,
    /// Empty means use `AppConfig::common.default_url`.
    pub sources: Vec<SubscriptionInput>,
    pub external_config: Option<String>,
    pub access_token: Option<String>,
    /// Allows a trusted in-process caller to use local/default sources without a token.
    pub trusted: bool,
    pub insert: Option<bool>,
    pub nodes: NodeConversionOptions,
    pub clash: ClashSubscriptionOptions,
    /// Variables made available to Liquid base/external templates.
    pub template_variables: HashMap<String, String>,
}

impl SubscriptionRequest {
    pub fn new(target: SubscriptionTarget) -> Self {
        Self {
            target,
            sources: Vec::new(),
            external_config: None,
            access_token: None,
            trusted: false,
            insert: None,
            nodes: NodeConversionOptions::default(),
            clash: ClashSubscriptionOptions::default(),
            template_variables: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubscriptionOutput {
    pub content: String,
    pub content_type: &'static str,
    pub metadata: FetchMetadata,
}

/// Reusable async subscription converter containing the complete `/sub` workflow.
#[derive(Clone)]
pub struct SubscriptionService {
    config: Arc<AppConfig>,
    fetcher: Fetcher,
}

struct PreparedConversion<'a> {
    nodes: &'a [Proxy],
    groups: &'a [external::ProxyGroup],
    loaded_rulesets: &'a [LoadedRuleset],
    external: Option<&'a ExternalConfig>,
    overwrite_rules: bool,
    enable_rule_generator: bool,
    append_type: bool,
    sort: bool,
    authorized: bool,
}

impl SubscriptionService {
    pub fn new(config: Arc<AppConfig>) -> Result<Self> {
        let fetcher = Fetcher::new(&config)?;
        Ok(Self { config, fetcher })
    }

    pub fn with_fetcher(config: Arc<AppConfig>, fetcher: Fetcher) -> Self {
        Self { config, fetcher }
    }

    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    pub async fn convert(&self, mut request: SubscriptionRequest) -> Result<SubscriptionOutput> {
        let authorized =
            request.trusted || request_is_authorized(&self.config, request.access_token.as_deref());
        let uses_default_sources = request.sources.is_empty();
        if self.config.common.api_mode && uses_default_sources && !authorized {
            return Err(AppError::Unauthorized(
                "token is required to use default subscription sources".into(),
            ));
        }

        let mut sources = self.sources_or_default(std::mem::take(&mut request.sources))?;
        reject_sensitive_inputs(&sources, authorized, "subscription")?;
        let insert = request.insert.unwrap_or(self.config.common.enable_insert);
        if insert && !self.config.common.insert_url.is_empty() {
            let inserts = self
                .config
                .common
                .insert_url
                .iter()
                .cloned()
                .map(SubscriptionInput::Source);
            if self.config.common.prepend_insert_url {
                let mut combined: Vec<_> = inserts.collect();
                combined.extend(sources);
                sources = combined;
            } else {
                sources.extend(inserts);
            }
        }
        enforce_source_limit(sources.len(), &self.config)?;

        let concurrency = self
            .config
            .advance
            .fetch_concurrency
            .min(sources.len())
            .max(1);
        let ttl = Duration::from_secs(self.config.advance.cache_subscription);
        let skip_failed = self.config.advance.skip_failed_links;
        let mut loaded: Vec<(usize, Vec<Proxy>, FetchMetadata)> =
            stream::iter(sources.into_iter().enumerate())
                .map(|(index, input)| {
                    let service = self.clone();
                    async move {
                        let result = service.load_subscription_input(&input, index, ttl).await;
                        match result {
                            Ok((nodes, metadata)) => Ok((index, nodes, metadata)),
                            Err(error) if skip_failed => {
                                tracing::warn!(
                                    %error,
                                    source = input.description(),
                                    "skipping failed subscription source"
                                );
                                Ok((index, Vec::new(), FetchMetadata::default()))
                            }
                            Err(error) => Err(error),
                        }
                    }
                })
                .buffer_unordered(concurrency)
                .try_collect()
                .await?;
        loaded.sort_by_key(|(index, _, _)| *index);
        let metadata = merge_fetch_metadata(&loaded);
        let mut nodes: Vec<Proxy> = loaded.into_iter().flat_map(|(_, nodes, _)| nodes).collect();
        if nodes.is_empty() {
            return Err(AppError::BadRequest(
                "all subscription sources failed or contained no supported nodes".into(),
            ));
        }

        apply_node_options(&mut nodes, &request.nodes, &self.config);
        if request
            .nodes
            .filter_deprecated
            .unwrap_or(self.config.node_pref.filter_deprecated_nodes)
        {
            nodes.retain(|node| node.kind != ProxyKind::Shadowsocks || node.method != "chacha20");
        }
        if nodes.is_empty() {
            return Err(AppError::BadRequest(
                "all subscription nodes were filtered".into(),
            ));
        }

        let append_type = request.nodes.append_proxy_type.unwrap_or(
            self.config.common.append_proxy_type || self.config.node_pref.append_proxy_type,
        );
        let sort = request
            .nodes
            .sort
            .unwrap_or(self.config.node_pref.sort_flag);
        let external = self
            .load_external_config(
                request.external_config.as_deref(),
                &request.template_variables,
                authorized,
            )
            .await?;
        let enable_rule_generator = external
            .as_ref()
            .is_none_or(|external| external.enable_rule_generator);
        let loaded_rulesets = if external
            .as_ref()
            .is_some_and(|external| external.enable_rule_generator)
        {
            self.load_rulesets(
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

        let prepared = PreparedConversion {
            nodes: &nodes,
            groups,
            loaded_rulesets: &loaded_rulesets,
            external: external.as_ref(),
            overwrite_rules,
            enable_rule_generator,
            append_type,
            sort,
            authorized,
        };
        let content = match request.target {
            SubscriptionTarget::Clash => self.convert_clash(&request, &prepared).await?,
            SubscriptionTarget::SingBox => self.convert_singbox(&request, &prepared).await?,
        };

        Ok(SubscriptionOutput {
            content,
            content_type: request.target.content_type(),
            metadata,
        })
    }

    async fn load_subscription_input(
        &self,
        input: &SubscriptionInput,
        index: usize,
        ttl: Duration,
    ) -> Result<(Vec<Proxy>, FetchMetadata)> {
        match input {
            SubscriptionInput::Content(content) => parse_subscription(content, index as u32)
                .map(|nodes| (nodes, FetchMetadata::default())),
            SubscriptionInput::Source(source) if looks_like_proxy(source) => {
                parse_node(source, index as u32).map(|node| (vec![node], FetchMetadata::default()))
            }
            SubscriptionInput::Source(source) => {
                let fetched = self.fetcher.get_with_metadata(source, ttl, false).await?;
                let text = std::str::from_utf8(&fetched.body)
                    .map_err(|_| AppError::BadRequest("subscription is not UTF-8".into()))?;
                parse_subscription(text, index as u32).map(|nodes| (nodes, fetched.metadata))
            }
        }
    }

    fn sources_or_default(
        &self,
        sources: Vec<SubscriptionInput>,
    ) -> Result<Vec<SubscriptionInput>> {
        if !sources.is_empty() {
            return Ok(sources);
        }
        if self.config.common.default_url.is_empty() {
            return Err(AppError::BadRequest("no subscription URL provided".into()));
        }
        Ok(self
            .config
            .common
            .default_url
            .iter()
            .cloned()
            .map(SubscriptionInput::Source)
            .collect())
    }

    async fn convert_clash(
        &self,
        request: &SubscriptionRequest,
        prepared: &PreparedConversion<'_>,
    ) -> Result<String> {
        let optimize = request
            .clash
            .ruleset_optimize
            .unwrap_or(self.config.node_pref.clash_ruleset_optimize);
        let optimize_to_http = request
            .clash
            .ruleset_optimize_to_http
            .unwrap_or(self.config.node_pref.clash_ruleset_optimize_to_http);
        let geo_convert = request
            .clash
            .geo_convert_ruleset
            .unwrap_or(self.config.node_pref.clash_geo_convert_ruleset);
        let provider_base_url = if optimize_to_http {
            Some(request.clash.provider_base_url.clone().ok_or_else(|| {
                AppError::BadRequest(
                    "provider_base_url is required when Clash rulesets are optimized to HTTP"
                        .into(),
                )
            })?)
        } else {
            None
        };
        let ruleset_options = ClashRulesetOptions {
            proxies_style: self.config.node_pref.clash_proxies_style.clone(),
            proxy_groups_style: self.config.node_pref.clash_proxy_groups_style.clone(),
            optimize,
            optimize_to_http,
            geo_convert,
            provider_base_url,
            access_token: request.access_token.clone(),
            update_interval: self.config.managed_config.ruleset_update_interval,
            geo_transforms: self.config.node_pref.clash_rulesets.clone(),
        };
        let base_source = prepared
            .external
            .and_then(|external| external.clash_rule_base.as_deref())
            .unwrap_or(&self.config.common.clash_rule_base);
        reject_sensitive_base(
            prepared
                .external
                .and_then(|value| value.clash_rule_base.as_deref()),
            prepared.authorized,
            "Clash",
        )?;
        let base = self
            .rendered_base(base_source, &request.template_variables, false)
            .await?;
        match base.as_deref() {
            Some(base) => to_clash_full_with_options(
                prepared.nodes,
                Some(base),
                prepared.groups,
                prepared.loaded_rulesets,
                prepared.overwrite_rules,
                self.config.advance.max_allowed_rules,
                prepared.append_type,
                prepared.sort,
                &ruleset_options,
            ),
            None if prepared.external.is_some() => to_clash_full_with_options(
                prepared.nodes,
                None,
                prepared.groups,
                prepared.loaded_rulesets,
                prepared.overwrite_rules,
                self.config.advance.max_allowed_rules,
                prepared.append_type,
                prepared.sort,
                &ruleset_options,
            ),
            None => to_clash(prepared.nodes, prepared.append_type, prepared.sort),
        }
    }

    async fn convert_singbox(
        &self,
        request: &SubscriptionRequest,
        prepared: &PreparedConversion<'_>,
    ) -> Result<String> {
        let export_options = SingboxExportOptions {
            add_clash_modes: self.config.node_pref.singbox_add_clash_modes,
            generate_rules: prepared.enable_rule_generator,
        };
        let base_source = prepared
            .external
            .and_then(|external| external.singbox_rule_base.as_deref())
            .unwrap_or(&self.config.common.singbox_rule_base);
        reject_sensitive_base(
            prepared
                .external
                .and_then(|value| value.singbox_rule_base.as_deref()),
            prepared.authorized,
            "sing-box",
        )?;
        let base = self
            .rendered_base(base_source, &request.template_variables, true)
            .await?;
        match base.as_deref() {
            Some(base) => to_singbox_full_with_options(
                prepared.nodes,
                Some(base),
                prepared.groups,
                prepared.loaded_rulesets,
                prepared.overwrite_rules,
                self.config.advance.max_allowed_rules,
                &self.config.node_pref.singbox_rulesets,
                self.config.managed_config.ruleset_update_interval,
                prepared.append_type,
                prepared.sort,
                &export_options,
            ),
            None if prepared.external.is_some() => to_singbox_full_with_options(
                prepared.nodes,
                None,
                prepared.groups,
                prepared.loaded_rulesets,
                prepared.overwrite_rules,
                self.config.advance.max_allowed_rules,
                &self.config.node_pref.singbox_rulesets,
                self.config.managed_config.ruleset_update_interval,
                prepared.append_type,
                prepared.sort,
                &export_options,
            ),
            None => to_singbox_full_with_options(
                prepared.nodes,
                None,
                &[],
                &[],
                false,
                self.config.advance.max_allowed_rules,
                &self.config.node_pref.singbox_rulesets,
                self.config.managed_config.ruleset_update_interval,
                prepared.append_type,
                prepared.sort,
                &export_options,
            ),
        }
    }

    async fn rendered_base(
        &self,
        source: &str,
        variables: &HashMap<String, String>,
        singbox: bool,
    ) -> Result<Option<String>> {
        if source.is_empty() {
            return Ok(None);
        }
        let source = self.config.resolve_source(source);
        let bytes = self
            .fetcher
            .get(
                &source,
                Duration::from_secs(self.config.advance.cache_config),
                true,
            )
            .await?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| AppError::BadRequest("base template is not UTF-8".into()))?;
        template::render(text, variables, &self.config, singbox).map(Some)
    }

    async fn load_external_config(
        &self,
        requested: Option<&str>,
        variables: &HashMap<String, String>,
        authorized: bool,
    ) -> Result<Option<ExternalConfig>> {
        let source = requested.filter(|source| !source.is_empty()).or_else(|| {
            (!self.config.common.default_external_config.is_empty())
                .then_some(self.config.common.default_external_config.as_str())
        });
        let Some(source) = source else {
            return Ok(None);
        };
        if requested.is_some() && is_sensitive_source(source) && !authorized {
            return Err(AppError::Unauthorized(
                "token is required for a local external config".into(),
            ));
        }
        let source = self.config.resolve_source(source);
        let bytes = self
            .fetcher
            .get(
                &source,
                Duration::from_secs(self.config.advance.cache_config),
                true,
            )
            .await?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| AppError::BadRequest("external config is not UTF-8".into()))?;
        let rendered = template::render(text, variables, &self.config, false)?;
        external::parse(&rendered).map(Some)
    }

    pub(crate) async fn load_rulesets(
        &self,
        specs: &[external::RulesetSpec],
        authorized: bool,
    ) -> Result<Vec<LoadedRuleset>> {
        if specs.len() > self.config.advance.max_allowed_rulesets {
            return Err(AppError::Limit(format!(
                "ruleset count {} exceeds limit {}",
                specs.len(),
                self.config.advance.max_allowed_rulesets
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
        let concurrency = self
            .config
            .advance
            .fetch_concurrency
            .min(specs.len())
            .max(1);
        let ttl = Duration::from_secs(self.config.advance.cache_ruleset);
        let skip_failed = self.config.advance.skip_failed_links;
        let mut loaded: Vec<(usize, Option<LoadedRuleset>)> =
            stream::iter(specs.iter().cloned().enumerate())
                .map(|(index, spec)| {
                    let service = self.clone();
                    async move {
                        let result = async {
                            let content = if spec.inline {
                                spec.source.clone()
                            } else {
                                let bytes = service.fetcher.get(&spec.source, ttl, false).await?;
                                std::str::from_utf8(&bytes)
                                    .map_err(|_| {
                                        AppError::BadRequest("ruleset is not UTF-8".into())
                                    })?
                                    .to_owned()
                            };
                            Ok::<_, AppError>(LoadedRuleset {
                                group: spec.group,
                                source: if spec.inline {
                                    String::new()
                                } else {
                                    spec.source.clone()
                                },
                                content,
                                format: spec.format,
                            })
                        }
                        .await;
                        match result {
                            Ok(ruleset) => Ok((index, Some(ruleset))),
                            Err(error) if skip_failed => {
                                tracing::warn!(
                                    %error,
                                    source = %spec.source,
                                    "skipping failed ruleset"
                                );
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
}

fn apply_node_options(nodes: &mut [Proxy], options: &NodeConversionOptions, config: &AppConfig) {
    let udp = options.udp.or(config.node_pref.udp_flag);
    let tfo = options
        .tcp_fast_open
        .or(config.node_pref.tcp_fast_open_flag);
    let skip_cert_verify = options
        .skip_cert_verify
        .or(config.node_pref.skip_cert_verify_flag);
    for node in nodes {
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
}

fn request_is_authorized(config: &AppConfig, token: Option<&str>) -> bool {
    !config.common.api_mode || token.is_some_and(|token| token == config.common.api_access_token)
}

fn is_sensitive_source(source: &str) -> bool {
    source.starts_with("file://") || source.starts_with("env:") || !source.contains("://")
}

fn reject_sensitive_inputs(
    inputs: &[SubscriptionInput],
    authorized: bool,
    kind: &str,
) -> Result<()> {
    if !authorized
        && inputs.iter().any(|input| {
            matches!(input, SubscriptionInput::Source(source) if is_sensitive_source(source))
        })
    {
        return Err(AppError::Unauthorized(format!(
            "token is required for local {kind} sources"
        )));
    }
    Ok(())
}

fn enforce_source_limit(count: usize, config: &AppConfig) -> Result<()> {
    if count == 0 {
        return Err(AppError::BadRequest("no source provided".into()));
    }
    if count > config.advance.max_allowed_rulesets {
        return Err(AppError::Limit(format!(
            "source count {count} exceeds limit {}",
            config.advance.max_allowed_rulesets
        )));
    }
    Ok(())
}

fn reject_sensitive_base(
    external_base: Option<&str>,
    authorized: bool,
    target: &str,
) -> Result<()> {
    if external_base.is_some_and(is_sensitive_source) && !authorized {
        return Err(AppError::Unauthorized(format!(
            "token is required for a local {target} rule base"
        )));
    }
    Ok(())
}

// Kept separate so fetch metadata can be reused by the Axum adapter and library callers.
pub(crate) fn merge_fetch_metadata(loaded: &[(usize, Vec<Proxy>, FetchMetadata)]) -> FetchMetadata {
    let first = |select: fn(&FetchMetadata) -> &Option<String>| {
        loaded
            .iter()
            .filter_map(|(_, _, metadata)| select(metadata).as_deref())
            .find(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    };
    FetchMetadata {
        subscription_userinfo: first(|metadata| &metadata.subscription_userinfo),
        profile_web_page_url: first(|metadata| &metadata.profile_web_page_url),
        profile_update_interval: first(|metadata| &metadata.profile_update_interval),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    use super::*;

    #[tokio::test]
    async fn converts_inline_subscription_without_axum() {
        let mut config = AppConfig::default();
        config.common.clash_rule_base.clear();
        config.common.enable_insert = false;
        let service = SubscriptionService::new(Arc::new(config)).unwrap();
        let mut request = SubscriptionRequest::new(SubscriptionTarget::Clash);
        request.sources.push(SubscriptionInput::content(
            "trojan://secret@example.com:443?sni=edge.example.com#edge",
        ));

        let output = service.convert(request).await.unwrap();

        assert_eq!(output.content_type, "text/yaml; charset=utf-8");
        assert!(output.content.contains("name: edge"));
        assert!(output.content.contains("type: trojan"));
    }

    #[tokio::test]
    async fn fetches_subscription_external_config_and_remote_ruleset() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 4096];
                let length = stream.read(&mut buffer).unwrap();
                let request = String::from_utf8_lossy(&buffer[..length]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap();
                let body = match path {
                    "/subscription" => {
                        "trojan://secret@example.com:443?sni=edge.example.com#edge".to_owned()
                    }
                    "/external.ini" => format!(
                        "[custom]\nruleset=Proxy,http://{address}/rules.list\ncustom_proxy_group=Proxy`select`[]DIRECT`.*\n"
                    ),
                    "/rules.list" => "DOMAIN,example.org\n".to_owned(),
                    _ => panic!("unexpected test path: {path}"),
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            }
        });

        let mut config = AppConfig::default();
        config.common.clash_rule_base.clear();
        config.common.enable_insert = false;
        config.advance.fetch_concurrency = 1;
        config.advance.skip_failed_links = false;
        let service = SubscriptionService::new(Arc::new(config)).unwrap();
        let mut request = SubscriptionRequest::new(SubscriptionTarget::Clash);
        request.sources.push(SubscriptionInput::source(format!(
            "http://{address}/subscription"
        )));
        request.external_config = Some(format!("http://{address}/external.ini"));

        let output = service.convert(request).await.unwrap();
        server.join().unwrap();

        assert!(output.content.contains("example.org"));
        assert!(output.content.contains("name: Proxy"));
        assert!(output.content.contains("name: edge"));
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

    #[tokio::test]
    async fn preserves_ruleset_order_while_skipping_failures() {
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
        let service = SubscriptionService::new(Arc::new(AppConfig::default())).unwrap();
        let loaded = service.load_rulesets(&specs, true).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].group, "FINAL");

        let mut strict_config = AppConfig::default();
        strict_config.advance.skip_failed_links = false;
        let strict_service = SubscriptionService::new(Arc::new(strict_config)).unwrap();
        assert!(strict_service.load_rulesets(&specs, true).await.is_err());
    }

    #[test]
    fn parses_supported_target_aliases() {
        assert_eq!(
            "clashr".parse::<SubscriptionTarget>().unwrap(),
            SubscriptionTarget::Clash
        );
        assert_eq!(
            "sing-box".parse::<SubscriptionTarget>().unwrap(),
            SubscriptionTarget::SingBox
        );
        assert!("unknown".parse::<SubscriptionTarget>().is_err());
    }
}
