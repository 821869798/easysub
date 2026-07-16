use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use serde::Deserialize;

use crate::{
    error::{AppError, Result},
    private::PrivateSubscriptions,
};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub common: CommonConfig,
    pub node_pref: NodePreferences,
    pub managed_config: ManagedConfig,
    pub template: TemplateConfig,
    pub advance: AdvancedConfig,
    #[serde(skip)]
    pub base_dir: PathBuf,
    #[serde(skip)]
    pub private_subscriptions: Option<PrivateSubscriptions>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CommonConfig {
    pub api_mode: bool,
    pub api_access_token: String,
    pub default_url: Vec<String>,
    pub insert_url: Vec<String>,
    pub enable_insert: bool,
    pub prepend_insert_url: bool,
    pub append_proxy_type: bool,
    pub default_external_config: String,
    pub clash_rule_base: String,
    pub singbox_rule_base: String,
    pub proxy_config: String,
}

impl Default for CommonConfig {
    fn default() -> Self {
        Self {
            api_mode: false,
            api_access_token: String::new(),
            default_url: Vec::new(),
            insert_url: Vec::new(),
            enable_insert: true,
            prepend_insert_url: true,
            append_proxy_type: false,
            default_external_config: String::new(),
            clash_rule_base: "base/clash.liquid".into(),
            singbox_rule_base: "base/singbox.liquid".into(),
            proxy_config: "SYSTEM".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NodePreferences {
    pub sort_flag: bool,
    pub append_proxy_type: bool,
    pub filter_deprecated_nodes: bool,
    pub append_sub_userinfo: bool,
    pub udp_flag: Option<bool>,
    pub tcp_fast_open_flag: Option<bool>,
    #[serde(alias = "skip_cert_verify")]
    pub skip_cert_verify_flag: Option<bool>,
    pub clash_ruleset_optimize: bool,
    pub clash_ruleset_optimize_to_http: bool,
    pub singbox_add_clash_modes: bool,
    pub clash_rulesets: HashMap<String, RulesetTransform>,
    pub singbox_rulesets: HashMap<String, RulesetTransform>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RulesetTransform {
    pub name: String,
    #[serde(rename = "type")]
    pub behavior: String,
    pub url_format: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TemplateConfig {
    pub globals: Vec<TemplateGlobal>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TemplateGlobal {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ManagedConfig {
    pub ruleset_update_interval: u64,
}

impl Default for ManagedConfig {
    fn default() -> Self {
        Self {
            ruleset_update_interval: 432_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AdvancedConfig {
    pub default_port: u16,
    pub port_env: String,
    pub log_level: String,
    pub cache_subscription: u64,
    pub cache_config: u64,
    pub cache_ruleset: u64,
    pub max_allowed_rules: usize,
    pub max_allowed_rulesets: usize,
    #[serde(alias = "max_allowed_download_size")]
    pub max_download_bytes: usize,
    pub cache_capacity_bytes: u64,
    pub fetch_concurrency: usize,
    pub heavy_task_concurrency: usize,
    pub request_timeout_seconds: u64,
    pub skip_failed_links: bool,
    pub enable_file_share: bool,
    pub file_share_path: String,
    pub enable_private_sub: bool,
    pub private_sub_config: String,
}

impl Default for AdvancedConfig {
    fn default() -> Self {
        let cpus = std::thread::available_parallelism().map_or(1, usize::from);
        Self {
            default_port: 25_500,
            port_env: "PORT".into(),
            log_level: "info".into(),
            cache_subscription: 60,
            cache_config: 300,
            cache_ruleset: 21_600,
            max_allowed_rules: 1_000_000,
            max_allowed_rulesets: 64,
            max_download_bytes: 32 * 1024 * 1024,
            cache_capacity_bytes: 128 * 1024 * 1024,
            fetch_concurrency: cpus.saturating_mul(4).clamp(8, 64),
            heavy_task_concurrency: cpus.div_ceil(2).max(1),
            request_timeout_seconds: 30,
            skip_failed_links: true,
            enable_file_share: true,
            file_share_path: "./file_share".into(),
            enable_private_sub: false,
            private_sub_config: String::new(),
        }
    }
}

impl AppConfig {
    pub async fn load(path: impl AsRef<Path>) -> Result<Arc<Self>> {
        let path = path.as_ref();
        let source = tokio::fs::read_to_string(path).await.map_err(|error| {
            AppError::Config(format!("failed to read {}: {error}", path.display()))
        })?;
        let mut config: Self = toml::from_str(&source)
            .map_err(|error| AppError::Config(format!("invalid TOML: {error}")))?;
        config.base_dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        config.normalize();
        if config.advance.enable_private_sub && !config.advance.private_sub_config.is_empty() {
            let source = config.resolve_source(&config.advance.private_sub_config);
            config.private_subscriptions = Some(PrivateSubscriptions::load(&source).await?);
        }
        Ok(Arc::new(config))
    }

    fn normalize(&mut self) {
        let defaults = AdvancedConfig::default();
        if self.advance.max_download_bytes == 0 {
            self.advance.max_download_bytes = defaults.max_download_bytes;
        }
        if self.advance.max_allowed_rulesets == 0 {
            self.advance.max_allowed_rulesets = defaults.max_allowed_rulesets;
        }
        if self.advance.fetch_concurrency == 0 {
            self.advance.fetch_concurrency = defaults.fetch_concurrency;
        }
        if self.advance.heavy_task_concurrency == 0 {
            self.advance.heavy_task_concurrency = defaults.heavy_task_concurrency;
        }
    }

    pub fn listen_port(&self) -> u16 {
        env::var(&self.advance.port_env)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(self.advance.default_port)
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.advance.request_timeout_seconds)
    }

    pub fn resolve_source(&self, source: &str) -> String {
        if source.starts_with("http://")
            || source.starts_with("https://")
            || source.starts_with("file://")
            || source.starts_with("env:")
            || Path::new(source).is_absolute()
        {
            source.to_owned()
        } else {
            self.base_dir.join(source).to_string_lossy().into_owned()
        }
    }
}
