use std::{
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use moka::future::Cache;

use crate::{
    config::AppConfig,
    error::{AppError, Result},
};

#[derive(Clone)]
pub struct Fetcher {
    client: reqwest::Client,
    cache: Cache<String, Arc<CachedValue>>,
    max_bytes: usize,
    file_share_root: PathBuf,
    enable_file_share: bool,
}

struct CachedValue {
    body: Bytes,
    expires_at: Instant,
}

impl Fetcher {
    pub fn new(config: &AppConfig) -> Result<Self> {
        let max_bytes = config.advance.max_download_bytes;
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(config.request_timeout())
            .user_agent(concat!("easysub-rs/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| {
                AppError::Config(format!("HTTP client initialization failed: {error}"))
            })?;
        let cache = Cache::builder()
            .max_capacity(config.advance.cache_capacity_bytes)
            .weigher(|_key: &String, value: &Arc<CachedValue>| {
                value.body.len().min(u32::MAX as usize) as u32
            })
            .build();
        Ok(Self {
            client,
            cache,
            max_bytes,
            file_share_root: PathBuf::from(config.resolve_source(&config.advance.file_share_path)),
            enable_file_share: config.advance.enable_file_share,
        })
    }

    pub async fn get(&self, source: &str, ttl: Duration, allow_local: bool) -> Result<Bytes> {
        let source = resolve_env(source);
        if source.starts_with("http://") || source.starts_with("https://") {
            return self.get_http(&source, ttl).await;
        }
        if source.starts_with("file://") {
            if !self.enable_file_share {
                return Err(AppError::BadRequest("file sharing is disabled".into()));
            }
            let relative = source.trim_start_matches("file://").trim_start_matches('/');
            let path = secure_join(&self.file_share_root, relative)?;
            return read_limited(&path, self.max_bytes).await;
        }
        if allow_local {
            return read_limited(Path::new(&source), self.max_bytes).await;
        }
        Err(AppError::BadRequest(format!(
            "unsupported source: {source}"
        )))
    }

    async fn get_http(&self, url: &str, ttl: Duration) -> Result<Bytes> {
        if ttl == Duration::ZERO {
            return self.download(url).await;
        }
        if ttl > Duration::ZERO {
            if let Some(value) = self.cache.get(url).await {
                if value.expires_at > Instant::now() {
                    return Ok(value.body.clone());
                }
                self.cache.invalidate(url).await;
            }
        }
        let key = url.to_owned();
        let download_url = key.clone();
        let fetcher = self.clone();
        let value = self
            .cache
            .try_get_with(key, async move {
                let body = fetcher.download(&download_url).await?;
                Result::<Arc<CachedValue>>::Ok(Arc::new(CachedValue {
                    body,
                    expires_at: Instant::now() + ttl,
                }))
            })
            .await
            .map_err(|error| AppError::Upstream(error.to_string()))?;
        Ok(value.body.clone())
    }

    async fn download(&self, url: &str) -> Result<Bytes> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| AppError::Upstream(error.to_string()))?
            .error_for_status()
            .map_err(|error| AppError::Upstream(error.to_string()))?;
        if response
            .content_length()
            .is_some_and(|length| length > self.max_bytes as u64)
        {
            return Err(AppError::Limit(format!(
                "upstream response is larger than {} bytes",
                self.max_bytes
            )));
        }
        let mut body = BytesMut::with_capacity(
            response
                .content_length()
                .unwrap_or(16 * 1024)
                .min(self.max_bytes as u64) as usize,
        );
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| AppError::Upstream(error.to_string()))?;
            if body.len().saturating_add(chunk.len()) > self.max_bytes {
                return Err(AppError::Limit(format!(
                    "upstream response exceeded {} bytes",
                    self.max_bytes
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body.freeze())
    }
}

fn resolve_env(source: &str) -> String {
    source
        .strip_prefix("env:")
        .map(|name| name.trim_start_matches('/'))
        .and_then(|name| std::env::var(name).ok())
        .unwrap_or_else(|| source.to_owned())
}

fn secure_join(root: &Path, relative: &str) -> Result<PathBuf> {
    let decoded = percent_encoding::percent_decode_str(relative).decode_utf8_lossy();
    let relative = Path::new(decoded.as_ref());
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AppError::BadRequest("invalid shared-file path".into()));
    }
    Ok(root.join(relative))
}

async fn read_limited(path: &Path, limit: usize) -> Result<Bytes> {
    let metadata = tokio::fs::metadata(path).await.map_err(|error| {
        AppError::BadRequest(format!("cannot read {}: {error}", path.display()))
    })?;
    if metadata.len() > limit as u64 {
        return Err(AppError::Limit(format!(
            "{} is larger than {limit} bytes",
            path.display()
        )));
    }
    tokio::fs::read(path)
        .await
        .map(Bytes::from)
        .map_err(|error| AppError::BadRequest(format!("cannot read {}: {error}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_paths_cannot_escape_root() {
        assert!(secure_join(Path::new("files"), "../secret").is_err());
        assert!(secure_join(Path::new("files"), "ok/list.txt").is_ok());
    }
}
