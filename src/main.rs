use std::{env, path::PathBuf};

use easysub_rs::{
    api::{AppState, router},
    config::AppConfig,
};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .or_else(|| env::var_os("EASYSUB_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| {
            let preferred = PathBuf::from("workdir/pref.toml");
            if preferred.exists() {
                preferred
            } else {
                PathBuf::from("workdir/pref.example.toml")
            }
        });
    let config = AppConfig::load(&config_path).await?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&config.advance.log_level)),
        )
        .compact()
        .init();
    let port = config.listen_port();
    let app = router(AppState::new(config)?);
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    info!(port, config = %config_path.display(), "easysub-rs listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to install shutdown signal");
    }
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            tracing::error!(%error, "failed to install SIGTERM handler");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::error!(%error, "failed to install Ctrl-C handler");
            }
        }
        _ = terminate.recv() => {}
    }
}
