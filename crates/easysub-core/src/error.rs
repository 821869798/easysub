//! Errors returned by the reusable conversion core.

use thiserror::Error;

pub type Result<T, E = AppError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("unsupported input: {0}")]
    Unsupported(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("input exceeds limit: {0}")]
    Limit(String),
    #[error("conversion error: {0}")]
    Conversion(String),
    #[error("internal error: {0}")]
    Internal(String),
}
