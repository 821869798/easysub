use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

pub type Result<T, E = AppError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("invalid request: {0}")]
    BadRequest(String),
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

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::BadRequest(_) | Self::Unsupported(_) => StatusCode::BAD_REQUEST,
            Self::Limit(_) => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
            Self::Config(_) | Self::Conversion(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (status, Json(json!({ "error": self.to_string() }))).into_response()
    }
}
