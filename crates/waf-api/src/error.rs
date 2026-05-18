use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("Storage error: {0}")]
    Storage(#[from] waf_storage::StorageError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            Self::TooManyRequests(msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone()),
            Self::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            Self::Storage(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };

        let body = Json(json!({ "error": message }));
        (status, body).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::StatusCode;

    async fn read_body_message(resp: Response) -> (StatusCode, String) {
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let msg = v
            .get("error")
            .and_then(serde_json::Value::as_str)
            .expect("error str")
            .to_string();
        (status, msg)
    }

    #[tokio::test]
    async fn not_found_maps_to_404() {
        let resp = ApiError::NotFound("host".into()).into_response();
        let (status, msg) = read_body_message(resp).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(msg, "host");
    }

    #[tokio::test]
    async fn bad_request_maps_to_400() {
        let resp = ApiError::BadRequest("missing field".into()).into_response();
        let (status, msg) = read_body_message(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(msg, "missing field");
    }

    #[tokio::test]
    async fn unauthorized_maps_to_401() {
        let resp = ApiError::Unauthorized("bad token".into()).into_response();
        let (status, msg) = read_body_message(resp).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(msg, "bad token");
    }

    #[tokio::test]
    async fn too_many_requests_maps_to_429() {
        let resp = ApiError::TooManyRequests("slow down".into()).into_response();
        let (status, msg) = read_body_message(resp).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(msg, "slow down");
    }

    #[tokio::test]
    async fn internal_anyhow_maps_to_500() {
        let resp = ApiError::Internal(anyhow::anyhow!("boom")).into_response();
        let (status, msg) = read_body_message(resp).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(msg, "boom");
    }

    #[test]
    fn from_anyhow_yields_internal_variant() {
        let err: ApiError = anyhow::anyhow!("disk full").into();
        assert!(matches!(err, ApiError::Internal(_)));
        assert!(err.to_string().contains("disk full"));
    }

    #[test]
    fn display_formats_include_variant_prefix() {
        assert!(ApiError::NotFound("x".into()).to_string().starts_with("Not found"));
        assert!(ApiError::BadRequest("x".into()).to_string().starts_with("Bad request"));
        assert!(
            ApiError::Unauthorized("x".into())
                .to_string()
                .starts_with("Unauthorized")
        );
        assert!(
            ApiError::TooManyRequests("x".into())
                .to_string()
                .starts_with("Too many requests")
        );
    }
}
