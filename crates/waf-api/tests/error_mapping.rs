// Unit tests for ApiError → HTTP status / response shape mapping.
//
// `ApiError` is a public-from-crate type but only used inside `waf-api`.
// We test it through `IntoResponse` directly to avoid depending on a real
// handler that returns the variant.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::to_bytes;
use axum::response::IntoResponse;
use waf_api::error::ApiError;

async fn body_to_json(resp: axum::response::Response) -> serde_json::Value {
    let (parts, body) = resp.into_parts();
    let bytes = to_bytes(body, 64 * 1024).await.expect("body");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(parts.status.as_u16(), parts.status.as_u16()); // no-op, keep parts alive
    v
}

#[tokio::test]
async fn not_found_maps_404() {
    let resp = ApiError::NotFound("missing".into()).into_response();
    assert_eq!(resp.status().as_u16(), 404);
    let v = body_to_json(resp).await;
    assert_eq!(v["error"], "missing");
}

#[tokio::test]
async fn bad_request_maps_400() {
    let resp = ApiError::BadRequest("invalid input".into()).into_response();
    assert_eq!(resp.status().as_u16(), 400);
    let v = body_to_json(resp).await;
    assert_eq!(v["error"], "invalid input");
}

#[tokio::test]
async fn unauthorized_maps_401() {
    let resp = ApiError::Unauthorized("nope".into()).into_response();
    assert_eq!(resp.status().as_u16(), 401);
    let v = body_to_json(resp).await;
    assert_eq!(v["error"], "nope");
}

#[tokio::test]
async fn too_many_requests_maps_429() {
    let resp = ApiError::TooManyRequests("slow down".into()).into_response();
    assert_eq!(resp.status().as_u16(), 429);
    let v = body_to_json(resp).await;
    assert_eq!(v["error"], "slow down");
}

#[tokio::test]
async fn internal_anyhow_maps_500() {
    let err: ApiError = anyhow::anyhow!("kaboom").into();
    let resp = err.into_response();
    assert_eq!(resp.status().as_u16(), 500);
    let v = body_to_json(resp).await;
    assert_eq!(v["error"], "kaboom");
}
