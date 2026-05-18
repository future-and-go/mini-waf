//! FR-042 — reputation feeds status + manual refresh.
//!
//! `GET  /api/reputation/status`  → snapshot every registered intel feed.
//! `POST /api/reputation/refresh` → trigger one refresh pass across all feeds.
//!
//! Both routes ride the existing `require_auth` middleware (admin role is
//! not enforced here because the codebase has no role-based gate — every
//! authenticated user is implicitly an operator, matching
//! `reload_rule_registry`).

use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode};
use serde_json::{Value, json};
use waf_engine::relay::RefreshOutcome;
use waf_engine::relay::intel::status::RefreshError;

use crate::error::ApiResult;
use crate::state::AppState;

/// `GET /api/reputation/status`
pub async fn reputation_status(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let feeds = state.feed_status_registry.snapshot();
    let notice = if feeds.is_empty() {
        Some("no intel providers registered — wire feeds via main.rs bootstrap")
    } else {
        None
    };

    Ok(Json(json!({
        "success": true,
        "data": {
            "feeds": feeds,
            "notice": notice,
        }
    })))
}

/// `POST /api/reputation/refresh`
///
/// Status code semantics:
/// - `200 OK` — every feed refreshed cleanly (`Updated` / `NotModified` / provider-level
///   `Failed`). Per-feed details in body.
/// - `207 Multi-Status` — mixed outcome containing at least one infrastructure-level
///   failure across multiple distinct failure classes. Each feed's status sits in
///   `data.refreshed[].status` so the FE can render per-row UX without parsing
///   message strings.
/// - `409 Conflict` — every infrastructure-level failure was `in_flight`. A retry
///   after the in-flight refresh completes is the expected operator action.
/// - `500 Internal Server Error` — every infrastructure-level failure was
///   `not_registered`. This indicates registry drift (config reload mid-call)
///   and warrants operator investigation.
/// - `200 OK` with empty `refreshed` + `notice` — registry has no feeds.
///   Uses 200 rather than 204 because the response body carries useful
///   diagnostic JSON (`notice`) and RFC 9110 §15.3.5 forbids bodies on 204.
pub async fn reputation_refresh(
    State(state): State<Arc<AppState>>,
) -> Result<(StatusCode, Json<Value>), crate::error::ApiError> {
    let names = state.feed_status_registry.names();
    if names.is_empty() {
        return Ok((
            StatusCode::OK,
            Json(json!({
                "success": true,
                "data": { "refreshed": [], "notice": "no providers registered" }
            })),
        ));
    }

    let results = state.feed_status_registry.refresh_all().await;

    let mut has_conflict = false;
    let mut has_not_registered = false;
    let summary: Vec<Value> = results
        .into_iter()
        .map(|(name, outcome)| {
            let (status, message) = match outcome {
                Ok(RefreshOutcome::Updated) => ("updated", None),
                Ok(RefreshOutcome::NotModified) => ("not_modified", None),
                Ok(RefreshOutcome::Failed(err)) => ("failed", Some(err.to_string())),
                Err(RefreshError::InFlight(_)) => {
                    has_conflict = true;
                    ("in_flight", Some("refresh already running".to_string()))
                }
                Err(RefreshError::NotRegistered(_)) => {
                    has_not_registered = true;
                    ("not_registered", Some("feed disappeared mid-call".to_string()))
                }
                Err(RefreshError::Provider(err)) => ("provider_error", Some(err.to_string())),
            };
            json!({ "name": name, "status": status, "error": message })
        })
        .collect();

    // When BOTH conflict and not-registered are present we have a genuine
    // multi-outcome scenario — neither 409 nor 500 alone captures it. 207
    // Multi-Status is the correct HTTP semantic (the FE inspects the body
    // to render per-feed UX). Single-class failures keep their narrow code
    // so existing clients don't see behaviour drift.
    let http_status = match (has_not_registered, has_conflict) {
        (true, true) => StatusCode::MULTI_STATUS,
        (true, false) => StatusCode::INTERNAL_SERVER_ERROR,
        (false, true) => StatusCode::CONFLICT,
        (false, false) => StatusCode::OK,
    };

    Ok((
        http_status,
        Json(json!({
            "success": !has_conflict && !has_not_registered,
            "data": { "refreshed": summary }
        })),
    ))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::expect_used)]
mod tests {
    use super::*;
    use anyhow::Result as AnyhowResult;
    use async_trait::async_trait;
    use waf_engine::relay::IntelProvider;
    use waf_engine::relay::intel::status::FeedStatusRegistry;

    struct DummyOk;

    #[async_trait]
    impl IntelProvider for DummyOk {
        fn name(&self) -> &'static str {
            "dummy_ok"
        }
        async fn refresh(&self) -> AnyhowResult<RefreshOutcome> {
            Ok(RefreshOutcome::Updated)
        }
    }

    #[tokio::test]
    async fn registry_snapshot_round_trips_through_serde() {
        let reg = FeedStatusRegistry::new();
        let provider: Arc<dyn IntelProvider> = Arc::new(DummyOk);
        reg.register(provider);
        let snap = reg.snapshot();
        let json = serde_json::to_value(&snap).expect("serialize");
        assert_eq!(json[0]["name"], "dummy_ok");
        assert_eq!(json[0]["health"], "unknown");
    }
}
