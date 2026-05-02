//! Cache management API handlers.

use std::sync::Arc;
use std::time::Instant;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use serde_json::json;

use crate::state::AppState;

/// Max length for a tag or `route_id` received over the admin API. Keeps
/// pathological inputs out of the index lookup path and out of audit logs.
const MAX_TAG_LEN: usize = 64;

/// Validate a tag or `route_id` — returns the trimmed value or an error string.
///
/// Defense-in-depth: rejects log-injection (CR/LF), shell-special chars, and
/// anything that could break a JSON audit-log line. Allowed alphabet matches
/// what `rules/cache.yaml` already accepts in practice (alnum + `_-:`).
fn validate_tag(raw: &str) -> Result<&str, &'static str> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("must not be empty");
    }
    if t.len() > MAX_TAG_LEN {
        return Err("must be 64 chars or fewer");
    }
    if !t
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':'))
    {
        return Err("only ASCII alnum and `_`, `-`, `:` allowed");
    }
    Ok(t)
}

#[derive(Deserialize)]
pub struct PurgeTagBody {
    pub tag: String,
}

#[derive(Deserialize)]
pub struct PurgeRouteBody {
    pub route_id: String,
}

/// GET /api/cache/stats — cache hit/miss/eviction counters
pub async fn cache_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let snap = state.cache.stats();
    let count = state.cache.entry_count();
    (
        StatusCode::OK,
        Json(json!({
            "hits": snap.hits,
            "misses": snap.misses,
            "evictions": snap.evictions,
            "stores": snap.stores,
            "entry_count": count,
            // FR-009 Phase 3 audit signals.
            "bypassed_critical": snap.bypassed_critical,
            "bypassed_authenticated": snap.bypassed_authenticated,
            "bypassed_explicit_deny": snap.bypassed_explicit_deny,
            // FR-009 Phase 4 purge counters + tag-index gauge.
            "purges_tag": snap.purges_tag,
            "purges_route": snap.purges_route,
            "tag_index_size": state.cache.tag_index_size(),
        })),
    )
        .into_response()
}

/// POST /api/cache/purge/tag — purge every entry tagged with `tag`.
///
/// Body: `{ "tag": "catalog" }`. Response shape matches the rest of the cache
/// API: `{ ok, purged, duration_ms }`.
pub async fn cache_purge_tag(State(state): State<Arc<AppState>>, Json(body): Json<PurgeTagBody>) -> impl IntoResponse {
    let tag = match validate_tag(&body.tag) {
        Ok(t) => t.to_string(),
        Err(reason) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "error": format!("invalid tag: {reason}") })),
            )
                .into_response();
        }
    };
    let started = Instant::now();
    let purged = state.cache.purge_by_tag(&tag).await;
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "purged": purged,
            "duration_ms": started.elapsed().as_millis(),
        })),
    )
        .into_response()
}

/// POST /api/cache/purge/route — purge every entry cached by the rule with
/// this `route_id`. Backed by the same tag index (rule id is auto-tagged).
pub async fn cache_purge_route(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PurgeRouteBody>,
) -> impl IntoResponse {
    let route_id = match validate_tag(&body.route_id) {
        Ok(t) => t.to_string(),
        Err(reason) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "ok": false, "error": format!("invalid route_id: {reason}") })),
            )
                .into_response();
        }
    };
    let started = Instant::now();
    let purged = state.cache.purge_by_route_id(&route_id).await;
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "purged": purged,
            "duration_ms": started.elapsed().as_millis(),
        })),
    )
        .into_response()
}

/// DELETE /api/cache — flush the entire cache
pub async fn cache_flush(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.cache.flush().await;
    (StatusCode::OK, Json(json!({ "flushed": true }))).into_response()
}

/// DELETE /api/cache/host/:host — flush all entries for a given host
pub async fn cache_flush_host(State(state): State<Arc<AppState>>, Path(host): Path<String>) -> impl IntoResponse {
    state.cache.purge_host(&host).await;
    (StatusCode::OK, Json(json!({ "flushed_host": host }))).into_response()
}

/// DELETE /api/cache/key — flush a specific cache key
///
/// Query param: `?key=<encoded-key>`
#[allow(clippy::implicit_hasher)]
pub async fn cache_flush_key(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let key = match params.get("key") {
        Some(k) => k.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "key query parameter required" })),
            )
                .into_response();
        }
    };
    state.cache.purge_key(&key).await;
    (StatusCode::OK, Json(json!({ "flushed_key": key }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_tag_accepts_empty_after_trim_with_whitespace_only() {
        assert!(matches!(validate_tag("   "), Err("must not be empty")));
    }

    #[test]
    fn validate_tag_rejects_empty_string() {
        assert!(matches!(validate_tag(""), Err("must not be empty")));
    }

    #[test]
    fn validate_tag_accepts_basic_alphanumeric() {
        assert_eq!(validate_tag("catalog"), Ok("catalog"));
        assert_eq!(validate_tag("Cache123"), Ok("Cache123"));
    }

    #[test]
    fn validate_tag_accepts_underscore() {
        assert_eq!(validate_tag("catalog_v2"), Ok("catalog_v2"));
        assert_eq!(validate_tag("_private"), Ok("_private"));
    }

    #[test]
    fn validate_tag_accepts_hyphen() {
        assert_eq!(validate_tag("catalog-items"), Ok("catalog-items"));
        assert_eq!(validate_tag("api-routes-v1"), Ok("api-routes-v1"));
    }

    #[test]
    fn validate_tag_accepts_colon() {
        assert_eq!(validate_tag("app:cache:v1"), Ok("app:cache:v1"));
        assert_eq!(validate_tag("rule:123"), Ok("rule:123"));
    }

    #[test]
    fn validate_tag_accepts_mixed_valid_chars() {
        assert_eq!(validate_tag("api-v1:catalog_prod"), Ok("api-v1:catalog_prod"));
        assert_eq!(validate_tag("ABC-123_xyz:0"), Ok("ABC-123_xyz:0"));
    }

    #[test]
    fn validate_tag_trims_whitespace() {
        assert_eq!(validate_tag("  catalog  "), Ok("catalog"));
        assert_eq!(validate_tag("\tcatalog\n"), Ok("catalog"));
    }

    #[test]
    fn validate_tag_rejects_at_64_char_boundary() {
        let valid_64 = "a".repeat(64);
        assert_eq!(validate_tag(&valid_64), Ok(valid_64.as_str()));

        let invalid_65 = "a".repeat(65);
        assert!(matches!(validate_tag(&invalid_65), Err("must be 64 chars or fewer")));
    }

    #[test]
    fn validate_tag_rejects_spaces() {
        assert!(matches!(
            validate_tag("catalog items"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }

    #[test]
    fn validate_tag_rejects_newline() {
        assert!(matches!(
            validate_tag("catalog\nv2"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }

    #[test]
    fn validate_tag_rejects_carriage_return() {
        assert!(matches!(
            validate_tag("catalog\rv2"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }

    #[test]
    fn validate_tag_rejects_semicolon() {
        assert!(matches!(
            validate_tag("catalog;drop"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }

    #[test]
    fn validate_tag_rejects_angle_brackets() {
        assert!(matches!(
            validate_tag("catalog<tag>"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
        assert!(matches!(
            validate_tag("<catalog>"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }

    #[test]
    fn validate_tag_rejects_dollar_sign() {
        assert!(matches!(
            validate_tag("catalog$var"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }

    #[test]
    fn validate_tag_rejects_pipe() {
        assert!(matches!(
            validate_tag("catalog|grep"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }

    #[test]
    fn validate_tag_rejects_backtick() {
        assert!(matches!(
            validate_tag("catalog`cmd`"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }

    #[test]
    fn validate_tag_rejects_quotes() {
        assert!(matches!(
            validate_tag("catalog\"quote"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
        assert!(matches!(
            validate_tag("catalog'quote"),
            Err("only ASCII alnum and `_`, `-`, `:` allowed")
        ));
    }
}
