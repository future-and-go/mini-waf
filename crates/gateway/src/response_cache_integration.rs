//! FR-009: serve cached responses from [`crate::cache::ResponseCache`] and
//! asynchronously store upstream bodies after the proxy path completes.

use std::sync::Arc;

use pingora_proxy::Session;

use crate::cache::{CachedResponse, ResponseCache};
use crate::context::{GatewayCtx, RESPONSE_CACHE_BODY_LIMIT, ResponseCachePending};
use crate::waf_observability_headers::{CacheStatus, inject_for_passthrough_with_cache};

/// Write a cache hit to the downstream session and finish the exchange.
///
/// Forces `cache = CacheStatus::Hit` on the injected headers so served-from-
/// cache responses always advertise the contract surface. Other fields come
/// from `ctx.waf_decision_meta` so a previously-stored `log_only` block
/// continues to advertise its intended action (red-team F9).
pub async fn write_cached_entry(
    session: &mut Session,
    entry: &Arc<CachedResponse>,
    ctx: &GatewayCtx,
) -> pingora_core::Result<()> {
    let status = http::StatusCode::from_u16(entry.status).unwrap_or(http::StatusCode::OK);
    let mut resp = pingora_http::ResponseHeader::build(status, None)?;
    for (k, v) in &entry.headers {
        let _ = resp.insert_header(k.clone(), v.clone());
    }
    // Inject AFTER the header replay loop so per-request observability values
    // override any (stale) x-waf-* baked into the cached entry.
    inject_for_passthrough_with_cache(&mut resp, ctx, CacheStatus::Hit)?;
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(bytes::Bytes::clone(&entry.body)), true)
        .await?;
    Ok(())
}

fn collect_response_headers(resp: &pingora_http::ResponseHeader) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in &resp.headers {
        let name_s = name.as_str();
        let Ok(val_s) = value.to_str() else {
            continue;
        };
        out.push((name_s.to_string(), val_s.to_string()));
    }
    out
}

/// `Content-Encoding` is cacheable when absent, empty, or `identity` (no gzip/br/etc.).
///
/// Uses the **current** response headers (after `response_chain` runs when host context exists).
fn response_content_encoding_allows_cache(resp: &pingora_http::ResponseHeader) -> bool {
    resp.headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| {
            let v = v.trim();
            v.is_empty() || v.eq_ignore_ascii_case("identity")
        })
}

/// Returns `false` when the upstream response must not be cached.
pub fn begin_upstream_cache_capture(
    pending: &mut ResponseCachePending,
    upstream_response: &pingora_http::ResponseHeader,
    body_mask_enabled: bool,
) -> bool {
    if body_mask_enabled || !response_content_encoding_allows_cache(upstream_response) {
        return false;
    }
    let status = upstream_response.status.as_u16();
    if !(200..300).contains(&status) {
        return false;
    }
    if upstream_response.headers.contains_key("vary") {
        tracing::debug!(
            cache_key = %pending.key,
            "response cache: skipping capture due to Vary header"
        );
        return false;
    }
    pending.status = status;
    pending.headers = collect_response_headers(upstream_response);
    // Belt-and-suspenders against cross-request leak (red-team F3/F6): even
    // though the §5 ordering invariant injects x-waf-* AFTER capture, drop
    // any that snuck in here so a future refactor cannot turn the cache into
    // a stale-identifier replay channel. Matches by lower-cased prefix
    // `x-waf-` (the dash terminator keeps `x-wafer` etc. unaffected).
    pending
        .headers
        .retain(|(name, _)| !name.to_ascii_lowercase().starts_with("x-waf-"));
    pending.cache_control = upstream_response
        .headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);
    pending.capture_started = true;
    true
}

/// Append body bytes; on end-of-stream spawn async `put` into [`ResponseCache`].
pub fn cache_store_on_body_chunk(
    cache: &Arc<ResponseCache>,
    pending: &mut Option<ResponseCachePending>,
    body: &mut Option<bytes::Bytes>,
    end_of_stream: bool,
) {
    let Some(p) = pending.as_mut() else {
        return;
    };
    if !p.capture_started {
        return;
    }
    if let Some(chunk) = body {
        let room = RESPONSE_CACHE_BODY_LIMIT.saturating_sub(p.body.len());
        if room > 0 {
            let take = chunk.len().min(room);
            if let Some(s) = chunk.get(..take) {
                p.body.extend_from_slice(s);
            }
        }
    }
    if end_of_stream {
        let Some(done) = pending.take() else {
            return;
        };
        spawn_cache_store_task(Arc::clone(cache), done);
    }
}

fn spawn_cache_store_task(cache: Arc<ResponseCache>, pending: ResponseCachePending) {
    let body = pending.body.freeze();
    let key = pending.key;
    let host = pending.host;
    let path = pending.path;
    let status = pending.status;
    let headers = pending.headers;
    let cc = pending.cache_control;
    let tier = pending.tier;
    let policy = pending.cache_policy;
    let auth = pending.has_authorization;
    let cookie = pending.has_cookie;
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let _stored = cache
                .put(
                    key,
                    &host,
                    &path,
                    status,
                    headers,
                    body,
                    cc.as_deref(),
                    tier,
                    &policy,
                    auth,
                    cookie,
                )
                .await;
        });
    } else {
        tracing::warn!("response cache store skipped: no tokio runtime handle");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use waf_common::tier::{CachePolicy, Tier};

    fn build_resp(status: u16, headers: &[(&str, &str)]) -> pingora_http::ResponseHeader {
        let mut resp = pingora_http::ResponseHeader::build(status, None).expect("build");
        for (k, v) in headers {
            resp.insert_header((*k).to_string(), *v).expect("insert");
        }
        resp
    }

    fn pending(key: &str) -> ResponseCachePending {
        ResponseCachePending {
            key: key.to_string(),
            host: "example.com".into(),
            path: "/p".into(),
            tier: Tier::Medium,
            cache_policy: CachePolicy::Aggressive { ttl_seconds: 300 },
            has_authorization: false,
            has_cookie: false,
            status: 0,
            headers: Vec::new(),
            cache_control: None,
            body: BytesMut::new(),
            capture_started: false,
        }
    }

    // ── collect_response_headers ─────────────────────────────────────────────

    #[test]
    fn collect_response_headers_extracts_ascii_value() {
        let resp = build_resp(200, &[("X-One", "v1"), ("X-Two", "v2")]);
        let pairs = collect_response_headers(&resp);
        // Names are stored canonical lower-case by pingora_http.
        assert!(pairs.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-one") && v == "v1"));
        assert!(pairs.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-two") && v == "v2"));
    }

    #[test]
    fn collect_response_headers_skips_non_utf8_value() {
        let mut resp = pingora_http::ResponseHeader::build(200, None).expect("build");
        // Insert a header with a non-UTF8 byte sequence directly via http types.
        let name = http::HeaderName::from_static("x-bin");
        let val = http::HeaderValue::from_bytes(b"\xff\xfe").expect("bytes");
        resp.headers.insert(name, val);
        // Plus one good header so we know the loop didn't abort early.
        resp.insert_header("x-good", "ok").expect("insert");
        let pairs = collect_response_headers(&resp);
        // Bad header dropped; good header retained.
        assert!(pairs.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-good")));
        assert!(!pairs.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-bin")));
    }

    // ── response_content_encoding_allows_cache ────────────────────────────────

    #[test]
    fn ce_absent_is_cacheable() {
        let resp = build_resp(200, &[]);
        assert!(response_content_encoding_allows_cache(&resp));
    }

    #[test]
    fn ce_empty_is_cacheable() {
        let resp = build_resp(200, &[("content-encoding", "")]);
        assert!(response_content_encoding_allows_cache(&resp));
    }

    #[test]
    fn ce_identity_is_cacheable_case_insensitive() {
        for v in ["identity", "Identity", "IDENTITY", "  identity  "] {
            let resp = build_resp(200, &[("content-encoding", v)]);
            assert!(response_content_encoding_allows_cache(&resp), "ce={v}");
        }
    }

    #[test]
    fn ce_gzip_blocks_cache() {
        let resp = build_resp(200, &[("content-encoding", "gzip")]);
        assert!(!response_content_encoding_allows_cache(&resp));
    }

    #[test]
    fn ce_brotli_blocks_cache() {
        let resp = build_resp(200, &[("content-encoding", "br")]);
        assert!(!response_content_encoding_allows_cache(&resp));
    }

    // ── begin_upstream_cache_capture ──────────────────────────────────────────

    #[test]
    fn capture_blocked_when_body_mask_enabled() {
        let mut p = pending("k1");
        let resp = build_resp(200, &[]);
        let ok = begin_upstream_cache_capture(&mut p, &resp, true);
        assert!(!ok);
        assert!(!p.capture_started);
    }

    #[test]
    fn capture_blocked_when_content_encoding_disallows() {
        let mut p = pending("k1");
        let resp = build_resp(200, &[("content-encoding", "gzip")]);
        assert!(!begin_upstream_cache_capture(&mut p, &resp, false));
        assert!(!p.capture_started);
    }

    #[test]
    fn capture_blocked_for_non_2xx() {
        let mut p = pending("k1");
        for status in [199_u16, 300, 404, 500] {
            let resp = build_resp(status, &[]);
            assert!(
                !begin_upstream_cache_capture(&mut p, &resp, false),
                "status {status} must not capture"
            );
        }
    }

    #[test]
    fn capture_blocked_when_vary_present() {
        let mut p = pending("k1");
        let resp = build_resp(200, &[("vary", "Accept-Encoding")]);
        assert!(!begin_upstream_cache_capture(&mut p, &resp, false));
        assert!(!p.capture_started);
    }

    #[test]
    fn capture_started_records_status_headers_and_cc() {
        let mut p = pending("k1");
        let resp = build_resp(204, &[("cache-control", "max-age=600"), ("x-extra", "v")]);
        assert!(begin_upstream_cache_capture(&mut p, &resp, false));
        assert!(p.capture_started);
        assert_eq!(p.status, 204);
        assert_eq!(p.cache_control.as_deref(), Some("max-age=600"));
        // Headers vector includes both headers we inserted.
        assert!(p.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("cache-control")));
        assert!(p.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-extra")));
    }

    #[test]
    fn capture_started_without_cache_control() {
        let mut p = pending("k2");
        let resp = build_resp(200, &[]);
        assert!(begin_upstream_cache_capture(&mut p, &resp, false));
        assert!(p.cache_control.is_none());
        assert_eq!(p.status, 200);
    }

    #[test]
    fn capture_started_with_identity_encoding() {
        let mut p = pending("k3");
        let resp = build_resp(200, &[("content-encoding", "identity")]);
        assert!(begin_upstream_cache_capture(&mut p, &resp, false));
    }

    // ── x-waf-* cross-request leak guard (§5 phase 5 red-team F3/F6) ─────────

    #[test]
    fn capture_unconditionally_strips_x_waf_star_from_pending_headers() {
        let mut p = pending("k-xwaf");
        // Upstream somehow returned x-waf-* (or a prior inject moved); the
        // cache snapshot must never include them — per-request identifiers
        // would replay to a different client on HIT.
        let resp = build_resp(
            200,
            &[
                ("x-waf-request-id", "leak-id-aaa"),
                ("x-waf-cache", "MISS"),
                ("x-waf-action", "allow"),
                ("x-waf-rule-id", "R-leak"),
                ("x-waf-risk-score", "9"),
                ("x-waf-mode", "enforce"),
                ("x-keep", "ok"),
            ],
        );
        assert!(begin_upstream_cache_capture(&mut p, &resp, false));
        // Non-waf header preserved; every x-waf-* stripped.
        assert!(
            p.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-keep")),
            "non-waf headers must survive capture: {:?}",
            p.headers
        );
        assert!(
            !p.headers
                .iter()
                .any(|(k, _)| k.to_ascii_lowercase().starts_with("x-waf-")),
            "no x-waf-* may enter the cache snapshot: {:?}",
            p.headers
        );
    }

    #[test]
    fn capture_strip_handles_mixed_case_and_partial_prefix_boundary() {
        let mut p = pending("k-case");
        let resp = build_resp(
            200,
            &[
                ("X-WAF-Request-Id", "MIXED-case"),
                ("x-Waf-Mode", "log_only"),
                ("x-wafer", "not-stripped"), // must NOT be stripped (no trailing -)
                ("x-keep", "ok"),
            ],
        );
        assert!(begin_upstream_cache_capture(&mut p, &resp, false));
        let lower: Vec<String> = p.headers.iter().map(|(k, _)| k.to_ascii_lowercase()).collect();
        assert!(!lower.iter().any(|k| k == "x-waf-request-id"));
        assert!(!lower.iter().any(|k| k == "x-waf-mode"));
        assert!(
            lower.iter().any(|k| k == "x-wafer"),
            "boundary: only `x-waf-` (with dash) strips"
        );
        assert!(lower.iter().any(|k| k == "x-keep"));
    }

    // ── cache_store_on_body_chunk ──────────────────────────────────────────────

    fn cache_for_test() -> Arc<crate::cache::ResponseCache> {
        crate::cache::ResponseCache::new(8, 60, 3600)
    }

    #[tokio::test]
    async fn body_chunk_is_noop_when_pending_is_none() {
        let cache = cache_for_test();
        let mut pending: Option<ResponseCachePending> = None;
        let mut body = Some(bytes::Bytes::from_static(b"abc"));
        cache_store_on_body_chunk(&cache, &mut pending, &mut body, true);
        assert!(pending.is_none());
        // Body untouched (we don't mutate inside).
        assert_eq!(body.as_ref().expect("body").as_ref(), b"abc");
    }

    #[tokio::test]
    async fn body_chunk_is_noop_when_capture_not_started() {
        let cache = cache_for_test();
        let mut pending = Some(pending("k"));
        let mut body = Some(bytes::Bytes::from_static(b"abc"));
        cache_store_on_body_chunk(&cache, &mut pending, &mut body, true);
        // capture_started is false → no append, no take, pending preserved.
        let p = pending.expect("preserved");
        assert!(p.body.is_empty());
    }

    #[tokio::test]
    async fn body_chunk_appends_until_limit_then_skips() {
        let cache = cache_for_test();
        let mut p = pending("k");
        p.capture_started = true;
        let mut pending = Some(p);

        // First chunk small.
        let mut body = Some(bytes::Bytes::from_static(b"hello"));
        cache_store_on_body_chunk(&cache, &mut pending, &mut body, false);
        assert_eq!(pending.as_ref().expect("kept").body.as_ref(), b"hello");

        // Second chunk: shrink the limit by filling close to ceiling.
        let chunk = vec![b'x'; 16];
        let mut body = Some(bytes::Bytes::from(chunk));
        cache_store_on_body_chunk(&cache, &mut pending, &mut body, false);
        let p = pending.as_ref().expect("kept");
        assert_eq!(p.body.len(), 5 + 16);
    }

    #[tokio::test]
    async fn body_chunk_skips_when_no_room_left() {
        // Force the case `room == 0`: body length already at the limit.
        let cache = cache_for_test();
        let mut p = pending("k");
        p.capture_started = true;
        // Pre-fill the pending body to exactly the limit so room == 0.
        p.body.resize(crate::context::RESPONSE_CACHE_BODY_LIMIT, 0);
        let mut pending = Some(p);
        let mut body = Some(bytes::Bytes::from_static(b"more-bytes"));
        cache_store_on_body_chunk(&cache, &mut pending, &mut body, false);
        // Body length unchanged.
        assert_eq!(
            pending.as_ref().expect("kept").body.len(),
            crate::context::RESPONSE_CACHE_BODY_LIMIT
        );
    }

    #[tokio::test]
    async fn body_chunk_no_chunk_passed_does_not_panic() {
        let cache = cache_for_test();
        let mut p = pending("k");
        p.capture_started = true;
        let mut pending = Some(p);
        let mut body: Option<bytes::Bytes> = None;
        cache_store_on_body_chunk(&cache, &mut pending, &mut body, false);
        assert!(pending.is_some());
    }

    #[tokio::test]
    async fn body_chunk_end_of_stream_takes_pending_and_spawns_store() {
        let cache = cache_for_test();
        let key = crate::cache::ResponseCache::make_key("GET", "example.com", "/p", "");
        let mut p = pending(&key);
        p.host = "example.com".into();
        p.path = "/p".into();
        p.capture_started = true;
        // Stage status + headers consistent with what begin_upstream_cache_capture would set.
        p.status = 200;
        p.headers = vec![];
        p.cache_control = Some("max-age=120".into());
        let mut pending = Some(p);
        let mut body = Some(bytes::Bytes::from_static(b"final"));
        cache_store_on_body_chunk(&cache, &mut pending, &mut body, true);
        assert!(pending.is_none(), "end_of_stream must take()");

        // Wait briefly for the spawned async store to land, then verify a hit.
        for _ in 0..20 {
            if cache.get(&key, Tier::Medium).await.is_some() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("cache store task did not land in time");
    }

    #[test]
    fn spawn_cache_store_task_outside_runtime_logs_warning_no_panic() {
        // Direct call to the inner spawn helper from a non-async context.
        // No tokio runtime → the function logs a warning and returns; must not panic.
        let cache: Arc<crate::cache::ResponseCache> = crate::cache::ResponseCache::new(1, 60, 60);
        let p = pending("k");
        spawn_cache_store_task(cache, p);
    }
}
