//! Security-hardening middleware and helpers.
//!
//! - Security response headers (`X-Frame-Options`, CSP, HSTS, `X-Content-Type-Options`)
//! - Cache-control for `/api/*` paths (prevents JWT/data caching by intermediaries)
//! - Request-ID correlation (generate or propagate `X-Request-Id`)
//! - Request body size enforcement
//! - IP-based admin access control
//! - Simple in-process per-IP rate limiting

#![allow(clippy::duration_suboptimal_units)] // prefer `from_secs` over MSRV‑gated `from_mins`

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;

use axum::{
    Json,
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use serde_json::json;

use crate::state::AppState;
use axum::{extract::Query, extract::State};
use waf_storage::models::AuditLogQuery;

// ─── Security headers middleware ──────────────────────────────────────────────

/// Adds hardened security headers to every management API response.
///
/// Headers applied (H2 in the plan):
/// - `Strict-Transport-Security` — 2-year max-age with preload
/// - `Content-Security-Policy` — default-src 'self' + hardened directives
/// - `Cross-Origin-Opener-Policy` — same-origin
/// - `Cross-Origin-Resource-Policy` — same-origin
/// - `Permissions-Policy` — restrictive set
/// - `X-Frame-Options` — DENY
/// - `X-Content-Type-Options` — nosniff
/// - `X-XSS-Protection` — 1; mode=block (legacy browsers)
/// - `Referrer-Policy` — strict-origin-when-cross-origin
///
/// `Cross-Origin-Embedder-Policy: require-corp` is applied only to `/ui/*`
/// paths to avoid blocking CORS API calls.
pub async fn security_headers_middleware(req: Request<Body>, next: Next) -> impl IntoResponse {
    use axum::http::HeaderValue;

    let path = req.uri().path().to_owned();
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-XSS-Protection", HeaderValue::from_static("1; mode=block"));
    headers.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
             style-src 'self' 'unsafe-inline'; \
             upgrade-insecure-requests; \
             base-uri 'self'; \
             form-action 'self'; \
             frame-ancestors 'none'; \
             object-src 'none'",
        ),
    );
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    headers.insert("Cross-Origin-Opener-Policy", HeaderValue::from_static("same-origin"));
    headers.insert("Cross-Origin-Resource-Policy", HeaderValue::from_static("same-origin"));
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=(), payment=()"),
    );

    // COEP only for UI — API routes may serve cross-origin clients (CORS).
    if path.starts_with("/ui") || path == "/" {
        headers.insert("Cross-Origin-Embedder-Policy", HeaderValue::from_static("require-corp"));
    }

    response
}

// ─── Cache-control middleware for /api/* ──────────────────────────────────────

/// Adds `Cache-Control: no-store` and related headers to every `/api/*` response.
///
/// Prevents JWT tokens and admin data from being cached by intermediary proxies.
pub async fn cache_control_middleware(req: Request<Body>, next: Next) -> impl IntoResponse {
    use axum::http::HeaderValue;

    let is_api = req.uri().path().starts_with("/api/");
    let mut response = next.run(req).await;

    if is_api {
        let headers = response.headers_mut();
        headers.insert(
            "Cache-Control",
            HeaderValue::from_static("no-store, no-cache, must-revalidate, private"),
        );
        headers.insert("Pragma", HeaderValue::from_static("no-cache"));
        headers.insert("Expires", HeaderValue::from_static("0"));
    }

    response
}

// ─── Request-ID middleware ────────────────────────────────────────────────────

/// Propagates or generates a `X-Request-Id` header.
///
/// If the incoming request already carries the header it is forwarded
/// unchanged. Otherwise a new `uuid::Uuid::new_v4()` (simple format) is
/// generated, stored in request extensions, and echoed in the response.
pub async fn request_id_middleware(mut req: Request<Body>, next: Next) -> impl IntoResponse {
    use axum::http::HeaderValue;

    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| uuid::Uuid::new_v4().simple().to_string(), ToOwned::to_owned);

    req.extensions_mut().insert(RequestId(request_id.clone()));

    let mut response = next.run(req).await;

    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", val);
    }

    response
}

/// Request extension holding the correlation ID for this request.
#[derive(Clone)]
pub struct RequestId(pub String);

// ─── Rate limiter ──────────────────────────────────────────────────────────────

/// Maximum number of per-IP entries before forced LRU eviction.
const API_RATE_MAX_ENTRIES: usize = 50_000;

/// Entries idle longer than this are evicted during periodic cleanup.
const API_RATE_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Token-bucket entry per IP
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Simple in-process per-IP rate limiter (token bucket algorithm).
///
/// Includes periodic cleanup of stale entries to prevent unbounded memory
/// growth when facing large numbers of unique source IPs.
pub struct ApiRateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    rps: f64,
    burst: f64,
}

impl ApiRateLimiter {
    pub fn new(rps: u32) -> Arc<Self> {
        let limiter = Arc::new(Self {
            buckets: Mutex::new(HashMap::new()),
            rps: f64::from(rps),
            burst: f64::from(rps.saturating_mul(5).max(10)),
        });

        // Spawn background cleanup task (runs every 60 seconds)
        let limiter_bg = Arc::clone(&limiter);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                limiter_bg.cleanup();
            }
        });

        limiter
    }

    /// Returns `true` if the request is allowed, `false` if rate-limited.
    #[allow(clippy::significant_drop_tightening)] // lock must span all bucket operations
    pub fn check(&self, ip: IpAddr) -> bool {
        if self.rps == 0.0 {
            return true;
        }
        let now = Instant::now();
        let mut map = self.buckets.lock();
        let bucket = map.entry(ip).or_insert(Bucket {
            tokens: self.burst,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = elapsed.mul_add(self.rps, bucket.tokens).min(self.burst);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Evict entries that have been idle longer than [`API_RATE_TTL`] and
    /// enforce [`API_RATE_MAX_ENTRIES`] by removing oldest entries first.
    fn cleanup(&self) {
        let now = Instant::now();
        let mut map = self.buckets.lock();

        // Remove stale entries
        map.retain(|_ip, bucket| now.duration_since(bucket.last_refill) < API_RATE_TTL);

        // If still over limit, evict oldest entries
        if map.len() > API_RATE_MAX_ENTRIES {
            let mut entries: Vec<(IpAddr, Instant)> = map.iter().map(|(ip, b)| (*ip, b.last_refill)).collect();
            entries.sort_by_key(|&(_ip, t)| t);

            let to_remove = map.len().saturating_sub(API_RATE_MAX_ENTRIES);
            for (ip, _) in entries.into_iter().take(to_remove) {
                map.remove(&ip);
            }
        }
    }
}

// ─── IP allowlist check ───────────────────────────────────────────────────────

/// Returns `true` when the IP is permitted by the allowlist.
/// An empty allowlist allows all addresses.
pub fn is_admin_ip_allowed(ip: &IpAddr, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    let ip_str = ip.to_string();
    for entry in allowlist {
        if entry == &ip_str {
            return true;
        }
        // CIDR check via ipnet
        if let Ok(net) = entry.parse::<ipnet::IpNet>()
            && net.contains(ip)
        {
            return true;
        }
    }
    false
}

// ─── GET /api/audit-log ───────────────────────────────────────────────────────

pub async fn list_audit_log(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuditLogQuery>,
) -> impl IntoResponse {
    match state.db.list_audit_log(&query).await {
        Ok((entries, total)) => (
            StatusCode::OK,
            Json(json!({
                "entries": entries,
                "total": total,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

// ─── Admin IP allowlist middleware ────────────────────────────────────────────

/// Rejects requests from IPs not in the admin allowlist.
/// If the allowlist is empty, all IPs are allowed.
pub async fn admin_ip_check_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let ip = req
        .extensions()
        .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
        .map_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), |ci| ci.0.ip());

    if !is_admin_ip_allowed(&ip, &state.security_config.admin_ip_allowlist) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "IP address not allowed" })),
        )
            .into_response();
    }

    next.run(req).await.into_response()
}

// ─── API rate limit middleware ────────────────────────────────────────────────

/// Enforces per-IP rate limiting on the management API.
/// Returns 429 Too Many Requests when the limit is exceeded.
pub async fn rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    if let Some(ref limiter) = state.rate_limiter {
        let ip = req
            .extensions()
            .get::<axum::extract::connect_info::ConnectInfo<std::net::SocketAddr>>()
            .map_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), |ci| ci.0.ip());

        if !limiter.check(ip) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "Rate limit exceeded" })),
            )
                .into_response();
        }
    }

    next.run(req).await.into_response()
}

// ─── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use axum::{Router, middleware, routing::get};
    #[allow(unused_imports)]
    use tower::ServiceExt;

    // ── IP allowlist tests ────────────────────────────────────────────────────

    /// Empty allowlist means every IP is permitted.
    #[test]
    fn admin_ip_empty_allowlist_allows_all() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(is_admin_ip_allowed(&ip, &[]));
    }

    /// An IP that exactly matches an allowlist entry is permitted.
    #[test]
    fn admin_ip_allowed_ip_passes() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let allowlist = vec!["1.2.3.4".to_owned()];
        assert!(is_admin_ip_allowed(&ip, &allowlist));
    }

    /// An IP that does not match any allowlist entry is rejected.
    #[test]
    fn admin_ip_blocked_ip_rejected() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let allowlist = vec!["1.2.3.4".to_owned()];
        assert!(!is_admin_ip_allowed(&ip, &allowlist));
    }

    /// Loopback IPv4 passes when it is explicitly listed.
    #[test]
    fn admin_ip_loopback_in_allowlist() {
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let allowlist = vec!["127.0.0.1".to_owned()];
        assert!(is_admin_ip_allowed(&ip, &allowlist));
    }

    /// Loopback IPv6 (`::1`) passes when it is explicitly listed.
    #[test]
    fn admin_ip_ipv6_loopback_check() {
        let ip: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let allowlist = vec!["::1".to_owned()];
        assert!(is_admin_ip_allowed(&ip, &allowlist));
    }

    /// CIDR entries are matched correctly: addresses inside the range pass,
    /// addresses outside are rejected.
    #[test]
    fn admin_ip_cidr_matching() {
        let allowlist = vec!["10.0.0.0/8".to_owned()];

        let inside: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert!(is_admin_ip_allowed(&inside, &allowlist));

        let outside: IpAddr = IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1));
        assert!(!is_admin_ip_allowed(&outside, &allowlist));
    }

    // ── Rate limiter tests ────────────────────────────────────────────────────

    /// Requests well under the burst limit are all allowed.
    #[tokio::test]
    async fn rate_limiter_allows_under_limit() {
        let limiter = ApiRateLimiter::new(100);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        for _ in 0..5 {
            assert!(limiter.check(ip));
        }
    }

    /// After the burst budget is exhausted (rps=1, burst=10), the 11th request
    /// is rejected.
    #[tokio::test]
    async fn rate_limiter_blocks_over_limit() {
        let limiter = ApiRateLimiter::new(1); // burst = max(1*5, 10) = 10
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // Exhaust the 10-token burst
        for _ in 0..10 {
            assert!(limiter.check(ip));
        }
        // 11th call must be rate-limited
        assert!(!limiter.check(ip));
    }

    /// Exhausting one IP's budget does not affect a different IP.
    #[tokio::test]
    async fn rate_limiter_different_ips_independent() {
        let limiter = ApiRateLimiter::new(1); // burst = 10
        let ip1: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Exhaust ip1
        for _ in 0..11 {
            let _ = limiter.check(ip1);
        }
        assert!(!limiter.check(ip1));

        // ip2 is unaffected
        assert!(limiter.check(ip2));
    }

    /// rps=0 means unlimited — every call returns true regardless of volume.
    #[tokio::test]
    async fn rate_limiter_zero_rps_allows_all() {
        let limiter = ApiRateLimiter::new(0);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        for _ in 0..100 {
            assert!(limiter.check(ip));
        }
    }

    // ── Security headers tests ────────────────────────────────────────────────

    /// `X-Content-Type-Options` and `X-Frame-Options` headers must be present.
    #[tokio::test]
    async fn security_headers_present() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(security_headers_middleware));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let resp: axum::response::Response = app.oneshot(req).await.unwrap();

        assert!(
            resp.headers().contains_key("x-content-type-options"),
            "X-Content-Type-Options header missing"
        );
        assert!(
            resp.headers().contains_key("x-frame-options"),
            "X-Frame-Options header missing"
        );
    }

    /// `Content-Security-Policy` header must be present.
    #[tokio::test]
    async fn security_headers_csp_present() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(security_headers_middleware));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let resp: axum::response::Response = app.oneshot(req).await.unwrap();

        assert!(
            resp.headers().contains_key("content-security-policy"),
            "Content-Security-Policy header missing"
        );
    }

    /// HSTS header must use 2-year max-age with preload.
    #[tokio::test]
    async fn hsts_header_value_is_two_years_with_preload() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(security_headers_middleware));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp: axum::response::Response = app.oneshot(req).await.unwrap();

        let hsts = resp
            .headers()
            .get("strict-transport-security")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            hsts.contains("max-age=63072000"),
            "HSTS must be 2-year max-age, got: {hsts}"
        );
        assert!(hsts.contains("preload"), "HSTS must include preload, got: {hsts}");
    }

    /// COOP header must be present.
    #[tokio::test]
    async fn coop_header_present() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(security_headers_middleware));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp: axum::response::Response = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.headers()
                .get("cross-origin-opener-policy")
                .unwrap()
                .to_str()
                .unwrap(),
            "same-origin"
        );
    }

    /// All security header values must match their expected strings exactly.
    #[tokio::test]
    async fn security_headers_values_correct() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(security_headers_middleware));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp: axum::response::Response = app.oneshot(req).await.unwrap();
        let headers = resp.headers();

        assert_eq!(headers.get("x-frame-options").unwrap().to_str().unwrap(), "DENY");
        assert_eq!(
            headers.get("x-content-type-options").unwrap().to_str().unwrap(),
            "nosniff"
        );
        assert_eq!(
            headers.get("x-xss-protection").unwrap().to_str().unwrap(),
            "1; mode=block"
        );
        assert_eq!(
            headers.get("referrer-policy").unwrap().to_str().unwrap(),
            "strict-origin-when-cross-origin"
        );
    }

    /// CSP header value must start with `default-src 'self'` and contain both
    /// `script-src` and `style-src` directives.
    #[tokio::test]
    async fn security_headers_csp_value() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(security_headers_middleware));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp: axum::response::Response = app.oneshot(req).await.unwrap();

        let csp = resp.headers().get("content-security-policy").unwrap().to_str().unwrap();

        assert!(
            csp.starts_with("default-src 'self'"),
            "CSP must start with \"default-src 'self'\", got: {csp}"
        );
        assert!(csp.contains("script-src"), "CSP missing script-src directive");
        assert!(csp.contains("style-src"), "CSP missing style-src directive");
        assert!(
            csp.contains("frame-ancestors 'none'"),
            "CSP missing frame-ancestors directive"
        );
    }

    // ── Cache-control tests ───────────────────────────────────────────────────

    /// `/api/*` responses must have `Cache-Control: no-store`.
    #[tokio::test]
    async fn cache_control_no_store_on_api_paths() {
        let app = Router::new()
            .route("/api/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(cache_control_middleware));

        let req = Request::builder().uri("/api/test").body(Body::empty()).unwrap();
        let resp: axum::response::Response = app.oneshot(req).await.unwrap();

        let cc = resp.headers().get("cache-control").unwrap().to_str().unwrap();
        assert!(
            cc.contains("no-store"),
            "Cache-Control must include no-store, got: {cc}"
        );
        assert!(
            cc.contains("no-cache"),
            "Cache-Control must include no-cache, got: {cc}"
        );
    }

    /// `/ui/*` responses must NOT have the cache-control override.
    #[tokio::test]
    async fn cache_control_absent_on_ui_paths() {
        let app = Router::new()
            .route("/ui/index.html", get(|| async { "ok" }))
            .layer(middleware::from_fn(cache_control_middleware));

        let req = Request::builder().uri("/ui/index.html").body(Body::empty()).unwrap();
        let resp: axum::response::Response = app.oneshot(req).await.unwrap();

        assert!(
            !resp.headers().contains_key("cache-control"),
            "Cache-Control must not be set for /ui/ paths"
        );
    }

    // ── Request-ID tests ──────────────────────────────────────────────────────

    /// When no `X-Request-Id` is provided, the middleware generates one and adds it.
    #[tokio::test]
    async fn request_id_generated_when_missing() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(request_id_middleware));

        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp: axum::response::Response = app.oneshot(req).await.unwrap();

        assert!(
            resp.headers().contains_key("x-request-id"),
            "X-Request-Id header must be generated"
        );
        let id = resp.headers().get("x-request-id").unwrap().to_str().unwrap();
        assert!(!id.is_empty(), "X-Request-Id must not be empty");
    }

    /// When `X-Request-Id` is provided it must be echoed back unchanged.
    #[tokio::test]
    async fn request_id_propagated_when_provided() {
        let app = Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(request_id_middleware));

        let req = Request::builder()
            .uri("/test")
            .header("x-request-id", "my-custom-id-abc123")
            .body(Body::empty())
            .unwrap();
        let resp: axum::response::Response = app.oneshot(req).await.unwrap();

        assert_eq!(
            resp.headers().get("x-request-id").unwrap().to_str().unwrap(),
            "my-custom-id-abc123"
        );
    }

    /// After consuming some tokens, sleeping allows the bucket to refill.
    #[tokio::test]
    async fn rate_limiter_token_refill() {
        let limiter = ApiRateLimiter::new(100); // rps=100, burst=500
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 1));

        // Consume 200 tokens (well within burst of 500)
        for _ in 0..200 {
            assert!(limiter.check(ip));
        }

        // Sleep 100 ms — should refill ~10 tokens (100 rps * 0.1 s)
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // At least one more token should now be available
        assert!(limiter.check(ip), "Expected tokens to refill after 100 ms sleep");
    }

    /// Exhausting all burst tokens causes the next call to fail; after sleeping
    /// long enough for at least one token to refill, calls succeed again.
    #[tokio::test]
    async fn rate_limiter_burst_exhaustion_then_recovery() {
        // rps=2, burst = max(2*5, 10) = 10
        let limiter = ApiRateLimiter::new(2);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 2));

        // Exhaust burst
        for _ in 0..10 {
            assert!(limiter.check(ip));
        }
        assert!(!limiter.check(ip), "Burst should be exhausted");

        // Sleep 600 ms — rps=2 means 1 token every 500 ms, so ~1 token refills
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;

        assert!(limiter.check(ip), "Expected at least one token after recovery sleep");
    }

    /// Concurrent `check()` calls from 10 tasks on the same IP must not panic
    /// and the total number of allowed calls must not exceed the burst limit.
    #[tokio::test]
    async fn rate_limiter_concurrent_check() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // rps=2, burst=10
        let limiter = ApiRateLimiter::new(2);
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 3));
        let allowed = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(10);
        for _ in 0..10 {
            let lim = Arc::clone(&limiter);
            let counter = Arc::clone(&allowed);
            handles.push(tokio::spawn(async move {
                if lim.check(ip) {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let total_allowed = allowed.load(Ordering::Relaxed);
        // Must not exceed burst (10) and must not panic
        assert!(
            total_allowed <= 10,
            "Concurrent check allowed {total_allowed} requests, exceeding burst of 10"
        );
    }

    /// Multiple exact entries and one CIDR entry: verify each combination.
    #[test]
    fn admin_ip_multiple_entries() {
        let allowlist = vec!["1.2.3.4".to_owned(), "5.6.7.8".to_owned(), "10.0.0.0/8".to_owned()];

        // Exact match first entry
        assert!(is_admin_ip_allowed(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), &allowlist));
        // Exact match second entry
        assert!(is_admin_ip_allowed(&IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), &allowlist));
        // Inside CIDR range
        assert!(is_admin_ip_allowed(
            &IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1)),
            &allowlist
        ));
        // Outside all entries
        assert!(!is_admin_ip_allowed(
            &IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1)),
            &allowlist
        ));
        // Partial match is not enough (e.g., 1.2.3.5 ≠ 1.2.3.4 and not in CIDR)
        assert!(!is_admin_ip_allowed(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)), &allowlist));
    }

    /// IPv4-mapped IPv6 address `::ffff:192.168.1.1` does NOT match allowlist
    /// entry "192.168.1.1" because `IpAddr::to_string()` produces different
    /// strings and `ipnet` does not cross-map IPv4-mapped IPv6 to IPv4 CIDRs.
    /// This test documents the actual behavior.
    #[test]
    fn admin_ip_ipv4_mapped_ipv6() {
        let allowlist = vec!["192.168.1.1".to_owned()];

        // Plain IPv4 address — must match
        let ipv4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(
            is_admin_ip_allowed(&ipv4, &allowlist),
            "Plain IPv4 192.168.1.1 should match"
        );

        // IPv4-mapped IPv6 — does NOT match the plain IPv4 allowlist entry
        let ipv4_mapped: IpAddr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101));
        assert!(
            !is_admin_ip_allowed(&ipv4_mapped, &allowlist),
            "IPv4-mapped IPv6 ::ffff:192.168.1.1 should NOT match plain IPv4 entry"
        );
    }
}
