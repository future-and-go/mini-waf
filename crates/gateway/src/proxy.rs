//! Pingora [`ProxyHttp`] implementation that wires WAF inspection and filter
//! chains into the proxy lifecycle.
//!
//! All context construction is delegated to [`RequestCtxBuilder`].
//! All filter execution is delegated to [`RequestFilterChain`] /
//! [`ResponseFilterChain`] (populated by phases 02–04).
//! WAF response helpers live in [`super::proxy_waf_response`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use tracing::{debug, info, warn};

use pingora_core::upstreams::peer::HttpPeer;
use pingora_proxy::{FailToProxy, ProxyHttp, Session};

use waf_common::HostConfig;
use waf_engine::WafEngine;

use crate::tiered::TierPolicyRegistry;

use crate::context::{BODY_PREVIEW_LIMIT, GatewayCtx};
use crate::ctx_builder::RequestCtxBuilder;
use crate::error_page::ErrorPageFactory;
use crate::filters::{
    CompiledMask, CompiledScanner, DecoderChain, RequestForwardedHostFilter, RequestForwardedProtoFilter,
    RequestHopByHopFilter, RequestHostPolicyFilter, RequestRealIpFilter, RequestXffFilter, ResponseEncoding,
    ResponseHeaderBlocklistFilter, ResponseLocationRewriter, ResponseServerPolicyFilter, ResponseViaStripFilter,
    apply_body_mask_chunk, apply_body_scan_chunk, parse_encoding, scanner_config_hash,
};
use crate::pipeline::{FilterCtx, RequestFilterChain, ResponseFilterChain};
use crate::protocol::{ProtoCounters, detect_from_session};
use crate::proxy_waf_response::{write_waf_body_decision, write_waf_decision};
use crate::router::HostRouter;

/// Pingora-based reverse proxy with WAF integration and filter chains.
pub struct WafProxy {
    pub router: Arc<HostRouter>,
    pub engine: Arc<WafEngine>,
    /// Whether to trust X-Forwarded-For headers for client IP extraction.
    pub trust_proxy_headers: bool,
    /// Parsed trusted proxy CIDR ranges.
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Total request counter (cloned from `AppState`).
    pub request_counter: Arc<AtomicU64>,
    /// Blocked request counter (cloned from `AppState`).
    pub blocked_counter: Arc<AtomicU64>,
    /// Per-protocol counters (AC-22 transparency proof). Shared with the
    /// HTTP/3 listener so QUIC traffic increments the same struct.
    pub proto_counters: Arc<ProtoCounters>,
    /// Ordered chain of upstream request filters (populated by phases 02–04).
    pub request_chain: Arc<RequestFilterChain>,
    /// Ordered chain of response filters (populated by phases 02–03).
    pub response_chain: Arc<ResponseFilterChain>,
    /// AC-17: per-host compiled mask cache, keyed by `Arc<HostConfig>` pointer
    /// identity. Compiled lazily on first body chunk; survives until config reload.
    pub body_mask_cache: Arc<DashMap<usize, Arc<CompiledMask>>>,
    /// FR-002: tier policy registry. When `None`, every request defaults to
    /// `Tier::CatchAll` + permissive policy (boot-time safety).
    pub tier_registry: Option<Arc<TierPolicyRegistry>>,
    /// FR-033: per-host compiled scanner cache, keyed by content-hash
    /// `(host_name, xxhash64(body_scan_*))` so config reload doesn't risk
    /// pointer-address reuse bleeding across hosts (red-team #6).
    /// Bounded via `moka::sync::Cache` (max 256 entries, 1 h TTL) so config
    /// churn cannot grow the cache without bound (red-team review H2).
    /// AC-17 / FR-034 caches inherit the same hazard; backport tracked separately.
    pub body_scan_cache: moka::sync::Cache<(String, u64), Arc<CompiledScanner>>,
}

impl WafProxy {
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(router: Arc<HostRouter>, engine: Arc<WafEngine>) -> Self {
        Self {
            router,
            engine,
            trust_proxy_headers: false,
            trusted_proxies: Vec::new(),
            request_counter: Arc::new(AtomicU64::new(0)),
            blocked_counter: Arc::new(AtomicU64::new(0)),
            proto_counters: ProtoCounters::new(),
            request_chain: Arc::new(build_request_chain()),
            response_chain: Arc::new(build_response_chain()),
            body_mask_cache: Arc::new(DashMap::new()),
            tier_registry: None,
            body_scan_cache: moka::sync::Cache::builder()
                .max_capacity(256)
                .time_to_live(std::time::Duration::from_hours(1))
                .build(),
        }
    }

    /// Inject the tier policy registry (FR-002 phase-05). When set, every
    /// `RequestCtx` built by this proxy carries a classified tier instead of
    /// the boot-time `CatchAll` fallback.
    pub fn with_tier_registry(&mut self, registry: Arc<TierPolicyRegistry>) {
        self.tier_registry = Some(registry);
    }

    /// Resolve (and lazily compile) the mask config for a given host.
    /// Cache key is the `Arc<HostConfig>` pointer; identical configs across
    /// requests reuse the same compiled regex.
    fn resolve_mask(&self, hc: &Arc<HostConfig>) -> Arc<CompiledMask> {
        let key = Arc::as_ptr(hc) as usize;
        if let Some(existing) = self.body_mask_cache.get(&key) {
            return Arc::clone(&existing);
        }
        let compiled = Arc::new(CompiledMask::build(
            &hc.internal_patterns,
            &hc.mask_token,
            hc.body_mask_max_bytes,
        ));
        self.body_mask_cache.insert(key, Arc::clone(&compiled));
        compiled
    }

    /// FR-033: resolve (and lazily compile) the content scanner for a given
    /// host. Cache key is `(host_name, xxhash64(body_scan_* fields))` —
    /// content-hashed so a config reload that produces an `Arc` at the same
    /// address as a different host's prior config cannot bleed (red-team #6).
    fn resolve_scanner(&self, hc: &Arc<HostConfig>) -> Arc<CompiledScanner> {
        let cfg_hash = scanner_config_hash(hc.body_scan_enabled, hc.body_scan_max_body_bytes);
        let key = (hc.host.clone(), cfg_hash);
        if let Some(existing) = self.body_scan_cache.get(&key) {
            return existing;
        }
        let compiled = Arc::new(CompiledScanner::build(hc.body_scan_max_body_bytes));
        self.body_scan_cache.insert(key, Arc::clone(&compiled));
        compiled
    }
}

/// Map a Pingora error to the HTTP status used by [`ErrorPageFactory`].
///
/// Mirrors the default `fail_to_proxy` mapping but lives in gateway code so we
/// can render a neutral body. `0` means "downstream is already gone — do not
/// attempt to write a response."
fn error_to_status(e: &pingora_core::Error) -> u16 {
    use pingora_core::{ErrorSource, ErrorType};
    if let ErrorType::HTTPStatus(code) = e.etype() {
        return *code;
    }
    match e.esource() {
        ErrorSource::Upstream => 502,
        ErrorSource::Downstream => match e.etype() {
            ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed => 0,
            _ => 400,
        },
        ErrorSource::Internal | ErrorSource::Unset => 500,
    }
}

/// FR-033: gate the body content scanner on a Content-Type allowlist so we
/// never corrupt gRPC trailers, server-sent event streams, or arbitrary
/// binary payloads. Allowed: textual + JSON / XML / JS bodies.
///
/// Missing `Content-Type` defaults to *not* scannable. Upstream responses
/// without a declared media type may legitimately be binary (protobuf,
/// images, octet-stream), and running text-shaped regex over arbitrary
/// bytes risks false positives (random byte sequences shaped like dotted-
/// quad IPs) plus body corruption from in-place redaction.
fn response_content_type_scannable(resp: &pingora_http::ResponseHeader) -> bool {
    let Some(ct) = resp.headers.get("content-type").and_then(|v| v.to_str().ok()) else {
        tracing::debug!("body-scan: skipping response without Content-Type header");
        return false;
    };
    let main = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if main.starts_with("application/grpc") || main == "text/event-stream" || main == "application/octet-stream" {
        return false;
    }
    if main.starts_with("text/")
        || main == "application/json"
        || main == "application/xml"
        || main == "application/problem+json"
        || main == "application/javascript"
    {
        return true;
    }
    false
}

/// Build the default response-side filter chain (AC-15, 16, 18).
///
/// Order:
/// 1. `via-strip` — unconditional removal.
/// 2. `server-policy` — passthrough (default) or strip.
/// 3. `location-rewrite` — rewrite internal-host redirects.
/// 4. `header-blocklist` — drop configured leak headers last so anything
///    a prior filter leaves behind still gets scrubbed.
fn build_response_chain() -> ResponseFilterChain {
    let mut chain = ResponseFilterChain::new();
    chain.register(Arc::new(ResponseViaStripFilter));
    chain.register(Arc::new(ResponseServerPolicyFilter));
    chain.register(Arc::new(ResponseLocationRewriter));
    chain.register(Arc::new(ResponseHeaderBlocklistFilter));
    chain
}

/// Build the default request-side filter chain.
///
/// Order is significant:
/// 1. `xff` / `real-ip` / `forwarded-proto` — populate forwarded metadata.
/// 2. `forwarded-host` — captures the ORIGINAL `Host` (must run before host-policy).
/// 3. `host-policy` — applies `Preserve` or `Rewrite(remote_host)` per host config.
/// 4. `hop-by-hop` — strips RFC 7230 hop headers + Connection-tokens last,
///    so any header *we* added (e.g. `Connection: upgrade` for WS) is preserved
///    by the WS-aware branch.
fn build_request_chain() -> RequestFilterChain {
    let mut chain = RequestFilterChain::new();
    chain.register(Arc::new(RequestXffFilter));
    chain.register(Arc::new(RequestRealIpFilter));
    chain.register(Arc::new(RequestForwardedProtoFilter));
    chain.register(Arc::new(RequestForwardedHostFilter));
    chain.register(Arc::new(RequestHostPolicyFilter));
    chain.register(Arc::new(RequestHopByHopFilter));
    chain
}

#[async_trait]
impl ProxyHttp for WafProxy {
    type CTX = GatewayCtx;

    fn new_ctx(&self) -> Self::CTX {
        GatewayCtx::default()
    }

    async fn upstream_peer(&self, session: &mut Session, ctx: &mut GatewayCtx) -> pingora_core::Result<Box<HttpPeer>> {
        self.request_counter.fetch_add(1, Ordering::Relaxed);

        let host_header = session
            .get_header("host")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .unwrap_or("")
            .to_string();

        debug!("Routing request for host: {}", host_header);

        let host_config = self.router.resolve(&host_header).ok_or_else(|| {
            pingora_core::Error::explain(
                pingora_core::ErrorType::ConnectProxyFailure,
                format!("No route found for host: {host_header}"),
            )
        })?;

        if !host_config.start_status {
            return Err(pingora_core::Error::explain(
                pingora_core::ErrorType::ConnectProxyFailure,
                "Site is closed",
            ));
        }

        let upstream_addr = format!("{}:{}", host_config.remote_host, host_config.remote_port);
        let use_tls = host_config.ssl;

        ctx.upstream_addr = Some(upstream_addr.clone());
        if ctx.host_config.is_none() {
            ctx.host_config = Some(Arc::clone(&host_config));
        }
        if ctx.request_ctx.is_none() {
            let mut builder = RequestCtxBuilder::new(session, self.trust_proxy_headers, &self.trusted_proxies)
                .with_host_config(Arc::clone(&host_config));
            if let Some(reg) = &self.tier_registry {
                builder = builder.with_tier_registry(reg);
            }
            ctx.request_ctx = Some(builder.build());
        }

        info!("Proxying {} → {}", host_header, upstream_addr);
        Ok(Box::new(HttpPeer::new(
            &upstream_addr,
            use_tls,
            host_config.remote_host.clone(),
        )))
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut GatewayCtx) -> pingora_core::Result<bool> {
        // AC-22: tag protocol once and bump the per-protocol counter so every
        // request through the Pingora listener (H1/H2/WS-upgrade) is accounted
        // for. H3 traffic increments the same struct from `http3.rs`.
        ctx.protocol = detect_from_session(session);
        self.proto_counters.record(ctx.protocol);

        // Build request context early so WAF runs before upstream_peer.
        if ctx.request_ctx.is_none() {
            let host_header = session
                .get_header("host")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                .unwrap_or("")
                .to_string();
            if let Some(host_config) = self.router.resolve(&host_header) {
                ctx.host_config = Some(Arc::clone(&host_config));
                let mut builder = RequestCtxBuilder::new(session, self.trust_proxy_headers, &self.trusted_proxies)
                    .with_host_config(host_config);
                if let Some(reg) = &self.tier_registry {
                    builder = builder.with_tier_registry(reg);
                }
                ctx.request_ctx = Some(builder.build());
            }
        }

        let host_for_log = ctx
            .request_ctx
            .as_ref()
            .map_or_else(|| "<unknown>".to_string(), |c| c.host.clone());

        // FAIL-CLOSED: never bypass WAF when context is missing (AC-22).
        let mut request_ctx = if let Some(c) = &ctx.request_ctx {
            c.clone()
        } else {
            self.blocked_counter.fetch_add(1, Ordering::Relaxed);
            warn!(host = %host_for_log, "fail-closed: missing request context, returning 503");
            let accept = session
                .get_header("accept")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                .map(str::to_string);
            let (headers, body) = ErrorPageFactory::render(503, accept.as_deref())?;
            session.write_response_header(Box::new(headers), false).await?;
            session.write_response_body(Some(body), true).await?;
            return Ok(true);
        };

        if request_ctx.path == "/health" && request_ctx.method == "GET" {
            let _ = session.respond_error(200).await;
            return Ok(true);
        }

        let decision = self.engine.inspect(&mut request_ctx).await;
        write_waf_decision(session, &decision, &request_ctx, &self.blocked_counter).await
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut GatewayCtx,
    ) -> pingora_core::Result<()> {
        if ctx.body_inspected {
            return Ok(());
        }
        if let Some(chunk) = body {
            let remaining = BODY_PREVIEW_LIMIT.saturating_sub(ctx.body_buf.len());
            if remaining > 0 {
                let take = chunk.len().min(remaining);
                if let Some(slice) = chunk.get(..take) {
                    ctx.body_buf.extend_from_slice(slice);
                }
            }
        }
        let should_inspect = ctx.body_buf.len() >= BODY_PREVIEW_LIMIT || (end_of_stream && !ctx.body_buf.is_empty());
        if !should_inspect {
            return Ok(());
        }
        ctx.body_inspected = true;
        let mut request_ctx = match &ctx.request_ctx {
            Some(c) => c.clone(),
            None => return Ok(()),
        };
        request_ctx.body_preview = Bytes::copy_from_slice(&ctx.body_buf);
        let decision = self.engine.inspect(&mut request_ctx).await;
        write_waf_body_decision(session, &decision, &request_ctx, &self.blocked_counter).await
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let (Some(req_ctx), Some(hc)) = (&ctx.request_ctx, &ctx.host_config) {
            // peer_ip is the IMMEDIATE TCP peer (not the resolved client).
            // The two differ when trust_proxy_headers=true and the peer is
            // a trusted proxy: client_ip then comes from XFF, while peer_ip
            // remains the proxy's IP. XFF append-mode (AC-14) needs peer_ip.
            let peer_ip = session
                .client_addr()
                .and_then(|a| a.as_inet())
                .map_or(req_ctx.client_ip, std::net::SocketAddr::ip);
            let fctx = FilterCtx {
                request_ctx: req_ctx,
                host_config: hc,
                peer_ip,
                is_tls: req_ctx.is_tls,
            };
            self.request_chain.apply_all(upstream_request, &fctx)?;
        }
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut pingora_http::ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        if let (Some(req_ctx), Some(hc)) = (&ctx.request_ctx, &ctx.host_config) {
            let fctx = FilterCtx {
                request_ctx: req_ctx,
                host_config: hc,
                peer_ip: req_ctx.client_ip,
                is_tls: req_ctx.is_tls,
            };
            self.response_chain.apply_all(upstream_response, &fctx)?;

            // FR-033: decide whether the response-body content scanner runs.
            // Gated by Content-Type allowlist + Content-Encoding (gzip / identity).
            // When enabled, drop Content-Length and Transfer-Encoding
            // unconditionally (red-team #9) so Pingora re-emits chunked.
            // Drop Content-Encoding only if we successfully attached a decoder.
            if hc.body_scan_enabled {
                let scanner = self.resolve_scanner(hc);
                let ct_ok = response_content_type_scannable(upstream_response);
                let ce_header = upstream_response
                    .headers
                    .get("content-encoding")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let encoding = parse_encoding(ce_header);
                if ct_ok && !scanner.is_noop() {
                    match encoding {
                        ResponseEncoding::Identity => {
                            ctx.body_scan.enabled = true;
                            ctx.body_scan.decoder = None;
                            let _ = upstream_response.remove_header("content-length");
                            let _ = upstream_response.remove_header("transfer-encoding");
                        }
                        ResponseEncoding::Gzip => {
                            ctx.body_scan.enabled = true;
                            ctx.body_scan.decoder = Some(DecoderChain::new());
                            let _ = upstream_response.remove_header("content-length");
                            let _ = upstream_response.remove_header("transfer-encoding");
                            let _ = upstream_response.remove_header("content-encoding");
                        }
                        ResponseEncoding::Unsupported => {
                            debug!(
                                encoding = ce_header,
                                "body-scan: skipping unsupported content-encoding (fail-open)"
                            );
                        }
                    }
                }
            }

            // FR-034 (PR #18) inserts here when merged: JSON field redactor
            // operates on plaintext after FR-033 has decompressed.

            // AC-17: decide whether body masking will run for this response.
            // Identity (or absent) Content-Encoding only — compressed bodies
            // are out of scope for FR-001 (FR-033 owns decompression).
            let identity = upstream_response
                .headers
                .get("content-encoding")
                .and_then(|v| v.to_str().ok())
                .is_none_or(|v| {
                    let v = v.trim();
                    v.is_empty() || v.eq_ignore_ascii_case("identity")
                });
            let compiled = self.resolve_mask(hc);
            if identity && !compiled.is_noop() {
                ctx.body_mask.enabled = true;
                // Replacement length differs from match length — body length is
                // no longer fixed. Drop Content-Length so Pingora switches to
                // chunked encoding.
                let _ = upstream_response.remove_header("content-length");
            } else if !compiled.is_noop() {
                debug!("body-mask: skipping non-identity content-encoding");
            }
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Option<Duration>>
    where
        Self::CTX: Send + Sync,
    {
        let Some(hc) = ctx.host_config.clone() else {
            return Ok(None);
        };

        // FR-033 runs FIRST so PR-18 (FR-034) and AC-17 see plaintext.
        if ctx.body_scan.enabled {
            let scanner = self.resolve_scanner(&hc);
            let host_label: &str = hc.host.as_str();
            apply_body_scan_chunk(&mut ctx.body_scan, &scanner, body, end_of_stream, host_label);
        }

        // FR-034 (PR #18) inserts here when merged: apply_redact_chunk(...)

        // AC-17 — operator regex masker on (now-plaintext) bytes.
        if ctx.body_mask.enabled {
            let compiled = self.resolve_mask(&hc);
            apply_body_mask_chunk(&mut ctx.body_mask, &compiled, body, end_of_stream);
        }
        Ok(None)
    }

    /// AC-19: render a neutral, content-negotiated error page (no Pingora fingerprint).
    ///
    /// Maps the error to an HTTP status using the same heuristics as the trait
    /// default, then writes our own headers+body so the response is free of any
    /// Pingora-default markers (`Server: pingora/...`, default HTML page, etc.).
    async fn fail_to_proxy(&self, session: &mut Session, e: &pingora_core::Error, _ctx: &mut Self::CTX) -> FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let code = error_to_status(e);
        if code > 0 {
            let accept = session
                .get_header("accept")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                .map(str::to_string);
            match ErrorPageFactory::render(code, accept.as_deref()) {
                Ok((headers, body)) => {
                    if let Err(write_err) = session.write_response_header(Box::new(headers), false).await {
                        warn!("failed to write error header to downstream: {write_err}");
                    } else if let Err(write_err) = session.write_response_body(Some(body), true).await {
                        warn!("failed to write error body to downstream: {write_err}");
                    }
                }
                Err(render_err) => {
                    warn!("error-page render failed: {render_err}");
                }
            }
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    async fn logging(&self, _session: &mut Session, _error: Option<&pingora_core::Error>, ctx: &mut GatewayCtx) {
        if let Some(req_ctx) = &ctx.request_ctx {
            debug!(
                tier = ?req_ctx.tier,
                "Request completed: {} {} {} → upstream={}",
                req_ctx.method,
                req_ctx.host,
                req_ctx.path,
                ctx.upstream_addr.as_deref().unwrap_or("unknown"),
            );
        }
    }
}

#[cfg(test)]
mod content_type_scannable_tests {
    use super::response_content_type_scannable;
    use pingora_http::ResponseHeader;

    fn build(ct: Option<&str>) -> ResponseHeader {
        let mut resp = ResponseHeader::build(200, None).expect("BUG: ResponseHeader::build(200) is infallible");
        if let Some(v) = ct {
            let _ = resp.append_header("content-type", v);
        }
        resp
    }

    #[test]
    fn missing_content_type_defaults_false() {
        let resp = build(None);
        assert!(
            !response_content_type_scannable(&resp),
            "missing CT must fail-closed (skip scan)"
        );
    }

    #[test]
    fn text_html_with_charset_allowed() {
        let resp = build(Some("text/html; charset=utf-8"));
        assert!(response_content_type_scannable(&resp));
    }

    #[test]
    fn application_json_allowed() {
        let resp = build(Some("application/json"));
        assert!(response_content_type_scannable(&resp));
    }

    #[test]
    fn octet_stream_blocked() {
        let resp = build(Some("application/octet-stream"));
        assert!(!response_content_type_scannable(&resp));
    }

    #[test]
    fn grpc_variants_blocked() {
        let resp = build(Some("application/grpc+proto"));
        assert!(!response_content_type_scannable(&resp));
    }

    #[test]
    fn event_stream_blocked() {
        let resp = build(Some("text/event-stream"));
        assert!(!response_content_type_scannable(&resp));
    }
}
