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

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tracing::{debug, info, warn};

use pingora_core::upstreams::peer::{HttpPeer, Peer};
use pingora_proxy::{FailToProxy, ProxyHttp, Session};

use waf_common::HostConfig;
use waf_common::tier::CachePolicy;
use waf_engine::access::AccessLists;
use waf_engine::device_fp::DeviceFpDetector;
use waf_engine::device_fp::behavior::Recorder as BehaviorRecorder;
use waf_engine::device_fp::capture::ConnCtx as DeviceFpConnCtx;
use waf_engine::relay::RelayDetector;
use waf_engine::{HeaderFilter, WafEngine};

use crate::tiered::TierPolicyRegistry;

use crate::cache::ResponseCache;
use crate::context::{BODY_PREVIEW_LIMIT, ChallengeCtx, GatewayCtx, ResponseCachePending};
use crate::ctx_builder::RequestCtxBuilder;
use crate::error_page::ErrorPageFactory;
use crate::filters::{
    CompiledMask, CompiledRedactor, CompiledScanner, DecoderChain, RequestForwardedHostFilter,
    RequestForwardedProtoFilter, RequestHopByHopFilter, RequestHostPolicyFilter, RequestRealIpFilter, RequestXffFilter,
    ResponseEncoding, ResponseHeaderBlocklistFilter, ResponseLocationRewriter, ResponseServerPolicyFilter,
    ResponseViaStripFilter, apply_body_mask_chunk, apply_body_scan_chunk, apply_redact_chunk, is_json_content_type,
    mask_config_hash, parse_encoding, redactor_config_hash, scanner_config_hash,
};
use crate::pipeline::{AccessGateOutcome, AccessPhaseGate, FilterCtx, RequestFilterChain, ResponseFilterChain};
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
    /// FR-035 outbound header-leak prevention. `None` when disabled by config.
    pub header_filter: Option<Arc<HeaderFilter>>,
    /// Per-protocol counters (AC-22 transparency proof). Shared with the
    /// HTTP/3 listener so QUIC traffic increments the same struct.
    pub proto_counters: Arc<ProtoCounters>,
    /// Ordered chain of upstream request filters (populated by phases 02–04).
    pub request_chain: Arc<RequestFilterChain>,
    /// Ordered chain of response filters (populated by phases 02–03).
    pub response_chain: Arc<ResponseFilterChain>,
    /// AC-17: per-host compiled mask cache, keyed by content hash
    /// `(host_name, xxhash64(internal_patterns, mask_token, body_mask_max_bytes))`
    /// so the allocator reusing a freed `Arc<HostConfig>` address on reload
    /// cannot serve a stale `CompiledMask` to a different host (BL-001).
    /// Bounded via `moka::sync::Cache` (256 entries / 1 h TTL) so config churn
    /// cannot grow the cache without bound.
    pub body_mask_cache: moka::sync::Cache<(String, u64), Arc<CompiledMask>>,
    /// FR-002: tier policy registry. When `None`, every request defaults to
    /// `Tier::CatchAll` + permissive policy (boot-time safety).
    pub tier_registry: Option<Arc<TierPolicyRegistry>>,
    /// FR-008 phase-05: Phase-0 access-list gate. Optional — `None` = every
    /// request continues unconditionally (no whitelist/blacklist enforcement).
    pub access_lists: Option<Arc<AccessPhaseGate>>,
    /// FR-007 phase-06: relay/proxy detector. Optional — `None` = pipeline
    /// behaves exactly as pre-FR-007 (back-compat fast path).
    pub relay_detector: Option<Arc<RelayDetector>>,
    /// FR-010 phase-07: device fingerprint detector. Optional — `None` =
    /// no fingerprinting, no signal emission, no aggregator submit.
    pub device_fp_detector: Option<Arc<DeviceFpDetector>>,
    /// FR-011 phase-02: behavioral anomaly recorder. Optional — `None` =
    /// no per-actor sliding-window state, classifiers downstream see no data.
    pub behavior_recorder: Option<Arc<BehaviorRecorder>>,
    /// FR-009: same `Arc` as the management API — when set, GET responses may
    /// be served from cache and cacheable upstream bodies are stored.
    pub response_cache: Option<Arc<ResponseCache>>,
    /// FR-006 phase-03: challenge context for bot mitigation via `PoW`.
    /// When set, `WafAction::Challenge` renders the JS challenge page.
    /// When unset, Challenge actions fall through as Allow (no-op).
    pub challenge_ctx: Option<Arc<ChallengeCtx>>,
    /// FR-033: per-host compiled scanner cache, keyed by content-hash
    /// `(host_name, xxhash64(body_scan_*))` so config reload doesn't risk
    /// pointer-address reuse bleeding across hosts (red-team #6).
    /// Bounded via `moka::sync::Cache` (max 256 entries, 1 h TTL) so config
    /// churn cannot grow the cache without bound (red-team review H2).
    /// AC-17 / FR-034 caches inherit the same hazard; backport tracked separately.
    pub body_scan_cache: moka::sync::Cache<(String, u64), Arc<CompiledScanner>>,
    /// FR-034: per-host compiled JSON redactor cache. Same content-hashed
    /// keying scheme as `body_mask_cache` (BL-001).
    pub body_redact_cache: moka::sync::Cache<(String, u64), Arc<CompiledRedactor>>,
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
            header_filter: None,
            proto_counters: ProtoCounters::new(),
            request_chain: Arc::new(build_request_chain()),
            response_chain: Arc::new(build_response_chain()),
            body_mask_cache: moka::sync::Cache::builder()
                .max_capacity(256)
                .time_to_live(Duration::from_hours(1))
                .build(),
            tier_registry: None,
            access_lists: None,
            relay_detector: None,
            device_fp_detector: None,
            behavior_recorder: None,
            response_cache: None,
            challenge_ctx: None,
            body_scan_cache: moka::sync::Cache::builder()
                .max_capacity(256)
                .time_to_live(Duration::from_hours(1))
                .build(),
            body_redact_cache: moka::sync::Cache::builder()
                .max_capacity(256)
                .time_to_live(Duration::from_hours(1))
                .build(),
        }
    }

    /// Inject the FR-006 challenge context. When set, `WafAction::Challenge`
    /// decisions render a JS Proof-of-Work page. When unset, Challenge
    /// actions are treated as Allow (fail-open for backward compatibility).
    pub fn with_challenge_ctx(&mut self, ctx: Arc<ChallengeCtx>) {
        self.challenge_ctx = Some(ctx);
    }

    /// Inject the FR-011 behavioral recorder. When set, every request with a
    /// non-empty `FpKey` records one `Sample` after device-fp resolution.
    /// When unset, the recording call is a no-op.
    pub fn with_behavior_recorder(&mut self, recorder: Arc<BehaviorRecorder>) {
        self.behavior_recorder = Some(recorder);
    }

    /// Inject the FR-010 device fingerprint detector. When set, every request
    /// runs `process()` after relay detection so resolved signals reach the
    /// risk aggregator. When unset, no fingerprinting work runs.
    pub fn with_device_fp_detector(&mut self, detector: Arc<DeviceFpDetector>) {
        self.device_fp_detector = Some(detector);
    }

    /// Inject the FR-007 relay/proxy detector. When set, every request runs
    /// detection in `request_filter` and the resolved `ClientIdentity` is
    /// stashed on the gateway context. When unset, the detector is skipped
    /// entirely (no overhead, identical to pre-FR-007 behaviour).
    pub fn with_relay_detector(&mut self, detector: Arc<RelayDetector>) {
        self.relay_detector = Some(detector);
    }

    /// Inject the tier policy registry (FR-002 phase-05). When set, every
    /// `RequestCtx` built by this proxy carries a classified tier instead of
    /// the boot-time `CatchAll` fallback.
    pub fn with_tier_registry(&mut self, registry: Arc<TierPolicyRegistry>) {
        self.tier_registry = Some(registry);
    }

    /// Inject the FR-008 Phase-0 access-list gate. The proxy stores a hot
    /// snapshot reference; phase-06 watcher will swap the `ArcSwap` content on
    /// file change without restart. When unset, no access-list enforcement runs.
    pub fn with_access_lists(&mut self, lists: Arc<ArcSwap<AccessLists>>) {
        self.access_lists = Some(Arc::new(AccessPhaseGate::new(lists)));
    }

    /// Resolve (and lazily compile) the mask config for a given host.
    /// Cache key is `(host_name, xxhash64(internal_patterns, mask_token,
    /// body_mask_max_bytes))` — content-hashed so that an `Arc<HostConfig>`
    /// landing at a previously-freed address on config reload cannot serve a
    /// stale `CompiledMask` from a different host (BL-001).
    fn resolve_mask(&self, hc: &Arc<HostConfig>) -> Arc<CompiledMask> {
        let cfg_hash = mask_config_hash(&hc.internal_patterns, &hc.mask_token, hc.body_mask_max_bytes);
        let key = (hc.host.clone(), cfg_hash);
        if let Some(existing) = self.body_mask_cache.get(&key) {
            return existing;
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

    /// FR-034: resolve (and lazily compile) the JSON field redactor for a
    /// given host. Mirrors `resolve_mask` keying scheme (BL-001).
    fn resolve_redactor(&self, hc: &Arc<HostConfig>) -> Arc<CompiledRedactor> {
        let cfg_hash = redactor_config_hash(hc);
        let key = (hc.host.clone(), cfg_hash);
        if let Some(existing) = self.body_redact_cache.get(&key) {
            return existing;
        }
        let compiled = Arc::new(CompiledRedactor::build(hc));
        self.body_redact_cache.insert(key, Arc::clone(&compiled));
        compiled
    }

    /// Evaluate response-body YAML rules against a response body chunk.
    fn eval_response_body_rules(engine: &Arc<WafEngine>, host_code: &str, host: &str, body: Option<&Bytes>) {
        if let Some(chunk) = body.filter(|c| !c.is_empty()) {
            let text = String::from_utf8_lossy(chunk);
            if let Some(detection) = engine.custom_rules.check_response_body(host_code, &text) {
                tracing::warn!(
                    rule_id = ?detection.rule_id,
                    rule_name = %detection.rule_name,
                    host = %host,
                    "response body rule matched"
                );
            }
        }
    }
}

/// Map a Pingora error to the HTTP status used by [`ErrorPageFactory`].
///
/// Mirrors the default `fail_to_proxy` mapping but lives in gateway code so we
/// can render a neutral body. `0` means "downstream is already gone — do not
/// attempt to write a response."
///
/// FR-039: transport-layer failures (connect timeout, read/write timeout,
/// connection refused, TLS handshake timeout) map to 503 — distinguishes a
/// dead upstream ("WAF is up but backend is unreachable") from an application
/// error ("backend replied but with 5xx"). The plain `502` we previously
/// returned conflated the two.
fn error_to_status(e: &pingora_core::Error) -> u16 {
    use pingora_core::{ErrorSource, ErrorType};
    if let ErrorType::HTTPStatus(code) = e.etype() {
        return *code;
    }
    // FR-039: transport-layer "backend unresponsive" → 503.
    if is_transport_unresponsive(e.etype()) {
        return 503;
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

/// FR-039: classify whether an [`ErrorType`] indicates the upstream is
/// unresponsive (no reply within the configured deadline OR refused
/// connection). Pure, exhaustive on the timeout/connect family.
const fn is_transport_unresponsive(et: &pingora_core::ErrorType) -> bool {
    use pingora_core::ErrorType;
    matches!(
        et,
        ErrorType::ConnectTimedout
            | ErrorType::ConnectRefused
            | ErrorType::ConnectNoRoute
            | ErrorType::ConnectError
            | ErrorType::ConnectProxyFailure
            | ErrorType::TLSHandshakeTimedout
            | ErrorType::ReadTimedout
            | ErrorType::WriteTimedout
    )
}

/// FR-039: copy the per-host upstream timeouts into the Pingora [`HttpPeer`]
/// options. Pulled out of `upstream_peer()` so unit tests can verify the
/// mapping without spinning up a full Pingora `Server`.
pub(crate) const fn apply_fr039_timeouts(peer: &mut HttpPeer, host_config: &HostConfig) {
    peer.options.connection_timeout = Some(Duration::from_millis(host_config.upstream_connect_timeout_ms));
    peer.options.total_connection_timeout =
        Some(Duration::from_millis(host_config.upstream_total_connection_timeout_ms));
    peer.options.read_timeout = Some(Duration::from_millis(host_config.upstream_read_timeout_ms));
    peer.options.write_timeout = Some(Duration::from_millis(host_config.upstream_write_timeout_ms));
    peer.options.idle_timeout = Some(Duration::from_millis(host_config.upstream_idle_timeout_ms));
}

/// Apply per-host upstream ALPN and TLS verification settings to the Pingora peer.
///
/// Set the upstream ALPN advertisement on `peer` from [`HostConfig`].
///
/// No-op when `ssl: false` — ALPN only applies inside a TLS ClientHello.
/// Maps [`waf_common::UpstreamAlpn`] → Pingora's [`pingora_core::protocols::ALPN`].
pub(crate) fn apply_upstream_alpn(peer: &mut HttpPeer, host_config: &HostConfig) {
    if !host_config.ssl {
        return;
    }
    use pingora_core::protocols::ALPN;
    use waf_common::UpstreamAlpn;
    peer.options.alpn = match host_config.upstream_alpn {
        UpstreamAlpn::H1Only => ALPN::H1,
        UpstreamAlpn::H2H1 => ALPN::H2H1,
        UpstreamAlpn::H2Only => ALPN::H2,
    };
    debug!(
        host = %host_config.host,
        alpn = ?host_config.upstream_alpn,
        "upstream ALPN set"
    );
}

/// Apply TLS certificate-verification flags from [`HostConfig`] to `peer`.
///
/// No-op when `ssl: false`. When `upstream_skip_ssl_verify` is `true`, both
/// `verify_cert` and `verify_hostname` are disabled and a **WARN** is emitted
/// — skipping verification leaves the connection MITM-vulnerable and must
/// never be used in production without a deliberate, documented reason.
pub(crate) fn apply_upstream_tls_verify(peer: &mut HttpPeer, host_config: &HostConfig) {
    if !host_config.ssl || !host_config.upstream_skip_ssl_verify {
        return;
    }
    peer.options.verify_cert = false;
    peer.options.verify_hostname = false;
    warn!(
        host = %host_config.host,
        "upstream TLS certificate verification DISABLED — connection is MITM-vulnerable; \
         only use for self-signed certs in controlled environments"
    );
}

/// FR-033: gate the body content scanner on a Content-Type allowlist so we
/// never corrupt gRPC trailers, server-sent event streams, or arbitrary
/// binary payloads. Allowed: textual + JSON / XML / JS bodies.
fn response_content_type_scannable(resp: &pingora_http::ResponseHeader) -> bool {
    let Some(ct) = resp.headers.get("content-type").and_then(|v| v.to_str().ok()) else {
        // No Content-Type → assume scannable (matches AC-17's permissive shape).
        return true;
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
        let mut peer = HttpPeer::new(&upstream_addr, use_tls, host_config.remote_host.clone());
        apply_fr039_timeouts(&mut peer, &host_config);
        apply_upstream_alpn(&mut peer, &host_config);
        apply_upstream_tls_verify(&mut peer, &host_config);
        Ok(Box::new(peer))
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut GatewayCtx) -> pingora_core::Result<bool> {
        // AC-22: tag protocol once and bump the per-protocol counter so every
        // request through the Pingora listener (H1/H2/WS-upgrade) is accounted
        // for. H3 traffic increments the same struct from `http3.rs`.
        ctx.protocol = detect_from_session(session);
        self.proto_counters.record(ctx.protocol);

        // FR-007 phase-06: run relay/proxy detection BEFORE building the
        // request ctx so the resolved `real_ip` can override the raw peer/XFF
        // value used by FR-008 + downstream WAF checks. When the detector is
        // unset, this block is skipped and the pipeline behaves exactly as
        // pre-FR-007 (no-op fast path).
        if let Some(detector) = &self.relay_detector
            && ctx.client_identity.is_none()
        {
            let peer_ip = session.client_addr().and_then(|a| a.as_inet()).map_or_else(
                || std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                std::net::SocketAddr::ip,
            );
            ctx.client_identity = Some(detector.evaluate(peer_ip, &session.req_header().headers));
        }

        // FR-010 phase-07: device fingerprint pipeline. Runs after relay
        // detection so it can use the validated `real_ip`. L4 capture
        // wiring (TLS/h2 inspectors → ConnCtx) lands in a later phase;
        // until then `process()` operates on an empty `ConnCtx`, producing
        // an empty FpKey but still dispatching UA-only providers.
        if let Some(detector) = &self.device_fp_detector
            && ctx.device_identity.is_none()
        {
            let peer_ip = ctx.client_identity.as_ref().map_or_else(
                || {
                    session.client_addr().and_then(|a| a.as_inet()).map_or(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        std::net::SocketAddr::ip,
                    )
                },
                |id| id.real_ip,
            );
            let ua = session
                .get_header("user-agent")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                .unwrap_or("");
            let conn = DeviceFpConnCtx::new();
            ctx.device_identity = Some(detector.process(peer_ip, ua, &conn).await);
        }

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
                let mut built = builder.build();
                // FR-007 → FR-008 handover: when the detector resolved a
                // validated `real_ip`, prefer it over the builder's XFF-based
                // extraction. Detector validates trusted-proxy chain + spoof
                // signals; raw XFF parsing in the builder does not.
                if let Some(id) = &ctx.client_identity {
                    built.client_ip = id.real_ip;
                }
                ctx.request_ctx = Some(built);
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

        // FR-011 phase-02 — record one behavioral sample per request. Skipped
        // when no fingerprint resolved (empty FpKey) or no recorder injected.
        // Phase 4 also forwards `Sec-Purpose: prefetch` so the
        // missing_referer classifier can exempt browser-prefetched navs.
        if let Some(device) = ctx.device_identity.as_ref() {
            let had_referer = session.get_header("referer").is_some();
            let had_prefetch_hint = session
                .get_header("sec-purpose")
                .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("prefetch")));
            crate::behavior_record::record_sample(
                self.behavior_recorder.as_ref(),
                &device.key,
                &request_ctx.path,
                had_referer,
                had_prefetch_hint,
                request_ctx.tier,
            );
        }

        // FR-008 phase-05 — Phase-0 access-list gate runs *before* the WAF
        // engine. peer_ip is the immediate TCP peer (XFF/real-ip rewrites are
        // upstream-bound and run later in upstream_request_filter).
        if let Some(gate) = &self.access_lists {
            // FR-007 → FR-008 handover: prefer detector-validated `real_ip`
            // over raw TCP peer. Falls back to peer when the detector is
            // unset, preserving pre-FR-007 semantics.
            let access_ip = ctx.client_identity.as_ref().map_or_else(
                || {
                    session
                        .client_addr()
                        .and_then(|a| a.as_inet())
                        .map_or(request_ctx.client_ip, std::net::SocketAddr::ip)
                },
                |id| id.real_ip,
            );
            match gate.evaluate(&request_ctx.host, access_ip, request_ctx.tier) {
                AccessGateOutcome::Continue => {}
                AccessGateOutcome::Bypass => {
                    ctx.access_bypass = true;
                }
                AccessGateOutcome::Block(status) => {
                    self.blocked_counter.fetch_add(1, Ordering::Relaxed);
                    let accept = session
                        .get_header("accept")
                        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
                        .map(str::to_string);
                    let (headers, body) = ErrorPageFactory::render(status, accept.as_deref())?;
                    session.write_response_header(Box::new(headers), false).await?;
                    session.write_response_body(Some(body), true).await?;
                    return Ok(true);
                }
            }
        }

        // Whitelist full-bypass skips the WAF engine entirely (D6 fast path).
        if ctx.access_bypass {
            return Ok(false);
        }

        let decision = self.engine.inspect(&mut request_ctx).await;
        if write_waf_decision(
            session,
            &decision,
            &request_ctx,
            &self.blocked_counter,
            self.challenge_ctx.as_ref(),
        )
        .await?
        {
            return Ok(true);
        }

        if let Some(cache) = &self.response_cache
            && request_ctx.method.eq_ignore_ascii_case("GET")
            && !matches!(request_ctx.tier_policy.cache_policy, CachePolicy::NoCache)
            && !request_ctx.headers.contains_key("authorization")
            && request_ctx.cookies.is_empty()
        {
            let key = ResponseCache::make_key(
                &request_ctx.method,
                &request_ctx.host,
                &request_ctx.path,
                &request_ctx.query,
            );
            if let Some(entry) = cache.get(&key, request_ctx.tier).await {
                crate::response_cache_integration::write_cached_entry(session, &entry).await?;
                return Ok(true);
            }
            ctx.response_cache_store = Some(ResponseCachePending {
                key,
                host: request_ctx.host.clone(),
                path: request_ctx.path.clone(),
                tier: request_ctx.tier,
                cache_policy: request_ctx.tier_policy.cache_policy.clone(),
                has_authorization: false,
                has_cookie: false,
                status: 0,
                headers: Vec::new(),
                cache_control: None,
                body: BytesMut::new(),
                capture_started: false,
            });
        }

        Ok(false)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut GatewayCtx,
    ) -> pingora_core::Result<()> {
        if ctx.body_inspected || ctx.access_bypass {
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
        let upstream_contacted = ctx.upstream_addr.is_some();
        if let (Some(req_ctx), Some(hc)) = (&ctx.request_ctx, &ctx.host_config) {
            // FR-018: brute-force / credential-stuffing dispatch. Engine state
            // advances on every upstream response status; the actual block
            // decision surfaces at the next request via request-time check.
            // Gated on `upstream_contacted` so self-generated WAF block pages
            // (request-time 403/401) cannot poison BF counters.
            if upstream_contacted {
                self.engine.on_response(req_ctx, upstream_response.status.as_u16());
            }
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

            // FR-034: decide whether JSON field redaction will run. Conditions:
            //   * identity Content-Encoding (reuse the boolean above)
            //   * Content-Type is application/json or application/*+json
            //   * Compiled redactor is non-noop for this host
            let redactor = self.resolve_redactor(hc);
            if !redactor.is_noop() {
                if identity {
                    let ct_is_json = upstream_response
                        .headers
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(is_json_content_type);
                    if ct_is_json {
                        ctx.body_redact.enabled = true;
                        // Length will mismatch; AC-17 may already have removed.
                        let _ = upstream_response.remove_header("content-length");
                    }
                } else {
                    debug!("json-redact: skipping non-identity content-encoding");
                }
            }
        }

        // FR-035 — global outbound header-leak safety net.  Runs after the
        // host's `response_chain` so per-host transforms get first say, then
        // this catches vendor/CVE-attributed fingerprints and PII leaks the
        // operator did not enumerate manually.  No-op when disabled.
        if let Some(filter) = self.header_filter.as_ref() {
            let mut to_remove: Vec<String> = Vec::new();
            for (name, value) in &upstream_response.headers {
                let name_str = name.as_str();
                if filter.should_strip(name_str) {
                    to_remove.push(name_str.to_string());
                    continue;
                }
                if let Ok(val_str) = std::str::from_utf8(value.as_bytes())
                    && filter.detect_pii_in_value(val_str).is_some()
                {
                    to_remove.push(name_str.to_string());
                }
            }
            if !to_remove.is_empty() {
                for name in &to_remove {
                    upstream_response.remove_header(name.as_str());
                }
                debug!("Outbound: stripped {} response header(s)", to_remove.len());
            }
        }

        // Cache capture reads `Content-Encoding` from the same header map Pingora will
        // stream (after response_chain above when host config exists), so misses without
        // host context still observe identity/absent CE correctly.
        if let Some(pending) = ctx.response_cache_store.as_mut()
            && !crate::response_cache_integration::begin_upstream_cache_capture(
                pending,
                upstream_response,
                ctx.body_mask.enabled,
            )
        {
            ctx.response_cache_store = None;
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
        // Body mutation (scan/redact/mask) and response cache are mutually
        // exclusive *by design*: mutation rewrites bytes in place (length
        // differs from match length → chunked encoding) so the bytes streamed
        // downstream are NOT what the cache would replay. `response_filter`
        // enforces the contract by passing `body_mask_enabled` into
        // `begin_upstream_cache_capture`, which short-circuits and clears
        // `ctx.response_cache_store` to `None`.
        if ctx.body_scan.enabled || ctx.body_redact.enabled || ctx.body_mask.enabled {
            let Some(hc) = ctx.host_config.clone() else {
                return Ok(None);
            };

            // FR-033 runs FIRST so FR-034 + AC-17 see plaintext.
            if ctx.body_scan.enabled {
                let scanner = self.resolve_scanner(&hc);
                let host_label: &str = hc.host.as_str();
                apply_body_scan_chunk(&mut ctx.body_scan, &scanner, body, end_of_stream, host_label);
            }

            // Response-body YAML rules on (post-decompression) plaintext.
            Self::eval_response_body_rules(&self.engine, &hc.code, &hc.host, body.as_ref());

            // FR-034: buffers JSON, sets *body = None until EOS or cap; emits
            // redacted full body. AC-17 then runs over it as a single chunk.
            if ctx.body_redact.enabled {
                let redactor = self.resolve_redactor(&hc);
                apply_redact_chunk(&mut ctx.body_redact, &redactor, body, end_of_stream);
            }

            // AC-17 — operator regex masker on (now-plaintext, redacted) bytes.
            if ctx.body_mask.enabled {
                let compiled = self.resolve_mask(&hc);
                apply_body_mask_chunk(&mut ctx.body_mask, &compiled, body, end_of_stream);
            }
            return Ok(None);
        }

        // Response-body YAML rules: fire independently when body_scan/redact/mask
        // are all disabled, so hosts with response_body rules still get coverage.
        if let Some(hc) = ctx.host_config.as_ref() {
            Self::eval_response_body_rules(&self.engine, &hc.code, &hc.host, body.as_ref());
        }

        if let Some(cache) = &self.response_cache {
            crate::response_cache_integration::cache_store_on_body_chunk(
                cache,
                &mut ctx.response_cache_store,
                body,
                end_of_stream,
            );
        }

        Ok(None)
    }

    /// FR-039: upstream connect failed (timeout, refused, no route, TLS
    /// handshake timed out). We never call `e.set_retry(true)` — retrying a
    /// timed-out upstream is exactly the hang FR-039 forbids. Falling through
    /// to `fail_to_proxy()` lets `error_to_status()` map this to 503.
    fn fail_to_connect(
        &self,
        _session: &mut Session,
        peer: &HttpPeer,
        _ctx: &mut Self::CTX,
        e: Box<pingora_core::Error>,
    ) -> Box<pingora_core::Error> {
        if is_transport_unresponsive(e.etype()) {
            warn!(
                upstream = peer.address().to_string(),
                err = ?e.etype(),
                "FR-039: upstream unresponsive; emitting 503 (no retry)",
            );
        }
        e
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
mod fr039_tests {
    //! FR-039 unit tests — pure-function level. Verify the timeout
    //! mapping and the transport-error classification without spinning
    //! up a Pingora server. End-to-end behaviour (hang backend → 503
    //! within deadline) is covered by Phase 4 Docker e2e.
    use super::*;
    use pingora_core::ErrorType;

    // ── apply_fr039_timeouts ────────────────────────────────────────────────

    #[test]
    fn timeouts_copied_from_host_config_default() {
        let hc = HostConfig::default();
        let mut peer = HttpPeer::new("127.0.0.1:8080", false, "test".into());
        apply_fr039_timeouts(&mut peer, &hc);
        assert_eq!(peer.options.connection_timeout, Some(Duration::from_secs(5)));
        assert_eq!(peer.options.total_connection_timeout, Some(Duration::from_secs(10)));
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(30)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(10)));
        assert_eq!(peer.options.idle_timeout, Some(Duration::from_mins(1)));
    }

    #[test]
    fn timeouts_copied_from_host_config_custom() {
        let hc = HostConfig {
            upstream_connect_timeout_ms: 1_500,
            upstream_total_connection_timeout_ms: 3_000,
            upstream_read_timeout_ms: 7_500,
            upstream_write_timeout_ms: 4_000,
            upstream_idle_timeout_ms: 45_000,
            ..HostConfig::default()
        };
        let mut peer = HttpPeer::new("127.0.0.1:8080", true, "test".into());
        apply_fr039_timeouts(&mut peer, &hc);
        assert_eq!(peer.options.connection_timeout, Some(Duration::from_millis(1_500)));
        assert_eq!(peer.options.total_connection_timeout, Some(Duration::from_secs(3)));
        assert_eq!(peer.options.read_timeout, Some(Duration::from_millis(7_500)));
        assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(4)));
        assert_eq!(peer.options.idle_timeout, Some(Duration::from_secs(45)));
    }

    #[test]
    fn timeouts_overwrite_pre_existing_options() {
        let hc = HostConfig::default();
        let mut peer = HttpPeer::new("127.0.0.1:8080", false, "test".into());
        // Simulate a pre-populated peer (e.g., another filter set defaults).
        peer.options.read_timeout = Some(Duration::from_millis(1));
        apply_fr039_timeouts(&mut peer, &hc);
        // FR-039 values win.
        assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(30)));
    }

    // ── is_transport_unresponsive ───────────────────────────────────────────

    fn transport_unresponsive_set() -> [ErrorType; 8] {
        [
            ErrorType::ConnectTimedout,
            ErrorType::ConnectRefused,
            ErrorType::ConnectNoRoute,
            ErrorType::ConnectError,
            ErrorType::ConnectProxyFailure,
            ErrorType::TLSHandshakeTimedout,
            ErrorType::ReadTimedout,
            ErrorType::WriteTimedout,
        ]
    }

    fn non_transport_set() -> [ErrorType; 10] {
        [
            ErrorType::HTTPStatus(500),
            ErrorType::HTTPStatus(502),
            ErrorType::InvalidHTTPHeader,
            ErrorType::H1Error,
            ErrorType::H2Error,
            ErrorType::ReadError,
            ErrorType::WriteError,
            ErrorType::ConnectionClosed,
            ErrorType::InternalError,
            ErrorType::UnknownError,
        ]
    }

    #[test]
    fn is_transport_unresponsive_yes() {
        for et in transport_unresponsive_set() {
            assert!(
                is_transport_unresponsive(&et),
                "expected `{et:?}` to classify as transport-unresponsive"
            );
        }
    }

    #[test]
    fn is_transport_unresponsive_no() {
        for et in non_transport_set() {
            assert!(
                !is_transport_unresponsive(&et),
                "did NOT expect `{et:?}` to classify as transport-unresponsive"
            );
        }
    }

    // ── error_to_status ─────────────────────────────────────────────────────

    #[test]
    fn http_status_passthrough() {
        // Explicit HTTPStatus(n) must return n directly (e.g. WAF block 403).
        for code in [400u16, 403, 404, 413, 500, 502, 504] {
            let e = pingora_core::Error::new(ErrorType::HTTPStatus(code));
            assert_eq!(error_to_status(&e), code, "HTTPStatus({code}) should pass through");
        }
    }

    #[test]
    fn transport_errors_map_to_503() {
        // FR-039: every whitelisted transport variant maps to 503, regardless
        // of esource. We test with Unset (Error::new) and Upstream (new_up)
        // — both must hit the FR-039 branch *before* the esource match.
        for et in transport_unresponsive_set() {
            let e = pingora_core::Error::new(et.clone());
            assert_eq!(error_to_status(&e), 503, "FR-039: `{et:?}` (unset) → 503");
            let e = pingora_core::Error::new_up(et.clone());
            assert_eq!(error_to_status(&e), 503, "FR-039: `{et:?}` (upstream) → 503");
        }
    }

    #[test]
    fn non_transport_upstream_errors_still_502() {
        // Application-side or framing errors that come from the upstream
        // direction stay 502 — we did not regress the pre-FR-039 behaviour.
        let e = pingora_core::Error::new_up(ErrorType::InvalidHTTPHeader);
        assert_eq!(error_to_status(&e), 502);
        let e = pingora_core::Error::new_up(ErrorType::H1Error);
        assert_eq!(error_to_status(&e), 502);
        let e = pingora_core::Error::new_up(ErrorType::H2Error);
        assert_eq!(error_to_status(&e), 502);
    }

    #[test]
    fn downstream_io_returns_zero() {
        // Original behaviour: when the downstream socket is already gone we
        // must not try to write a response. Sentinel value 0 means
        // "skip response write".
        for et in [ErrorType::WriteError, ErrorType::ReadError, ErrorType::ConnectionClosed] {
            let e = pingora_core::Error::new_down(et.clone());
            assert_eq!(error_to_status(&e), 0, "{et:?} downstream → 0 sentinel");
        }
    }

    #[test]
    fn downstream_other_returns_400() {
        // Downstream errors that aren't the closed-socket sentinels map to 400.
        let e = pingora_core::Error::new_down(ErrorType::InvalidHTTPHeader);
        assert_eq!(error_to_status(&e), 400);
    }

    #[test]
    fn internal_unspecified_returns_500() {
        let e = pingora_core::Error::new_in(ErrorType::InternalError);
        assert_eq!(error_to_status(&e), 500);
        let e = pingora_core::Error::new_in(ErrorType::UnknownError);
        assert_eq!(error_to_status(&e), 500);
        // Unset source on a non-transport error falls into the same Internal arm.
        let e = pingora_core::Error::new(ErrorType::UnknownError);
        assert_eq!(error_to_status(&e), 500);
    }

    // ── retry-after header round-trip via ErrorPageFactory ───────────────────

    #[test]
    fn retry_after_present_on_503_only() {
        use crate::error_page::ErrorPageFactory;
        use http::HeaderValue;
        let (h, _) = ErrorPageFactory::render(503, None).expect("render 503");
        assert_eq!(
            h.headers.get("retry-after").map(HeaderValue::as_bytes),
            Some(b"5".as_slice())
        );

        let (h, _) = ErrorPageFactory::render(502, None).expect("render 502");
        assert!(
            h.headers.get("retry-after").is_none(),
            "Retry-After must NOT be set on non-503"
        );

        let (h, _) = ErrorPageFactory::render(403, None).expect("render 403");
        assert!(h.headers.get("retry-after").is_none());
    }
}

#[cfg(test)]
mod alpn_tests {
    use super::*;
    use pingora_core::protocols::ALPN;
    use waf_common::UpstreamAlpn;

    fn ssl_peer() -> HttpPeer {
        // Use a numeric address to avoid DNS resolution in unit tests.
        HttpPeer::new("127.0.0.1:443", true, "upstream".into())
    }

    // ── apply_upstream_alpn ──────────────────────────────────────────────────

    #[test]
    fn ssl_false_is_noop() {
        let mut p = ssl_peer();
        let before = p.options.alpn.clone();
        let hc = HostConfig {
            ssl: false,
            upstream_alpn: UpstreamAlpn::H2Only,
            ..HostConfig::default()
        };
        apply_upstream_alpn(&mut p, &hc);
        assert_eq!(p.options.alpn, before, "must not touch ALPN when TLS is off");
    }

    #[test]
    fn h2h1_advertises_both() {
        let mut p = ssl_peer();
        let hc = HostConfig {
            ssl: true,
            upstream_alpn: UpstreamAlpn::H2H1,
            ..HostConfig::default()
        };
        apply_upstream_alpn(&mut p, &hc);
        assert!(matches!(p.options.alpn, ALPN::H2H1));
    }

    #[test]
    fn h1_only() {
        let mut p = ssl_peer();
        let hc = HostConfig {
            ssl: true,
            upstream_alpn: UpstreamAlpn::H1Only,
            ..HostConfig::default()
        };
        apply_upstream_alpn(&mut p, &hc);
        assert!(matches!(p.options.alpn, ALPN::H1));
    }

    #[test]
    fn h2_only() {
        let mut p = ssl_peer();
        let hc = HostConfig {
            ssl: true,
            upstream_alpn: UpstreamAlpn::H2Only,
            ..HostConfig::default()
        };
        apply_upstream_alpn(&mut p, &hc);
        assert!(matches!(p.options.alpn, ALPN::H2));
    }

    // ── apply_upstream_tls_verify ────────────────────────────────────────────

    #[test]
    fn skip_ssl_verify_disables_both_checks() {
        let mut p = ssl_peer();
        let hc = HostConfig {
            ssl: true,
            upstream_skip_ssl_verify: true,
            ..HostConfig::default()
        };
        apply_upstream_tls_verify(&mut p, &hc);
        assert!(!p.options.verify_cert, "verify_cert must be false when skip=true");
        assert!(
            !p.options.verify_hostname,
            "verify_hostname must be false when skip=true"
        );
    }

    #[test]
    fn skip_ssl_verify_default_false_preserves_verify() {
        let mut p = ssl_peer();
        let hc = HostConfig {
            ssl: true,
            upstream_skip_ssl_verify: false,
            ..HostConfig::default()
        };
        apply_upstream_tls_verify(&mut p, &hc);
        assert!(p.options.verify_cert, "verify_cert must remain true when skip=false");
        assert!(
            p.options.verify_hostname,
            "verify_hostname must remain true when skip=false"
        );
    }

    #[test]
    fn skip_ssl_verify_noop_when_ssl_off() {
        let mut p = ssl_peer();
        // Capture Pingora's baseline before the call so the assertion stays
        // correct even if future Pingora versions change the default.
        let before_cert = p.options.verify_cert;
        let before_hostname = p.options.verify_hostname;
        // Even with skip=true, ssl=false means no TLS — flags must be untouched.
        let hc = HostConfig {
            ssl: false,
            upstream_skip_ssl_verify: true,
            ..HostConfig::default()
        };
        apply_upstream_tls_verify(&mut p, &hc);
        assert_eq!(
            p.options.verify_cert, before_cert,
            "must not touch verify_cert when ssl=false"
        );
        assert_eq!(
            p.options.verify_hostname, before_hostname,
            "must not touch verify_hostname when ssl=false"
        );
    }
}
