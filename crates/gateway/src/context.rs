use std::sync::Arc;

use bytes::BytesMut;
use waf_common::tier::{CachePolicy, Tier};
use waf_common::{HostConfig, RequestCtx};
use waf_engine::challenge::{ChallengeRenderer, DifficultyMap, JsChallengeRenderer};
use waf_engine::device_fp::DeviceIdentity;
use waf_engine::relay::ClientIdentity;
use waf_engine::risk::{ChallengeIssuer, ChallengeVerifier};

use crate::filters::BodyRedactState;
use crate::filters::response_body_decompressor::DecoderChain;
use crate::protocol::Protocol;
use crate::waf_observability_headers::CacheStatus;

/// Lightweight per-request snapshot of WAF decision metadata reachable from
/// every egress path (`response_filter`, cache HIT writer, error pages).
///
/// Avoids cloning the heavy `DetectionResult` from `WafDecision` and provides
/// safe defaults: `action == "allow"` (NEVER `""`) so passthrough / fast-path
/// outcomes that never call `engine.inspect()` still emit a contract-legal
/// `X-WAF-Action` header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WafDecisionMeta {
    /// Contract action string (e.g. `"allow"`, `"block"`, `"challenge"`).
    /// Sourced from `WafAction::as_contract_str()` — always `'static` lifetime.
    pub action: &'static str,
    /// Cumulative risk score, clamped to `0..=100`.
    pub risk_score: u8,
    /// Originating rule id; `None` on allow (no allocation). Mapped to the
    /// contract literal `"none"` at injection time.
    pub rule_id: Option<String>,
    /// Enforcement mode contract string (`"enforce"` or `"log_only"`).
    pub mode: &'static str,
}

impl Default for WafDecisionMeta {
    fn default() -> Self {
        Self {
            action: "allow",
            risk_score: 0,
            rule_id: None,
            mode: "enforce",
        }
    }
}

impl WafDecisionMeta {
    /// Build a snapshot from a `WafDecision`. Allocates a `String` for `rule_id`
    /// only when the decision carries one (Allow paths stay alloc-free).
    #[must_use]
    pub fn from_decision(decision: &waf_common::WafDecision) -> Self {
        Self {
            action: decision.action.as_contract_str(),
            risk_score: decision.risk_score.min(100),
            rule_id: decision.rule_id.clone(),
            mode: decision.mode.as_contract_str(),
        }
    }
}

/// FR-006 Phase 3: Challenge context holding issuer, verifier, and renderer.
/// Initialized once per `WafProxy` and shared across all requests.
pub struct ChallengeCtx {
    pub issuer: Arc<ChallengeIssuer>,
    pub verifier: Arc<ChallengeVerifier>,
    pub renderer: Arc<dyn ChallengeRenderer>,
    pub difficulty_map: DifficultyMap,
    pub config: ChallengePageConfig,
}

/// Configurable branding for the challenge page.
#[derive(Debug, Clone)]
pub struct ChallengePageConfig {
    pub branding_title: String,
    pub branding_message: String,
}

impl Default for ChallengePageConfig {
    fn default() -> Self {
        Self {
            branding_title: "Security Check".into(),
            branding_message: "Please wait while we verify your browser...".into(),
        }
    }
}

impl ChallengeCtx {
    /// Create a new challenge context with the given issuer and verifier.
    #[must_use]
    pub fn new(issuer: Arc<ChallengeIssuer>, verifier: Arc<ChallengeVerifier>) -> Self {
        Self {
            issuer,
            verifier,
            renderer: Arc::new(JsChallengeRenderer::new()),
            difficulty_map: DifficultyMap::default(),
            config: ChallengePageConfig::default(),
        }
    }

    /// Set a custom renderer (for testing or alternative challenge types).
    #[must_use]
    pub fn with_renderer(mut self, renderer: Arc<dyn ChallengeRenderer>) -> Self {
        self.renderer = renderer;
        self
    }

    /// Set a custom difficulty map.
    #[must_use]
    pub fn with_difficulty_map(mut self, map: DifficultyMap) -> Self {
        self.difficulty_map = map;
        self
    }

    /// Set custom branding config.
    #[must_use]
    pub fn with_config(mut self, config: ChallengePageConfig) -> Self {
        self.config = config;
        self
    }
}

/// Maximum request body bytes buffered for WAF inspection (64 KiB).
pub const BODY_PREVIEW_LIMIT: usize = 64 * 1024;

/// Maximum bytes buffered from upstream for response caching.
pub const RESPONSE_CACHE_BODY_LIMIT: usize = 2 * 1024 * 1024;

/// FR-009: state for deferred `ResponseCache::put` after the upstream body completes.
pub struct ResponseCachePending {
    pub key: String,
    pub host: String,
    pub path: String,
    pub tier: Tier,
    pub cache_policy: CachePolicy,
    pub has_authorization: bool,
    pub has_cookie: bool,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub cache_control: Option<String>,
    pub body: BytesMut,
    /// Set in `response_filter` once headers are snapshotted and buffering is allowed.
    pub capture_started: bool,
}

/// Per-request state stored in the Pingora session context
#[derive(Default)]
pub struct GatewayCtx {
    /// Built `RequestCtx` for WAF pipeline
    pub request_ctx: Option<RequestCtx>,
    /// Resolved upstream address (host:port)
    pub upstream_addr: Option<String>,
    /// Matched host config
    pub host_config: Option<Arc<HostConfig>>,
    /// Accumulates the first [`BODY_PREVIEW_LIMIT`] bytes of the request body
    /// for WAF body inspection in `request_body_filter`.
    pub body_buf: BytesMut,
    /// Set to `true` once the body WAF check has been performed so we only
    /// inspect once (on the first chunk that completes the preview or at EOS).
    pub body_inspected: bool,
    /// AC-17: streaming state for the response body internal-ref masker.
    pub body_mask: BodyMaskState,
    /// FR-033: streaming state for the response body content scanner.
    pub body_scan: BodyScanState,
    /// FR-034: streaming state for the JSON field redactor. Composes with
    /// `body_mask` — when both are enabled, `body_redact` runs first and the
    /// AC-17 mask runs over the redacted output (see
    /// `proxy::WafProxy::response_body_filter`).
    pub body_redact: BodyRedactState,
    /// Phase-05: wire protocol detected at session start. Tagged once in
    /// `request_filter` and consumed for per-protocol observability.
    pub protocol: Protocol,
    /// FR-008 phase-05: set by the Phase-0 access gate when an IP whitelist hit
    /// resolves to `full_bypass` for the request's tier. When `true`, the WAF
    /// engine `inspect()` call is skipped (whitelist trust → fast path).
    pub access_bypass: bool,
    /// FR-007 phase-06: validated client identity from the relay/proxy detector.
    /// `None` when the detector is not configured (back-compat) or before the
    /// `request_filter` phase has run. Downstream phases prefer
    /// `client_identity.real_ip` over the raw TCP peer when present.
    pub client_identity: Option<ClientIdentity>,
    /// FR-010 phase-07: resolved device fingerprint identity. `None` when the
    /// detector is not configured or before `request_filter` has run.
    pub device_identity: Option<DeviceIdentity>,
    /// FR-009: buffer a cacheable upstream response for [`crate::cache::ResponseCache::put`].
    pub response_cache_store: Option<ResponseCachePending>,
    /// Snapshot of the WAF decision metadata, set by `request_filter` on every
    /// outcome (block, allow, challenge, access-bypass fast-path) so downstream
    /// egress paths and `response_filter` can emit the contract observability
    /// headers without reaching back into the engine.
    pub waf_decision_meta: Option<WafDecisionMeta>,
    /// Source value for the `X-WAF-Cache` response header. Defaults to
    /// `Bypass` (fail-safe — never falsely advertise HIT). `request_filter`
    /// upgrades to `Hit`/`Miss` only on the allow path; non-allow outcomes
    /// must never report a cache-clean origin response.
    pub cache_status: CacheStatus,
}

/// Per-response state for the streaming body masker (AC-17).
///
/// `enabled` is decided in `response_filter` once the upstream `Content-Encoding`
/// is known. Compressed bodies bypass masking entirely (FR-001 scope).
#[derive(Default)]
pub struct BodyMaskState {
    /// Whether masking should run for this response (set in `response_filter`).
    pub enabled: bool,
    /// Tail bytes of the prior chunk preserved to handle pattern straddle.
    pub tail: BytesMut,
    /// Total bytes scanned so far. Beyond [`HostConfig::body_mask_max_bytes`]
    /// the rest of the response is forwarded unchanged.
    pub processed: u64,
    /// `true` once the byte ceiling was hit; used to log a single warning.
    pub ceiling_logged: bool,
}

/// Per-response state for the FR-033 streaming content scanner.
///
/// Lives next to [`BodyMaskState`] in [`GatewayCtx`]; the two are independent
/// (each layer reads its own enable flag) but share the body-filter callback.
#[derive(Default)]
pub struct BodyScanState {
    /// Whether the FR-033 scanner is active for this response. Set in
    /// `response_filter` after Content-Type allowlist + Content-Encoding probe.
    pub enabled: bool,
    /// gzip decoder when the upstream sent `Content-Encoding: gzip`. `None`
    /// for identity bodies.
    pub decoder: Option<DecoderChain>,
    /// Total plaintext bytes scanned so far. Beyond
    /// [`HostConfig::body_scan_max_body_bytes`] the rest of the response is
    /// forwarded unchanged.
    pub processed: u64,
    /// Inter-chunk straddle buffer.
    pub tail: BytesMut,
    /// Set on decode error / bomb / cap; subsequent chunks short-circuit.
    pub failed: bool,
    /// `true` once the byte ceiling was hit; used to log a single warning.
    pub ceiling_logged: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;
    use std::net::{IpAddr, Ipv4Addr};
    use waf_engine::relay::RelayDetector;

    // Pingora's `ProxyHttp::CTX` bound requires `Send`. If a future field on
    // BodyScanState (e.g. a non-Send Mutex) breaks this, fail at compile time.
    static_assertions::assert_impl_all!(BodyScanState: Send);
    static_assertions::assert_impl_all!(GatewayCtx: Send);

    #[test]
    fn default_client_identity_is_none() {
        let ctx = GatewayCtx::default();
        assert!(ctx.client_identity.is_none());
    }

    #[test]
    fn detector_eval_populates_identity_with_peer_as_real_ip() {
        // FR-007 phase-06: when no XFF and no providers (empty detector),
        // `real_ip` falls back to the TCP peer. Verifies the wiring contract
        // gateway relies on for FR-008 handover.
        let detector = RelayDetector::empty();
        let peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let id = detector.evaluate(peer, &HeaderMap::new());
        assert_eq!(id.real_ip, peer);

        let ctx = GatewayCtx {
            client_identity: Some(id),
            ..GatewayCtx::default()
        };
        assert_eq!(ctx.client_identity.as_ref().expect("set above").real_ip, peer);
    }
}
