use std::sync::Arc;

use bytes::BytesMut;
use waf_common::{HostConfig, RequestCtx};

use crate::filters::response_body_decompressor::DecoderChain;
use crate::protocol::Protocol;

/// Maximum request body bytes buffered for WAF inspection (64 KiB).
pub const BODY_PREVIEW_LIMIT: usize = 64 * 1024;

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
    /// Phase-05: wire protocol detected at session start. Tagged once in
    /// `request_filter` and consumed for per-protocol observability.
    pub protocol: Protocol,
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

    // Pingora's `ProxyHttp::CTX` bound requires `Send`. If a future field on
    // BodyScanState (e.g. a non-Send Mutex) breaks this, fail at compile time.
    static_assertions::assert_impl_all!(BodyScanState: Send);
    static_assertions::assert_impl_all!(GatewayCtx: Send);
}
