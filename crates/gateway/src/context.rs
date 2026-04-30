use std::sync::Arc;

use bytes::BytesMut;
use waf_common::{HostConfig, RequestCtx};

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
    /// Phase-05: wire protocol detected at session start. Tagged once in
    /// `request_filter` and consumed for per-protocol observability.
    pub protocol: Protocol,
    /// FR-008: set by Phase-0 access gate when an IP whitelist hit resolves
    /// to `full_bypass` for the request's tier. When true, `engine.inspect()`
    /// is skipped (whitelist trust → fast path).
    pub access_bypass: bool,
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
