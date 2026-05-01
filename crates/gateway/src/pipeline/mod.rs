//! Request and response filter pipeline.
//!
//! Defines [`RequestFilter`] and [`ResponseFilter`] traits, plus [`FilterCtx`]
//! which carries per-request context through each filter in the chain.
//! Concrete chain implementations live in the sub-modules.

use std::net::IpAddr;
use std::sync::Arc;

use waf_common::{HostConfig, RequestCtx};

pub mod access_phase;
pub mod request_filter_chain;
pub mod response_filter_chain;

pub use access_phase::{AccessGateOutcome, AccessPhaseGate};
pub use request_filter_chain::RequestFilterChain;
pub use response_filter_chain::ResponseFilterChain;

/// Immutable context passed to every filter in the chain.
///
/// Borrows both the per-request context and the matched host configuration
/// so filters can read configuration without allocating.
pub struct FilterCtx<'a> {
    /// WAF request context (IP, method, headers, etc.)
    pub request_ctx: &'a RequestCtx,
    /// Host-level configuration (defense settings, backend, etc.)
    pub host_config: &'a Arc<HostConfig>,
    /// Resolved client IP (may be from X-Forwarded-For when trusted).
    pub peer_ip: IpAddr,
    /// Whether the downstream connection was established over TLS.
    pub is_tls: bool,
}

/// A filter that may transform or reject an upstream request header.
///
/// Implementations must be `Send + Sync` so the chain can be shared across
/// Tokio worker threads.  The `name` method is used only for structured
/// logging when a filter returns an error.
pub trait RequestFilter: Send + Sync {
    /// Apply this filter to `req`.
    ///
    /// Return `Ok(())` to let the request continue to the next filter.
    /// Return `Err(_)` to short-circuit the chain; the error is logged and
    /// propagated back to the caller.
    fn apply(&self, req: &mut pingora_http::RequestHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()>;

    /// Human-readable name used in log messages.
    fn name(&self) -> &'static str;
}

/// A filter that may transform an upstream response header.
///
/// Same contract as [`RequestFilter`] but applied to the response.
pub trait ResponseFilter: Send + Sync {
    /// Apply this filter to `resp`.
    fn apply(&self, resp: &mut pingora_http::ResponseHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()>;

    /// Human-readable name used in log messages.
    fn name(&self) -> &'static str;
}
