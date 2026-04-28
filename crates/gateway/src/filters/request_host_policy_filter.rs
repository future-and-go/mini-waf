//! `RequestFilter` adapter for the [`HostHeaderPolicy`] strategy (AC-25).
//!
//! The strategy itself lives in `policies/host_header_policy.rs` so it can
//! be unit-tested without the filter trait. Built per-request from
//! `fctx.host_config.preserve_host` so config changes take effect on the
//! next request without rebuilding the chain.

use crate::pipeline::{FilterCtx, RequestFilter};
use crate::policies::HostHeaderPolicy;

/// Filter wrapper around [`HostHeaderPolicy`].
pub struct RequestHostPolicyFilter;

impl RequestFilter for RequestHostPolicyFilter {
    fn apply(&self, req: &mut pingora_http::RequestHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        let policy = HostHeaderPolicy::from_host_config(fctx.host_config);
        policy.apply(req)
    }

    fn name(&self) -> &'static str {
        "request-host-policy"
    }
}
