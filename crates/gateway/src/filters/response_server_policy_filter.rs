//! Server-header policy filter (AC-16).
//!
//! Thin wrapper that resolves [`ServerHeaderPolicy`] from `host_config`
//! per request and applies it.

use crate::pipeline::{FilterCtx, ResponseFilter};
use crate::policies::ServerHeaderPolicy;

pub struct ResponseServerPolicyFilter;

impl ResponseFilter for ResponseServerPolicyFilter {
    fn apply(&self, resp: &mut pingora_http::ResponseHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        ServerHeaderPolicy::from_host_config(fctx.host_config).apply(resp)
    }

    fn name(&self) -> &'static str {
        "response-server-policy"
    }
}
