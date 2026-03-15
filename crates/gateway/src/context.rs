use waf_common::{HostConfig, RequestCtx};
use std::sync::Arc;

/// Per-request state stored in the Pingora session context
pub struct GatewayCtx {
    /// Built RequestCtx for WAF pipeline
    pub request_ctx: Option<RequestCtx>,
    /// Resolved upstream address (host:port)
    pub upstream_addr: Option<String>,
    /// Matched host config
    pub host_config: Option<Arc<HostConfig>>,
}

impl Default for GatewayCtx {
    fn default() -> Self {
        Self {
            request_ctx: None,
            upstream_addr: None,
            host_config: None,
        }
    }
}
