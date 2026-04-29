//! Ordered chain of [`ResponseFilter`] implementations.
//!
//! Filters are invoked in registration order.  The first filter that returns
//! an error short-circuits the chain: a warning is logged and the error is
//! propagated to the caller.

use std::sync::Arc;

use super::{FilterCtx, ResponseFilter};

/// Executes a sequence of [`ResponseFilter`]s against a single response header.
///
/// The chain holds `Arc<dyn ResponseFilter>` entries so individual filters can be
/// shared or replaced cheaply without re-allocating the whole chain.
pub struct ResponseFilterChain {
    filters: Vec<Arc<dyn ResponseFilter>>,
}

impl ResponseFilterChain {
    /// Create an empty chain.
    pub fn new() -> Self {
        Self { filters: Vec::new() }
    }

    /// Append a filter to the end of the chain.
    pub fn register(&mut self, filter: Arc<dyn ResponseFilter>) {
        self.filters.push(filter);
    }

    /// Run every filter in registration order against `resp`.
    ///
    /// Stops on the first error, logs a warning with the filter name and
    /// the error, then returns the error to the caller.
    pub fn apply_all(&self, resp: &mut pingora_http::ResponseHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        for filter in &self.filters {
            if let Err(e) = filter.apply(resp, fctx) {
                tracing::warn!(
                    filter = filter.name(),
                    err = ?e,
                    "response filter failed"
                );
                return Err(e);
            }
        }
        Ok(())
    }
}

impl Default for ResponseFilterChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::FilterCtx;
    use parking_lot::Mutex;
    use pingora_http::ResponseHeader;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use waf_common::{HostConfig, RequestCtx};

    struct Recorder {
        tag: &'static str,
        log: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    }

    impl ResponseFilter for Recorder {
        fn apply(&self, _resp: &mut ResponseHeader, _fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
            self.log.lock().push(self.tag);
            if self.fail {
                Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::InternalError,
                    "stub",
                ))
            } else {
                Ok(())
            }
        }
        fn name(&self) -> &'static str {
            self.tag
        }
    }

    fn make_ctx() -> (RequestCtx, Arc<HostConfig>) {
        let hc = Arc::new(HostConfig::default());
        let ctx = RequestCtx {
            req_id: "t".into(),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            client_port: 0,
            method: "GET".into(),
            host: "h".into(),
            port: 80,
            path: "/".into(),
            query: String::new(),
            headers: std::collections::HashMap::new(),
            body_preview: bytes::Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::clone(&hc),
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
            cookies: std::collections::HashMap::new(),
        };
        (ctx, hc)
    }

    #[test]
    fn empty_chain_is_ok() {
        let chain = ResponseFilterChain::default();
        let (ctx, hc) = make_ctx();
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: ctx.client_ip,
            is_tls: false,
        };
        let mut resp = ResponseHeader::build(200, None).expect("build");
        assert!(chain.apply_all(&mut resp, &fctx).is_ok());
    }

    #[test]
    fn runs_filters_in_registration_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut chain = ResponseFilterChain::new();
        chain.register(Arc::new(Recorder {
            tag: "a",
            log: Arc::clone(&log),
            fail: false,
        }));
        chain.register(Arc::new(Recorder {
            tag: "b",
            log: Arc::clone(&log),
            fail: false,
        }));

        let (ctx, hc) = make_ctx();
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: ctx.client_ip,
            is_tls: false,
        };
        let mut resp = ResponseHeader::build(200, None).expect("build");
        chain.apply_all(&mut resp, &fctx).expect("ok");
        assert_eq!(*log.lock(), vec!["a", "b"]);
    }

    #[test]
    fn first_error_short_circuits() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut chain = ResponseFilterChain::new();
        chain.register(Arc::new(Recorder {
            tag: "ok1",
            log: Arc::clone(&log),
            fail: false,
        }));
        chain.register(Arc::new(Recorder {
            tag: "boom",
            log: Arc::clone(&log),
            fail: true,
        }));
        chain.register(Arc::new(Recorder {
            tag: "never",
            log: Arc::clone(&log),
            fail: false,
        }));

        let (ctx, hc) = make_ctx();
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: ctx.client_ip,
            is_tls: false,
        };
        let mut resp = ResponseHeader::build(200, None).expect("build");
        let res = chain.apply_all(&mut resp, &fctx);
        assert!(res.is_err());
        assert_eq!(*log.lock(), vec!["ok1", "boom"]);
    }
}
