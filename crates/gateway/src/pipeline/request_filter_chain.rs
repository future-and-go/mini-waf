//! Ordered chain of [`RequestFilter`] implementations.
//!
//! Filters are invoked in registration order.  The first filter that returns
//! an error short-circuits the chain: a warning is logged and the error is
//! propagated to the caller.

use std::sync::Arc;

use super::{FilterCtx, RequestFilter};

/// Executes a sequence of [`RequestFilter`]s against a single request header.
///
/// The chain holds `Arc<dyn RequestFilter>` entries so individual filters can be
/// shared or replaced cheaply without re-allocating the whole chain.
pub struct RequestFilterChain {
    filters: Vec<Arc<dyn RequestFilter>>,
}

impl RequestFilterChain {
    /// Create an empty chain.
    pub fn new() -> Self {
        Self { filters: Vec::new() }
    }

    /// Append a filter to the end of the chain.
    pub fn register(&mut self, filter: Arc<dyn RequestFilter>) {
        self.filters.push(filter);
    }

    /// Run every filter in registration order against `req`.
    ///
    /// Stops on the first error, logs a warning with the filter name and
    /// the error, then returns the error to the caller.
    pub fn apply_all(&self, req: &mut pingora_http::RequestHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        for filter in &self.filters {
            if let Err(e) = filter.apply(req, fctx) {
                tracing::warn!(
                    filter = filter.name(),
                    err = ?e,
                    "request filter failed"
                );
                return Err(e);
            }
        }
        Ok(())
    }
}

impl Default for RequestFilterChain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::FilterCtx;
    use parking_lot::Mutex;
    use pingora_http::RequestHeader;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use waf_common::{HostConfig, RequestCtx};

    /// Stub filter recording its name when invoked; optionally errors.
    struct Recorder {
        tag: &'static str,
        log: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    }

    impl RequestFilter for Recorder {
        fn apply(&self, _req: &mut RequestHeader, _fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
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
        let chain = RequestFilterChain::new();
        let (ctx, hc) = make_ctx();
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: ctx.client_ip,
            is_tls: false,
        };
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        assert!(chain.apply_all(&mut req, &fctx).is_ok());
    }

    #[test]
    fn runs_filters_in_registration_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut chain = RequestFilterChain::default();
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
        chain.register(Arc::new(Recorder {
            tag: "c",
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
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        chain.apply_all(&mut req, &fctx).expect("ok");
        assert_eq!(*log.lock(), vec!["a", "b", "c"]);
    }

    #[test]
    fn first_error_short_circuits() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut chain = RequestFilterChain::new();
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
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        let res = chain.apply_all(&mut req, &fctx);
        assert!(res.is_err());
        assert_eq!(*log.lock(), vec!["ok1", "boom"]);
    }
}
