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
