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
