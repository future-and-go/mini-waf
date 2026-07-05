//! Re-export shim over [`crate::time`].
//!
//! The clock abstraction lives in [`crate::time`] so the `DDoS` detectors and
//! the risk ingest pipeline share one implementation. Existing
//! `checks::ddos::detector::clock::*` paths keep working.

pub use crate::time::{Clock, SystemClock};

#[cfg(test)]
pub use crate::time::test_utils;
