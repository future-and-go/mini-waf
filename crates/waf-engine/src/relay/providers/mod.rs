//! FR-007 — provider implementations.
//!
//! - phase-02: `parse`, `xff_validator`, `proxy_chain`
//! - phase-03: `asn_classifier` (pending)
//! - phase-04: `tor_exit` (pending)

pub mod asn_classifier;
pub mod parse;
pub mod proxy_chain;
pub mod tor_exit;
pub mod xff_validator;

pub use asn_classifier::AsnClassifier;
pub use proxy_chain::ProxyChainAnalyzer;
pub use tor_exit::{TorExitMatcher, TorSet};
pub use xff_validator::XffValidator;
