//! Neutral error-page rendering (AC-19).
//!
//! Replaces Pingora's default error pages so the WAF never echoes a
//! recognizable proxy fingerprint (e.g. "Pingora") or stack content
//! to clients.

pub mod error_page_factory;

pub use error_page_factory::ErrorPageFactory;
