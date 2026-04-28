//! Outbound response protection (FR-035 — header leak prevention).
//!
//! Inspects upstream response headers and strips those that leak server
//! fingerprint, debug/internal info, error detail, or PII before the response
//! is forwarded to the client. Detection cases live in code; activation
//! toggles live in `waf_common::config::HeaderFilterConfig`.

pub mod header_filter;

pub use header_filter::HeaderFilter;

/// Errors produced when constructing an outbound filter from operator config.
///
/// Returned by `HeaderFilter::try_new` when the operator-supplied
/// `pii.disable_builtin` references an unknown pattern name or when
/// `pii.extra_patterns` contains an invalid regex.  The gateway
/// construction site logs these and continues without the outbound filter
/// (fail-safe — a misconfigured filter must not break the proxy).
#[derive(Debug, thiserror::Error)]
pub enum OutboundConfigError {
    #[error("FR-035: unknown PII pattern '{name}'. Valid names: {valid:?}")]
    UnknownPiiPattern { name: String, valid: Vec<&'static str> },
    #[error("FR-035: invalid extra_patterns[{index}] regex: {message}")]
    InvalidExtraPattern { index: usize, message: String },
}
