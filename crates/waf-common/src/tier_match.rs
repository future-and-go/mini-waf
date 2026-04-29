//! Matcher value types for tier classifier rules.
//!
//! Pure data — no regex compilation here. Phase 2 (`gateway::tiered`) compiles
//! the `Regex` variants into `regex::Regex` once at config load.
//! `TierConfig::validate()` test-compiles the regex strings to fail-fast on
//! malformed patterns, then discards the result.

use serde::{Deserialize, Serialize};

/// Path matcher. `Exact` = byte-equal, `Prefix` = `starts_with`, `Regex` = source string.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PathMatch {
    Exact { value: String },
    Prefix { value: String },
    Regex { value: String },
}

/// Host matcher. `Suffix` is for subdomain matching (e.g. `.example.com`).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HostMatch {
    Exact { value: String },
    Suffix { value: String },
    Regex { value: String },
}

/// Header matcher. MVP: exact value match; name compared ASCII-case-insensitively.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HeaderMatch {
    pub name: String,
    pub value: String,
}

impl PathMatch {
    /// Returns the regex source string if this variant is `Regex`, else `None`.
    /// Used by validator to test-compile without depending on `regex` API here.
    pub const fn regex_source(&self) -> Option<&str> {
        match self {
            Self::Regex { value } => Some(value.as_str()),
            _ => None,
        }
    }
}

impl HostMatch {
    pub const fn regex_source(&self) -> Option<&str> {
        match self {
            Self::Regex { value } => Some(value.as_str()),
            _ => None,
        }
    }
}
