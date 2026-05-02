//! YAML schema types for `rules/cache.yaml` (FR-009 Phase 3).
//!
//! Pure deserialization data — no regex compilation, no semantic validation.
//! Compilation lives in [`super::rule_set::CompiledRuleSet::try_from_doc`].
//!
//! Two stages on purpose: a parse error here is a YAML syntax problem; a
//! compile/validate error there is a semantic one. Operators reading logs
//! benefit from the distinction.

use serde::Deserialize;
use waf_common::tier::HttpMethod;

/// Top-level YAML envelope. `version` is reserved for forward-compat; only
/// `1` is accepted today (rejected in [`super::rule_set::CompiledRuleSet::try_from_doc`]).
#[derive(Debug, Deserialize)]
pub struct CacheConfigDoc {
    pub version: u32,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub rules: Vec<RuleDoc>,
}

/// Per-document defaults. Today only carries response shape limits; future
/// fields land here without breaking existing files.
#[derive(Debug, Deserialize, Default)]
pub struct Defaults {
    /// Hard cap on cacheable response body size. `0` = no cap.
    /// Enforced by Phase 5; kept here so the YAML is forward-compatible.
    #[serde(default)]
    pub max_body_bytes: Option<u64>,
    /// When `true` (default), upstream `Cache-Control: no-store|no-cache|private`
    /// still bypasses regardless of route TTL. Encoded by `UpstreamCcGate`
    /// being a member of the chain.
    #[serde(default = "default_true")]
    pub respect_upstream_cache_control: bool,
    /// Status codes that may be cached when a route matches. Defaults to
    /// `[200, 203, 301, 410]`. Note: 404 deliberately excluded — recon detection
    /// is FR-019's concern.
    #[serde(default = "default_cacheable_statuses")]
    pub cacheable_status_codes: Vec<u16>,
}

const fn default_true() -> bool {
    true
}

fn default_cacheable_statuses() -> Vec<u16> {
    vec![200, 203, 301, 410]
}

/// One rule entry. Renames `match` to `match_` because `match` is a Rust keyword.
#[derive(Debug, Deserialize)]
pub struct RuleDoc {
    pub id: String,
    #[serde(rename = "match")]
    pub match_: MatchDoc,
    pub ttl_seconds: u32,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Per-rule opt-in to caching authenticated traffic. `false` = `AuthGate`
    /// bypasses any request bearing `Authorization` or `Cookie`.
    /// v1 always treats this as `false` even when set; key-dim hashing for
    /// real per-user caching is deferred (see plan.md open Q1).
    #[serde(default)]
    pub allow_authenticated: bool,
}

/// Match clause. Any field omitted = "match anything for this dimension".
#[derive(Debug, Deserialize)]
pub struct MatchDoc {
    /// `*` or omitted = any host. Else exact match (case-insensitive).
    #[serde(default)]
    pub host: Option<String>,
    pub path: PathSpec,
    /// `None` = any method (subject to upstream `MethodGate` which still demands GET/HEAD).
    #[serde(default)]
    pub methods: Option<Vec<HttpMethod>>,
}

/// Path matcher — either a literal prefix or a regex source string.
/// `untagged` so YAML can use either `{ prefix: "/foo" }` or `{ regex: "^/.*\\.css$" }`
/// without an explicit `kind:` discriminator.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PathSpec {
    Prefix { prefix: String },
    Regex { regex: String },
}
