//! Compiled cache rule — pre-built matchers ready for the hot path.
//!
//! `RuleDoc` (YAML) → `CompiledRule` (matchable). Compilation runs once at
//! load / hot-reload time so per-request work stays allocation-free.

use std::sync::Arc;
use std::time::Duration;

use http::Method;
use regex::{Regex, RegexBuilder};
use waf_common::tier::HttpMethod;

use crate::cache::config::{MatchDoc, PathSpec, RuleDoc};
use crate::tiered::compiled_rule::MethodSet;

/// Cap on a single regex compiled size. The `regex` crate is linear-time, but
/// a giant pattern can still hog RAM. 64 KiB is generous for cache routing
/// patterns and matches the order-of-magnitude used by the tier classifier.
const REGEX_SIZE_LIMIT_BYTES: usize = 64 * 1024;

/// Errors compiling a single rule.
#[derive(Debug, thiserror::Error)]
pub enum RuleCompileError {
    #[error("rule '{id}': bad path regex: {source}")]
    BadPathRegex { id: String, source: regex::Error },
    #[error("rule '{id}': bad host regex: {source}")]
    BadHostRegex { id: String, source: regex::Error },
}

/// Host matcher. `Any` = wildcard; `Exact` = case-insensitive byte equal;
/// `Wildcard` = literal `*.foo.com` style suffix; `Regex` for advanced cases.
#[derive(Debug)]
pub enum HostMatcher {
    Any,
    Exact(String),
    /// Suffix WITH leading dot — e.g. `.example.com` matches `api.example.com`
    /// but NOT `evilexample.com`.
    Suffix(String),
    Regex(Regex),
}

impl HostMatcher {
    /// `host_lower` MUST be lowercase already. Caller normalizes once per request.
    pub fn matches(&self, host_lower: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(v) => host_lower == v,
            Self::Suffix(v) => host_lower.ends_with(v.as_str()),
            Self::Regex(r) => r.is_match(host_lower),
        }
    }
}

/// Path matcher — prefix or regex. No `Exact` for cache routing: most
/// production patterns are family-of-paths (e.g. all `/static/*`).
#[derive(Debug)]
pub enum PathMatcher {
    Prefix(String),
    Regex(Regex),
}

impl PathMatcher {
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::Prefix(v) => path.starts_with(v.as_str()),
            Self::Regex(r) => r.is_match(path),
        }
    }
}

/// Compiled rule. `Arc<str>` for `id` + `tags` so they're cheap to clone into
/// the cache entry on `put` (Phase 4 tag index dedups the same `Arc` instances).
#[derive(Debug)]
pub struct CompiledRule {
    pub id: Arc<str>,
    pub host: HostMatcher,
    pub path: PathMatcher,
    /// `None` = any method. `Some(set)` = only listed methods.
    pub methods: Option<MethodSet>,
    pub ttl: Duration,
    pub tags: Vec<Arc<str>>,
    pub allow_authenticated: bool,
}

impl CompiledRule {
    /// Compile from YAML doc form. Returned errors include the rule `id` so
    /// operator-facing messages pinpoint which entry failed.
    pub fn try_from_doc(doc: &RuleDoc) -> Result<Self, RuleCompileError> {
        let host = compile_host(&doc.id, doc.match_.host.as_deref())?;
        let path = compile_path(&doc.id, &doc.match_.path)?;
        let methods = doc.match_.methods.as_deref().map(compile_methods);

        Ok(Self {
            id: Arc::<str>::from(doc.id.as_str()),
            host,
            path,
            methods,
            ttl: Duration::from_secs(u64::from(doc.ttl_seconds)),
            tags: doc.tags.iter().map(|t| Arc::<str>::from(t.as_str())).collect(),
            allow_authenticated: doc.allow_authenticated,
        })
    }

    /// Hot-path match check. `host_lower` must already be ASCII-lowercased.
    pub fn matches(&self, host_lower: &str, path: &str, method: &Method) -> bool {
        if !self.host.matches(host_lower) {
            return false;
        }
        if !self.path.matches(path) {
            return false;
        }
        if let Some(set) = &self.methods
            && !set.contains_http(method)
        {
            return false;
        }
        true
    }

    /// Match against a string method. Falls back to the bitset path; unknown
    /// methods (extension verbs) never match a method-restricted rule.
    pub fn matches_str(&self, host_lower: &str, path: &str, method: &str) -> bool {
        Method::try_from(method).is_ok_and(|m| self.matches(host_lower, path, &m))
    }
}

fn compile_host(id: &str, raw: Option<&str>) -> Result<HostMatcher, RuleCompileError> {
    let Some(raw) = raw else { return Ok(HostMatcher::Any) };
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "*" {
        return Ok(HostMatcher::Any);
    }
    // Wildcard form: "*.example.com" → suffix ".example.com".
    if let Some(rest) = trimmed.strip_prefix("*.") {
        return Ok(HostMatcher::Suffix(format!(".{}", rest.to_ascii_lowercase())));
    }
    // Heuristic: contains a regex metacharacter → treat as regex.
    // Otherwise = exact host. Keeps the common case (`api.example.com`)
    // declaration-friendly without forcing operators to escape every dot.
    if trimmed
        .chars()
        .any(|c| matches!(c, '^' | '$' | '|' | '(' | ')' | '[' | ']' | '+' | '?' | '\\'))
    {
        let r = RegexBuilder::new(trimmed)
            .size_limit(REGEX_SIZE_LIMIT_BYTES)
            .build()
            .map_err(|source| RuleCompileError::BadHostRegex {
                id: id.to_string(),
                source,
            })?;
        return Ok(HostMatcher::Regex(r));
    }
    Ok(HostMatcher::Exact(trimmed.to_ascii_lowercase()))
}

fn compile_path(id: &str, spec: &PathSpec) -> Result<PathMatcher, RuleCompileError> {
    match spec {
        PathSpec::Prefix { prefix } => Ok(PathMatcher::Prefix(prefix.clone())),
        PathSpec::Regex { regex } => {
            let r = RegexBuilder::new(regex)
                .size_limit(REGEX_SIZE_LIMIT_BYTES)
                .build()
                .map_err(|source| RuleCompileError::BadPathRegex {
                    id: id.to_string(),
                    source,
                })?;
            Ok(PathMatcher::Regex(r))
        }
    }
}

fn compile_methods(methods: &[HttpMethod]) -> MethodSet {
    let mut set = MethodSet::empty();
    for m in methods {
        set.insert(*m);
    }
    set
}

/// Match dispatcher used in [`MatchDoc`] field; kept here for cohesion. Only
/// referenced at compile time but explicit `dead_code` allow keeps the import
/// from drifting away.
#[allow(dead_code)]
const _DOC_LINK: fn(&MatchDoc) = |_| ();

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, host: Option<&str>, path: PathSpec, methods: Option<Vec<HttpMethod>>) -> RuleDoc {
        RuleDoc {
            id: id.to_string(),
            match_: MatchDoc {
                host: host.map(str::to_string),
                path,
                methods,
            },
            ttl_seconds: 60,
            tags: vec!["t".into()],
            allow_authenticated: false,
        }
    }

    #[test]
    fn host_any_matches_anything() {
        let r = CompiledRule::try_from_doc(&rule("r", Some("*"), PathSpec::Prefix { prefix: "/".into() }, None))
            .expect("compile");
        assert!(r.matches_str("a.example.com", "/x", "GET"));
        assert!(r.matches_str("z.test", "/y", "GET"));
    }

    #[test]
    fn host_wildcard_is_suffix_with_dot() {
        let r = CompiledRule::try_from_doc(&rule(
            "r",
            Some("*.example.com"),
            PathSpec::Prefix { prefix: "/".into() },
            None,
        ))
        .expect("compile");
        assert!(r.matches_str("api.example.com", "/", "GET"));
        // CRITICAL: must NOT match a domain that merely ends in the same chars.
        assert!(!r.matches_str("evilexample.com", "/", "GET"));
    }

    #[test]
    fn host_exact_lowercased() {
        let r = CompiledRule::try_from_doc(&rule(
            "r",
            Some("Foo.Example.COM"),
            PathSpec::Prefix { prefix: "/".into() },
            None,
        ))
        .expect("compile");
        assert!(r.matches_str("foo.example.com", "/", "GET"));
        assert!(!r.matches_str("bar.example.com", "/", "GET"));
    }

    #[test]
    fn path_regex_matches_static_assets() {
        let r = CompiledRule::try_from_doc(&rule(
            "r",
            None,
            PathSpec::Regex {
                regex: r"^/(static|assets)/".into(),
            },
            None,
        ))
        .expect("compile");
        assert!(r.matches_str("h", "/static/app.css", "GET"));
        assert!(r.matches_str("h", "/assets/x.png", "GET"));
        assert!(!r.matches_str("h", "/api/users", "GET"));
    }

    #[test]
    fn method_bitset_filters_post() {
        let r = CompiledRule::try_from_doc(&rule(
            "r",
            None,
            PathSpec::Prefix { prefix: "/".into() },
            Some(vec![HttpMethod::Get, HttpMethod::Head]),
        ))
        .expect("compile");
        assert!(r.matches_str("h", "/x", "GET"));
        assert!(r.matches_str("h", "/x", "HEAD"));
        assert!(!r.matches_str("h", "/x", "POST"));
    }

    #[test]
    fn bad_path_regex_returns_error_with_rule_id() {
        let err =
            CompiledRule::try_from_doc(&rule("broken", None, PathSpec::Regex { regex: "[".into() }, None)).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("broken"), "error must name the rule: {msg}");
    }
}
