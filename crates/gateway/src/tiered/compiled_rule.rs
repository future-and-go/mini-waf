//! Compiled tier classifier rule — pre-parsed from `waf-common::TierClassifierRule`.
//!
//! Compilation happens once at config load. Hot-path matching uses these
//! compiled forms (Regex objects, lowercased host strings, method bitset,
//! pre-parsed HeaderName/HeaderValue) to avoid per-request allocation.

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use regex::Regex;
use waf_common::tier::{HttpMethod, Tier, TierClassifierRule};
use waf_common::tier_match::{HeaderMatch, HostMatch, PathMatch};

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("regex compile failed in rule #{idx}: {source}")]
    BadRegex {
        idx: usize,
        #[source]
        source: regex::Error,
    },
    #[error("invalid header name in rule #{idx}: {name}")]
    BadHeaderName { idx: usize, name: String },
    #[error("invalid header value in rule #{idx} for header {name}")]
    BadHeaderValue { idx: usize, name: String },
}

/// Bitset over the 9 HTTP methods defined in `waf-common::HttpMethod`.
/// One bitwise AND replaces a `Vec<HttpMethod>` linear scan on the hot path.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MethodSet(u16);

impl MethodSet {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn insert(&mut self, m: HttpMethod) {
        self.0 |= 1u16 << method_bit(m);
    }

    pub const fn contains(self, m: HttpMethod) -> bool {
        (self.0 & (1u16 << method_bit(m))) != 0
    }

    /// Test against an `http::Method`. Unknown extension methods never match.
    pub fn contains_http(self, m: &Method) -> bool {
        let bit = match m.as_str() {
            "GET" => 0,
            "HEAD" => 1,
            "POST" => 2,
            "PUT" => 3,
            "DELETE" => 4,
            "CONNECT" => 5,
            "OPTIONS" => 6,
            "TRACE" => 7,
            "PATCH" => 8,
            _ => return false,
        };
        (self.0 & (1u16 << bit)) != 0
    }
}

const fn method_bit(m: HttpMethod) -> u16 {
    match m {
        HttpMethod::Get => 0,
        HttpMethod::Head => 1,
        HttpMethod::Post => 2,
        HttpMethod::Put => 3,
        HttpMethod::Delete => 4,
        HttpMethod::Connect => 5,
        HttpMethod::Options => 6,
        HttpMethod::Trace => 7,
        HttpMethod::Patch => 8,
    }
}

#[derive(Debug)]
pub enum CompiledPathMatch {
    Exact(String),
    Prefix(String),
    Regex(Regex),
}

impl CompiledPathMatch {
    pub fn matches(&self, path: &str) -> bool {
        match self {
            Self::Exact(v) => path == v,
            Self::Prefix(v) => path.starts_with(v.as_str()),
            Self::Regex(r) => r.is_match(path),
        }
    }
}

/// Host matcher. Exact/Suffix values are pre-lowercased at compile time;
/// callers must pass an already-lowercased host (cheap when sourced once
/// from the request's authority).
#[derive(Debug)]
pub enum CompiledHostMatch {
    Exact(String),
    Suffix(String),
    Regex(Regex),
}

impl CompiledHostMatch {
    pub fn matches(&self, host_lower: &str) -> bool {
        match self {
            Self::Exact(v) => host_lower == v,
            Self::Suffix(v) => host_lower.ends_with(v.as_str()),
            Self::Regex(r) => r.is_match(host_lower),
        }
    }
}

#[derive(Debug)]
pub struct CompiledTierRule {
    pub priority: u32,
    pub tier: Tier,
    pub host: Option<CompiledHostMatch>,
    pub path: Option<CompiledPathMatch>,
    pub method: Option<MethodSet>,
    pub headers: Option<Vec<(HeaderName, HeaderValue)>>,
}

impl CompiledTierRule {
    pub fn matches(&self, host_lower: &str, path: &str, method: &Method, headers: &HeaderMap) -> bool {
        if let Some(h) = &self.host
            && !h.matches(host_lower)
        {
            return false;
        }
        if let Some(p) = &self.path
            && !p.matches(path)
        {
            return false;
        }
        if let Some(m) = &self.method
            && !m.contains_http(method)
        {
            return false;
        }
        if let Some(hs) = &self.headers {
            for (name, expected) in hs {
                match headers.get(name) {
                    Some(v) if v.as_bytes() == expected.as_bytes() => {}
                    _ => return false,
                }
            }
        }
        true
    }
}

fn compile_path(idx: usize, m: &PathMatch) -> Result<CompiledPathMatch, CompileError> {
    Ok(match m {
        PathMatch::Exact { value } => CompiledPathMatch::Exact(value.clone()),
        PathMatch::Prefix { value } => CompiledPathMatch::Prefix(value.clone()),
        PathMatch::Regex { value } => {
            CompiledPathMatch::Regex(Regex::new(value).map_err(|e| CompileError::BadRegex { idx, source: e })?)
        }
    })
}

fn compile_host(idx: usize, m: &HostMatch) -> Result<CompiledHostMatch, CompileError> {
    Ok(match m {
        HostMatch::Exact { value } => CompiledHostMatch::Exact(value.to_ascii_lowercase()),
        HostMatch::Suffix { value } => CompiledHostMatch::Suffix(value.to_ascii_lowercase()),
        HostMatch::Regex { value } => {
            CompiledHostMatch::Regex(Regex::new(value).map_err(|e| CompileError::BadRegex { idx, source: e })?)
        }
    })
}

fn compile_methods(methods: &[HttpMethod]) -> MethodSet {
    let mut set = MethodSet::empty();
    for m in methods {
        set.insert(*m);
    }
    set
}

fn compile_headers(idx: usize, hs: &[HeaderMatch]) -> Result<Vec<(HeaderName, HeaderValue)>, CompileError> {
    hs.iter()
        .map(|h| {
            let name = HeaderName::from_bytes(h.name.to_ascii_lowercase().as_bytes()).map_err(|_| {
                CompileError::BadHeaderName {
                    idx,
                    name: h.name.clone(),
                }
            })?;
            let value = HeaderValue::from_str(&h.value).map_err(|_| CompileError::BadHeaderValue {
                idx,
                name: h.name.clone(),
            })?;
            Ok((name, value))
        })
        .collect()
}

/// Compile a single rule. Index is included in errors so config failures
/// pinpoint the offending TOML entry.
pub fn compile_rule(idx: usize, rule: &TierClassifierRule) -> Result<CompiledTierRule, CompileError> {
    Ok(CompiledTierRule {
        priority: rule.priority,
        tier: rule.tier,
        host: rule.host.as_ref().map(|h| compile_host(idx, h)).transpose()?,
        path: rule.path.as_ref().map(|p| compile_path(idx, p)).transpose()?,
        method: rule.method.as_deref().map(compile_methods),
        headers: rule.headers.as_deref().map(|hs| compile_headers(idx, hs)).transpose()?,
    })
}

/// Compile a full rule list. Sort is stable + descending by `priority`
/// so original TOML order breaks ties predictably.
pub fn compile_rules(rules: &[TierClassifierRule]) -> Result<Vec<CompiledTierRule>, CompileError> {
    let mut compiled: Vec<CompiledTierRule> = rules
        .iter()
        .enumerate()
        .map(|(i, r)| compile_rule(i, r))
        .collect::<Result<_, _>>()?;
    // Stable sort by priority DESC; original TOML order breaks ties.
    compiled.sort_by_key(|r| std::cmp::Reverse(r.priority));
    Ok(compiled)
}
