//! FR-012 phase-01 — endpoint role tagger.
//!
//! Compiles each `RoleRule` into a `Regex` once at config load. `classify`
//! walks the rules in order and returns the first matching role; if no rule
//! matches, returns [`EndpointRole::None`]. Hot-reload swaps the whole
//! tagger via `ArcSwap<TxVelocityConfig>` — no per-request recompile.

use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};

use super::EndpointRole;
use super::config::RoleRule;

/// Compiled path → role rules. Order is significant: first match wins.
#[derive(Debug)]
pub struct RoleTagger {
    rules: Vec<CompiledRule>,
}

#[derive(Debug)]
struct CompiledRule {
    role: EndpointRole,
    re: Regex,
}

impl RoleTagger {
    /// Empty tagger — every path classifies as [`EndpointRole::None`].
    /// Used as the runtime default and for `enabled = false`.
    #[must_use]
    pub const fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Compile each rule's `path` regex. Returns the first compile error
    /// (with rule index) so operators see exactly which line is wrong.
    pub fn compile(rules: &[RoleRule]) -> Result<Self> {
        let mut compiled = Vec::with_capacity(rules.len());
        for (idx, rule) in rules.iter().enumerate() {
            let re = RegexBuilder::new(&rule.path)
                .size_limit(1 << 20) // 1 MB compiled DFA limit — guards against regex DoS
                .build()
                .with_context(|| format!("endpoint_roles[{idx}] regex compile: {}", rule.path))?;
            compiled.push(CompiledRule { role: rule.role, re });
        }
        Ok(Self { rules: compiled })
    }

    /// First matching rule wins. Empty tagger ⇒ `None`.
    #[must_use]
    pub fn classify(&self, path: &str) -> EndpointRole {
        for rule in &self.rules {
            if rule.re.is_match(path) {
                return rule.role;
            }
        }
        EndpointRole::None
    }

    /// Number of compiled rules. Test/diagnostic helper.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rules.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(role: EndpointRole, path: &str) -> RoleRule {
        RoleRule {
            role,
            path: path.to_string(),
        }
    }

    #[test]
    fn empty_tagger_returns_none() {
        let t = RoleTagger::empty();
        assert_eq!(t.classify("/anything"), EndpointRole::None);
        assert!(t.is_empty());
    }

    #[test]
    fn first_match_wins() {
        let t = RoleTagger::compile(&[
            rule(EndpointRole::Login, r"^/api/login$"),
            rule(EndpointRole::Otp, r"^/api/otp"),
            rule(EndpointRole::Deposit, r"^/api/deposit"),
        ])
        .expect("compile");
        assert_eq!(t.classify("/api/login"), EndpointRole::Login);
        assert_eq!(t.classify("/api/otp/verify"), EndpointRole::Otp);
        assert_eq!(t.classify("/api/deposit"), EndpointRole::Deposit);
        assert_eq!(t.classify("/api/other"), EndpointRole::None);
    }

    #[test]
    fn order_is_significant() {
        // Broader rule listed first ⇒ shadows the more specific one.
        let t = RoleTagger::compile(&[
            rule(EndpointRole::Withdrawal, r"^/api/"),
            rule(EndpointRole::Login, r"^/api/login$"),
        ])
        .expect("compile");
        assert_eq!(t.classify("/api/login"), EndpointRole::Withdrawal);
    }

    #[test]
    fn invalid_regex_reports_index() {
        let err = RoleTagger::compile(&[
            rule(EndpointRole::Login, r"^/ok$"),
            rule(EndpointRole::Otp, r"[invalid("),
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("endpoint_roles[1]"), "got: {err}");
    }

    #[test]
    fn oversized_pattern_rejected_by_size_limit() {
        // Build a 16-way alternation repeated 10k times — compiled NFA easily
        // exceeds the 1 MB size_limit. Without the size_limit guard, this would
        // allocate hundreds of MB at compile time (regex crate default cap is
        // 10 MB; this pattern would pass that and only fail in OOM-land if no
        // builder limit were set).
        let bomb = "^(?:a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p){10000}$";
        let err = RoleTagger::compile(&[rule(EndpointRole::Login, bomb)])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("endpoint_roles[0]"),
            "expected index-tagged compile error, got: {err}"
        );
    }
}
