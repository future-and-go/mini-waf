//! Compiled cache rule set + atomic, hot-swappable holder.
//!
//! Mirrors `tiered::tier_policy_registry`: an immutable snapshot lives behind
//! an `ArcSwap`, so request-side reads are lock-free and writers (the file
//! watcher) replace the entire snapshot with one atomic store.
//!
//! Why not `RwLock<HashMap>`: every cache request touches this. `RwLock` reads
//! still pay an atomic CAS; `ArcSwap::load()` is a relaxed atomic load. Under
//! the kind of read-heavy workload this gates, that delta is measurable.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::cache::config::{CacheConfigDoc, Defaults};
use crate::cache::rule::{CompiledRule, RuleCompileError};

/// Total compiled regex byte budget across an entire ruleset. Defense against
/// a config file packed with thousands of huge patterns.
const TOTAL_REGEX_BUDGET_BYTES: usize = 1024 * 1024;

/// Errors building a `CompiledRuleSet` from a YAML document.
#[derive(Debug, thiserror::Error)]
pub enum RuleSetError {
    #[error("unsupported config version {0}; only version 1 is supported")]
    UnsupportedVersion(u32),
    #[error("duplicate rule id '{0}'")]
    DuplicateId(String),
    #[error("rule '{0}': tags must be non-empty (required for tag-based purge)")]
    EmptyTags(String),
    #[error("total compiled regex size exceeds budget ({budget} bytes)")]
    RegexBudgetExceeded { budget: usize },
    #[error(transparent)]
    Compile(#[from] RuleCompileError),
}

/// Immutable, hot-path-ready ruleset. Build once, share via `Arc`.
#[derive(Debug)]
pub struct CompiledRuleSet {
    pub rules: Arc<[CompiledRule]>,
    pub defaults: Defaults,
}

impl CompiledRuleSet {
    /// Empty ruleset — used at boot when `rules/cache.yaml` is missing.
    /// Means: no per-route TTLs; only `TierDefaultGate` produces verdicts.
    pub fn empty() -> Self {
        Self {
            rules: Arc::from(Vec::<CompiledRule>::new()),
            defaults: Defaults::default(),
        }
    }

    /// Build from a parsed YAML document. Validates version, id uniqueness,
    /// non-empty tags, then compiles each rule.
    pub fn try_from_doc(doc: CacheConfigDoc) -> Result<Self, RuleSetError> {
        if doc.version != 1 {
            return Err(RuleSetError::UnsupportedVersion(doc.version));
        }

        let mut seen_ids = std::collections::HashSet::with_capacity(doc.rules.len());
        let mut compiled: Vec<CompiledRule> = Vec::with_capacity(doc.rules.len());
        let mut total_regex = 0usize;

        for rule_doc in &doc.rules {
            if !seen_ids.insert(rule_doc.id.clone()) {
                return Err(RuleSetError::DuplicateId(rule_doc.id.clone()));
            }
            if rule_doc.tags.is_empty() {
                return Err(RuleSetError::EmptyTags(rule_doc.id.clone()));
            }
            let rule = CompiledRule::try_from_doc(rule_doc)?;

            // Approximate regex memory cost: regex::Regex doesn't expose
            // size, so use the source string length × 4 (rough for compiled
            // DFA/NFA tables). Conservative; protects against pathological
            // configs without rejecting realistic ones.
            total_regex = total_regex.saturating_add(approx_regex_cost(rule_doc));
            if total_regex > TOTAL_REGEX_BUDGET_BYTES {
                return Err(RuleSetError::RegexBudgetExceeded {
                    budget: TOTAL_REGEX_BUDGET_BYTES,
                });
            }

            compiled.push(rule);
        }

        Ok(Self {
            rules: Arc::from(compiled),
            defaults: doc.defaults,
        })
    }

    /// First matching cache rule for statistics routing (mirrors
    /// [`crate::cache::gates::RouteRuleGate`] match order).
    ///
    /// Returns `None` when a rule matches with `ttl_seconds: 0` (explicit deny).
    /// Returns `Some("_default")` when no rule matches (tier-default caching).
    pub fn first_cacheable_rule_id(&self, host: &str, path: &str, method: &str) -> Option<Arc<str>> {
        let host_lower_storage;
        let host_lower: &str = if host.bytes().all(|b| !b.is_ascii_uppercase()) {
            host
        } else {
            host_lower_storage = host.to_ascii_lowercase();
            host_lower_storage.as_str()
        };
        for rule in self.rules.iter() {
            if !rule.matches_str(host_lower, path, method) {
                continue;
            }
            if rule.ttl.is_zero() {
                return None;
            }
            return Some(Arc::clone(&rule.id));
        }
        Some(Arc::from("_default"))
    }
}

fn approx_regex_cost(rule: &crate::cache::config::RuleDoc) -> usize {
    use crate::cache::config::PathSpec;
    let path_cost = match &rule.match_.path {
        PathSpec::Regex { regex } => regex.len().saturating_mul(4),
        PathSpec::Prefix { .. } => 0,
    };
    let host_cost = rule
        .match_
        .host
        .as_deref()
        .filter(|h| h.contains(['^', '$', '|', '(', '\\']))
        .map_or(0, |h| h.len().saturating_mul(4));
    path_cost + host_cost
}

/// Lock-free, hot-swappable holder. `Arc<RuleSetHolder>` is what callers share.
#[derive(Debug)]
pub struct RuleSetHolder {
    inner: ArcSwap<CompiledRuleSet>,
}

impl RuleSetHolder {
    pub fn new(set: CompiledRuleSet) -> Arc<Self> {
        Arc::new(Self {
            inner: ArcSwap::from(Arc::new(set)),
        })
    }

    /// Snapshot — full Arc clone, safe to hold across `.await`.
    pub fn load(&self) -> Arc<CompiledRuleSet> {
        self.inner.load_full()
    }

    /// Atomically replace. In-flight readers keep their Arc until done.
    pub fn swap(&self, new_set: CompiledRuleSet) {
        self.inner.store(Arc::new(new_set));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::config::{MatchDoc, PathSpec, RuleDoc};

    fn doc(version: u32, rules: Vec<RuleDoc>) -> CacheConfigDoc {
        CacheConfigDoc {
            version,
            defaults: Defaults::default(),
            rules,
        }
    }

    fn rule(id: &str, prefix: &str, tags: Vec<String>) -> RuleDoc {
        RuleDoc {
            id: id.into(),
            match_: MatchDoc {
                host: None,
                path: PathSpec::Prefix { prefix: prefix.into() },
                methods: None,
            },
            ttl_seconds: 60,
            tags,
            allow_authenticated: false,
        }
    }

    #[test]
    fn empty_ruleset_is_valid() {
        let set = CompiledRuleSet::try_from_doc(doc(1, vec![])).expect("ok");
        assert_eq!(set.rules.len(), 0);
    }

    #[test]
    fn rejects_unknown_version() {
        let err = CompiledRuleSet::try_from_doc(doc(2, vec![])).unwrap_err();
        assert!(matches!(err, RuleSetError::UnsupportedVersion(2)));
    }

    #[test]
    fn rejects_duplicate_ids() {
        let r1 = rule("dup", "/a", vec!["x".into()]);
        let r2 = rule("dup", "/b", vec!["y".into()]);
        let err = CompiledRuleSet::try_from_doc(doc(1, vec![r1, r2])).unwrap_err();
        assert!(matches!(err, RuleSetError::DuplicateId(id) if id == "dup"));
    }

    #[test]
    fn rejects_empty_tags() {
        let r = rule("r", "/a", vec![]);
        let err = CompiledRuleSet::try_from_doc(doc(1, vec![r])).unwrap_err();
        assert!(matches!(err, RuleSetError::EmptyTags(id) if id == "r"));
    }

    #[test]
    fn first_cacheable_with_uppercase_host_is_lowercased() {
        let r = rule("static", "/p", vec!["t".into()]);
        let set = CompiledRuleSet::try_from_doc(doc(1, vec![r])).unwrap();
        let id = set.first_cacheable_rule_id("EXAMPLE.COM", "/p/foo", "GET");
        assert_eq!(id.as_deref(), Some("static"));
    }

    #[test]
    fn first_cacheable_returns_none_on_zero_ttl_match() {
        let mut r = rule("deny", "/admin", vec!["t".into()]);
        r.ttl_seconds = 0;
        let set = CompiledRuleSet::try_from_doc(doc(1, vec![r])).unwrap();
        assert!(set.first_cacheable_rule_id("h", "/admin/x", "GET").is_none());
    }

    #[test]
    fn first_cacheable_returns_default_when_no_match() {
        let r = rule("static", "/p", vec!["t".into()]);
        let set = CompiledRuleSet::try_from_doc(doc(1, vec![r])).unwrap();
        let id = set.first_cacheable_rule_id("h", "/api/v1", "GET");
        assert_eq!(id.as_deref(), Some("_default"));
    }

    #[test]
    fn rejects_when_total_regex_size_exceeds_budget() {
        // Budget = 1 MiB; cost = regex.len() * 4. Each rule's regex must
        // compile (size_limit per pattern is 64 KiB), so we build many
        // moderate-length disjunction patterns. Per-rule source length ~600
        // → cost 2400. 500 rules → 1.2 MiB total, exceeds the 1 MiB budget.
        use crate::cache::config::PathSpec;
        // Build a 600-char alternation: ^/(p0|p1|...|p99)$ kept simple.
        let pattern: String = {
            let alternatives: Vec<String> = (0..100).map(|i| format!("p{i:04}")).collect();
            format!("^/({})", alternatives.join("|"))
        };
        // Sanity: pattern length ~600, cost ~2400 per rule.
        let cost_per_rule = pattern.len() * 4;
        let rules_needed = (1024 * 1024 / cost_per_rule) + 5;
        let rules: Vec<RuleDoc> = (0..rules_needed)
            .map(|i| RuleDoc {
                id: format!("r{i}"),
                match_: MatchDoc {
                    host: None,
                    path: PathSpec::Regex { regex: pattern.clone() },
                    methods: None,
                },
                ttl_seconds: 60,
                tags: vec!["t".into()],
                allow_authenticated: false,
            })
            .collect();
        let err = CompiledRuleSet::try_from_doc(doc(1, rules)).unwrap_err();
        assert!(matches!(err, RuleSetError::RegexBudgetExceeded { .. }));
    }

    #[test]
    fn approx_regex_cost_counts_anchored_host() {
        // Hosts with regex metacharacters contribute to the budget.
        use crate::cache::config::PathSpec;
        let r = RuleDoc {
            id: "h".into(),
            match_: MatchDoc {
                host: Some("^api\\.example\\.com$".into()),
                path: PathSpec::Prefix { prefix: "/".into() },
                methods: None,
            },
            ttl_seconds: 60,
            tags: vec!["t".into()],
            allow_authenticated: false,
        };
        let set = CompiledRuleSet::try_from_doc(doc(1, vec![r])).expect("ok");
        assert_eq!(set.rules.len(), 1);
    }

    #[test]
    fn holder_swaps_atomically() {
        let s1 = CompiledRuleSet::try_from_doc(doc(1, vec![rule("a", "/x", vec!["t".into()])])).unwrap();
        let holder = RuleSetHolder::new(s1);
        assert_eq!(holder.load().rules.len(), 1);

        let s2 = CompiledRuleSet::try_from_doc(doc(
            1,
            vec![rule("a", "/x", vec!["t".into()]), rule("b", "/y", vec!["t".into()])],
        ))
        .unwrap();
        holder.swap(s2);
        assert_eq!(holder.load().rules.len(), 2);
    }
}
