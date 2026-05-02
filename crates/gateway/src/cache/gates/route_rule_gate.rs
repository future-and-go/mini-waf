//! Route-rule gate — walk the compiled ruleset and apply the first match.
//!
//! Verdict semantics:
//! - First matching rule wins (declaration order in YAML).
//! - `ttl_seconds == 0` → explicit bypass (operator opt-out via config).
//! - No match → `Continue` so `UpstreamCcGate` / `TierDefaultGate` decide.

use std::sync::Arc;
use std::time::Duration;

use crate::cache::policy::{BypassReason, CacheCtx, CacheGate, Verdict};
use crate::cache::rule_set::RuleSetHolder;

pub struct RouteRuleGate {
    holder: Arc<RuleSetHolder>,
}

impl RouteRuleGate {
    pub const fn new(holder: Arc<RuleSetHolder>) -> Self {
        Self { holder }
    }
}

impl CacheGate for RouteRuleGate {
    fn name(&self) -> &'static str {
        "route_rule"
    }

    fn evaluate(&self, ctx: &CacheCtx<'_>) -> Verdict {
        let set = self.holder.load();
        // Caller normalizes host once; we only ASCII-lower here defensively.
        // Rules already store lowercase, so passing host as-is would mis-match
        // if upstream provided a mixed-case authority.
        let host_lower_owned;
        let host_lower: &str = if ctx.host.bytes().all(|b| !b.is_ascii_uppercase()) {
            ctx.host
        } else {
            host_lower_owned = ctx.host.to_ascii_lowercase();
            host_lower_owned.as_str()
        };

        for rule in set.rules.iter() {
            if !rule.matches_str(host_lower, ctx.path, ctx.method) {
                continue;
            }
            if rule.ttl.is_zero() {
                return Verdict::Bypass(BypassReason::ExplicitDeny);
            }
            // `allow_authenticated` is recorded but inert in v1: AuthGate
            // already ran before us and bypassed any authenticated request.
            // Documented in the plan — see open Q1.
            // FR-009 Phase 4: prepend rule.id as a tag so every entry cached
            // by this rule is purgeable via `purge_by_route_id`. Operators
            // get free per-rule invalidation without authoring a dedicated
            // tag.
            let mut tags = Vec::with_capacity(rule.tags.len() + 1);
            tags.push(Arc::clone(&rule.id));
            tags.extend(rule.tags.iter().cloned());
            return Verdict::Cache {
                ttl: cap(rule.ttl, ctx.max_ttl_secs),
                tags,
            };
        }
        Verdict::Continue
    }
}

fn cap(ttl: Duration, max_secs: u64) -> Duration {
    let s = ttl.as_secs().min(max_secs);
    Duration::from_secs(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::config::{CacheConfigDoc, Defaults, MatchDoc, PathSpec, RuleDoc};
    use crate::cache::rule_set::CompiledRuleSet;
    use waf_common::tier::{CachePolicy, Tier};

    const POLICY: CachePolicy = CachePolicy::Aggressive { ttl_seconds: 300 };

    fn rule_doc(id: &str, prefix: &str, ttl: u32) -> RuleDoc {
        RuleDoc {
            id: id.into(),
            match_: MatchDoc {
                host: None,
                path: PathSpec::Prefix { prefix: prefix.into() },
                methods: None,
            },
            ttl_seconds: ttl,
            tags: vec!["t".into()],
            allow_authenticated: false,
        }
    }

    fn holder(rules: Vec<RuleDoc>) -> Arc<RuleSetHolder> {
        let set = CompiledRuleSet::try_from_doc(CacheConfigDoc {
            version: 1,
            defaults: Defaults::default(),
            rules,
        })
        .unwrap();
        RuleSetHolder::new(set)
    }

    fn ctx_for(host: &'static str, path: &'static str) -> CacheCtx<'static> {
        CacheCtx {
            tier: Tier::Medium,
            method: "GET",
            host,
            path,
            status: 200,
            headers: &[],
            cache_control: None,
            policy: &POLICY,
            max_ttl_secs: 3600,
            default_ttl_secs: 60,
            has_authorization: false,
            has_cookie: false,
        }
    }

    #[test]
    fn first_match_wins_with_ttl() {
        let h = holder(vec![rule_doc("static", "/static/", 600), rule_doc("all", "/", 30)]);
        let g = RouteRuleGate::new(h);
        match g.evaluate(&ctx_for("example.com", "/static/x.css")) {
            Verdict::Cache { ttl, .. } => assert_eq!(ttl.as_secs(), 600),
            v => panic!("expected Cache, got {v:?}"),
        }
    }

    #[test]
    fn ttl_zero_is_explicit_bypass() {
        let h = holder(vec![rule_doc("deny", "/admin", 0)]);
        let g = RouteRuleGate::new(h);
        assert!(matches!(
            g.evaluate(&ctx_for("example.com", "/admin/users")),
            Verdict::Bypass(BypassReason::ExplicitDeny)
        ));
    }

    #[test]
    fn no_match_continues() {
        let h = holder(vec![rule_doc("static", "/static/", 600)]);
        let g = RouteRuleGate::new(h);
        assert!(matches!(
            g.evaluate(&ctx_for("example.com", "/api/x")),
            Verdict::Continue
        ));
    }

    #[test]
    fn empty_ruleset_continues() {
        let h = RuleSetHolder::new(CompiledRuleSet::empty());
        let g = RouteRuleGate::new(h);
        assert!(matches!(g.evaluate(&ctx_for("example.com", "/x")), Verdict::Continue));
    }

    #[test]
    fn ttl_capped_by_max_ttl_secs() {
        let h = holder(vec![rule_doc("big", "/", 999_999)]);
        let g = RouteRuleGate::new(h);
        match g.evaluate(&ctx_for("example.com", "/x")) {
            Verdict::Cache { ttl, .. } => assert_eq!(ttl.as_secs(), 3600),
            v => panic!("expected Cache, got {v:?}"),
        }
    }

    // Helper for the Verdict pattern (no Debug derive on Verdict).
    impl std::fmt::Debug for Verdict {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Continue => write!(f, "Continue"),
                Self::Bypass(r) => write!(f, "Bypass({r:?})"),
                Self::Cache { ttl, tags } => write!(f, "Cache{{ttl={ttl:?}, tags={tags:?}}}"),
            }
        }
    }
}
