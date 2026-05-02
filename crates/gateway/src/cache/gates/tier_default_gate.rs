//! Tier-default gate — terminal gate that always produces `Cache` using the
//! policy's default TTL. Reached only when upstream sent no `Cache-Control`
//! and no earlier gate bypassed.

use std::time::Duration;

use crate::cache::policy::{CacheCtx, CacheGate, Verdict, policy_default_secs};

pub struct TierDefaultGate;

impl CacheGate for TierDefaultGate {
    fn name(&self) -> &'static str {
        "tier_default"
    }

    fn evaluate(&self, ctx: &CacheCtx<'_>) -> Verdict {
        let secs = policy_default_secs(ctx.policy, ctx.default_ttl_secs);
        Verdict::Cache {
            ttl: Duration::from_secs(secs),
            tags: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_common::tier::{CachePolicy, Tier};

    fn ctx(policy: &CachePolicy) -> CacheCtx<'_> {
        CacheCtx {
            tier: Tier::Medium,
            method: "GET",
            status: 200,
            headers: &[],
            cache_control: None,
            policy,
            max_ttl_secs: 3600,
            default_ttl_secs: 60,
        }
    }

    #[test]
    fn aggressive_uses_policy_ttl() {
        let p = CachePolicy::Aggressive { ttl_seconds: 300 };
        match TierDefaultGate.evaluate(&ctx(&p)) {
            Verdict::Cache { ttl, .. } => assert_eq!(ttl.as_secs(), 300),
            _ => panic!("expected Cache"),
        }
    }

    #[test]
    fn short_ttl_uses_policy_ttl() {
        let p = CachePolicy::ShortTtl { ttl_seconds: 120 };
        match TierDefaultGate.evaluate(&ctx(&p)) {
            Verdict::Cache { ttl, .. } => assert_eq!(ttl.as_secs(), 120),
            _ => panic!("expected Cache"),
        }
    }
}
