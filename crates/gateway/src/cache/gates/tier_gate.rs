//! Tier gate — non-overridable bypass for CRITICAL traffic and `NoCache`
//! policy. MUST be index 0 in the resolver chain (FR-009 AC-1).

use waf_common::tier::{CachePolicy, Tier};

use crate::cache::policy::{BypassReason, CacheCtx, CacheGate, Verdict};

pub struct TierGate;

impl CacheGate for TierGate {
    fn name(&self) -> &'static str {
        "tier"
    }

    fn evaluate(&self, ctx: &CacheCtx<'_>) -> Verdict {
        if matches!(ctx.tier, Tier::Critical) {
            return Verdict::Bypass(BypassReason::CriticalTier);
        }
        if matches!(ctx.policy, CachePolicy::NoCache) {
            return Verdict::Bypass(BypassReason::NoCachePolicy);
        }
        Verdict::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(tier: Tier, policy: &CachePolicy) -> CacheCtx<'_> {
        CacheCtx {
            tier,
            method: "GET",
            host: "h",
            path: "/",
            status: 200,
            headers: &[],
            cache_control: None,
            policy,
            max_ttl_secs: 3600,
            default_ttl_secs: 60,
            has_authorization: false,
            has_cookie: false,
        }
    }

    #[test]
    fn critical_tier_bypasses() {
        let p = CachePolicy::Aggressive { ttl_seconds: 300 };
        assert!(matches!(
            TierGate.evaluate(&ctx(Tier::Critical, &p)),
            Verdict::Bypass(BypassReason::CriticalTier)
        ));
    }

    #[test]
    fn no_cache_policy_bypasses_even_for_catch_all_tier() {
        let p = CachePolicy::NoCache;
        assert!(matches!(
            TierGate.evaluate(&ctx(Tier::CatchAll, &p)),
            Verdict::Bypass(BypassReason::NoCachePolicy)
        ));
    }

    #[test]
    fn medium_tier_with_cacheable_policy_continues() {
        let p = CachePolicy::Aggressive { ttl_seconds: 300 };
        assert!(matches!(TierGate.evaluate(&ctx(Tier::Medium, &p)), Verdict::Continue));
    }
}
