//! Upstream Cache-Control gate — inspects the response itself.
//!
//! Bypasses when:
//! - status is not 2xx
//! - any `Set-Cookie` header is present (per-user response)
//! - `Cache-Control: no-store | no-cache | private`
//!
//! Otherwise, if upstream sent `max-age=N`, returns `Cache{ ttl: min(N,
//! policy_ceiling, max_ttl) }`. Else `Continue` so `TierDefaultGate` applies
//! the policy default.

use std::time::Duration;

use crate::cache::policy::{BypassReason, CacheCtx, CacheGate, Verdict, policy_ceiling_secs};

pub struct UpstreamCcGate;

impl CacheGate for UpstreamCcGate {
    fn name(&self) -> &'static str {
        "upstream_cc"
    }

    fn evaluate(&self, ctx: &CacheCtx<'_>) -> Verdict {
        if !(200..300).contains(&ctx.status) {
            return Verdict::Bypass(BypassReason::NonCacheableStatus);
        }
        if ctx
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        {
            return Verdict::Bypass(BypassReason::SetCookie);
        }
        match parse_cache_control(ctx.cache_control) {
            CcDecision::NoStore => Verdict::Bypass(BypassReason::UpstreamNoStore),
            CcDecision::NoCache => Verdict::Bypass(BypassReason::UpstreamNoCache),
            CcDecision::Private => Verdict::Bypass(BypassReason::UpstreamPrivate),
            CcDecision::MaxAge(secs) => {
                let ceiling = policy_ceiling_secs(ctx.policy, ctx.max_ttl_secs);
                let ttl = secs.min(ceiling).min(ctx.max_ttl_secs);
                Verdict::Cache {
                    ttl: Duration::from_secs(ttl),
                    tags: Vec::new(),
                }
            }
            CcDecision::None => Verdict::Continue,
        }
    }
}

enum CcDecision {
    None,
    NoStore,
    NoCache,
    Private,
    MaxAge(u64),
}

/// Match the original `cache.rs` parser exactly: directive priority is
/// no-store > no-cache > private > max-age. Substring match (not strict CSV
/// split) preserved so behavior is byte-identical to Phase 1.
fn parse_cache_control(header: Option<&str>) -> CcDecision {
    let Some(header) = header else {
        return CcDecision::None;
    };
    let lower = header.to_lowercase();
    if lower.contains("no-store") {
        return CcDecision::NoStore;
    }
    if lower.contains("no-cache") {
        return CcDecision::NoCache;
    }
    if lower.contains("private") {
        return CcDecision::Private;
    }
    for part in lower.split(',') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("max-age=")
            && let Ok(secs) = rest.trim().parse::<u64>()
        {
            return CcDecision::MaxAge(secs);
        }
    }
    CcDecision::None
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_common::tier::{CachePolicy, Tier};

    const POLICY: CachePolicy = CachePolicy::Aggressive { ttl_seconds: 300 };

    fn ctx<'a>(status: u16, headers: &'a [(String, String)], cc: Option<&'a str>) -> CacheCtx<'a> {
        CacheCtx {
            tier: Tier::Medium,
            method: "GET",
            status,
            headers,
            cache_control: cc,
            policy: &POLICY,
            max_ttl_secs: 3600,
            default_ttl_secs: 60,
        }
    }

    #[test]
    fn non_2xx_bypasses() {
        assert!(matches!(
            UpstreamCcGate.evaluate(&ctx(404, &[], None)),
            Verdict::Bypass(BypassReason::NonCacheableStatus)
        ));
    }

    #[test]
    fn set_cookie_bypasses() {
        let h = vec![("Set-Cookie".into(), "sid=abc".into())];
        assert!(matches!(
            UpstreamCcGate.evaluate(&ctx(200, &h, Some("max-age=60"))),
            Verdict::Bypass(BypassReason::SetCookie)
        ));
    }

    #[test]
    fn no_store_bypasses() {
        assert!(matches!(
            UpstreamCcGate.evaluate(&ctx(200, &[], Some("no-store"))),
            Verdict::Bypass(BypassReason::UpstreamNoStore)
        ));
    }

    #[test]
    fn max_age_capped_by_policy_ceiling() {
        // Aggressive ceiling = 300; upstream says 10000 → expect 300.
        let v = UpstreamCcGate.evaluate(&ctx(200, &[], Some("max-age=10000")));
        match v {
            Verdict::Cache { ttl, .. } => assert_eq!(ttl.as_secs(), 300),
            _ => panic!("expected Cache verdict"),
        }
    }

    #[test]
    fn no_cache_control_continues_to_default_gate() {
        assert!(matches!(
            UpstreamCcGate.evaluate(&ctx(200, &[], None)),
            Verdict::Continue
        ));
    }
}
