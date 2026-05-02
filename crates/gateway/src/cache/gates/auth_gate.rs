//! Auth gate — bypass cache for any request bearing `Authorization` or `Cookie`.
//!
//! Conservative-by-default: v1 ALWAYS bypasses authenticated requests, even
//! when the matched route declares `allow_authenticated: true`. Per-user
//! caching needs key-dim hashing (deferred — plan.md open Q1).
//!
//! Resolver position: AFTER `MethodGate` (cheap rejects first), BEFORE
//! `RouteRuleGate` (so authenticated requests bypass without paying for the
//! rule walk).

use crate::cache::policy::{BypassReason, CacheCtx, CacheGate, Verdict};

pub struct AuthGate;

impl CacheGate for AuthGate {
    fn name(&self) -> &'static str {
        "auth"
    }

    fn evaluate(&self, ctx: &CacheCtx<'_>) -> Verdict {
        // The two probes are pre-computed by the caller (see `CacheCtx`),
        // so this is a single bool check per request — no header re-parse.
        if ctx.has_authorization || ctx.has_cookie {
            return Verdict::Bypass(BypassReason::Authenticated);
        }
        Verdict::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_common::tier::{CachePolicy, Tier};

    const POLICY: CachePolicy = CachePolicy::Aggressive { ttl_seconds: 300 };

    fn ctx(has_auth: bool, has_cookie: bool) -> CacheCtx<'static> {
        CacheCtx {
            tier: Tier::Medium,
            method: "GET",
            host: "example.com",
            path: "/",
            status: 200,
            headers: &[],
            cache_control: None,
            policy: &POLICY,
            max_ttl_secs: 3600,
            default_ttl_secs: 60,
            has_authorization: has_auth,
            has_cookie,
        }
    }

    #[test]
    fn authorization_bypasses() {
        assert!(matches!(
            AuthGate.evaluate(&ctx(true, false)),
            Verdict::Bypass(BypassReason::Authenticated)
        ));
    }

    #[test]
    fn cookie_bypasses() {
        assert!(matches!(
            AuthGate.evaluate(&ctx(false, true)),
            Verdict::Bypass(BypassReason::Authenticated)
        ));
    }

    #[test]
    fn anonymous_request_continues() {
        assert!(matches!(AuthGate.evaluate(&ctx(false, false)), Verdict::Continue));
    }
}
