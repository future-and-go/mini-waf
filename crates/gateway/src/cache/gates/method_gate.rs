//! Method gate — only GET and HEAD are cacheable. Everything else (POST,
//! PUT, DELETE, PATCH, OPTIONS, …) bypasses with `NonIdempotentMethod`.

use crate::cache::policy::{BypassReason, CacheCtx, CacheGate, Verdict};

pub struct MethodGate;

impl CacheGate for MethodGate {
    fn name(&self) -> &'static str {
        "method"
    }

    fn evaluate(&self, ctx: &CacheCtx<'_>) -> Verdict {
        if ctx.method.eq_ignore_ascii_case("GET") || ctx.method.eq_ignore_ascii_case("HEAD") {
            Verdict::Continue
        } else {
            Verdict::Bypass(BypassReason::NonIdempotentMethod)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_common::tier::{CachePolicy, Tier};

    fn ctx(method: &str) -> CacheCtx<'_> {
        // policy reference must outlive ctx — caller passes a borrow.
        // For a simple test we use a long-lived static via Box::leak in real
        // tests; here we sidestep by inlining the policy literal at call site.
        const POLICY: CachePolicy = CachePolicy::Default { ttl_seconds: 60 };
        CacheCtx {
            tier: Tier::Medium,
            method,
            host: "h",
            path: "/",
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
    fn get_continues() {
        assert!(matches!(MethodGate.evaluate(&ctx("GET")), Verdict::Continue));
    }

    #[test]
    fn head_continues_case_insensitive() {
        assert!(matches!(MethodGate.evaluate(&ctx("head")), Verdict::Continue));
    }

    #[test]
    fn post_bypasses() {
        assert!(matches!(
            MethodGate.evaluate(&ctx("POST")),
            Verdict::Bypass(BypassReason::NonIdempotentMethod)
        ));
    }
}
