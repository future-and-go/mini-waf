//! Cache decision pipeline — Chain of Responsibility over `CacheGate`s.
//!
//! `ResponseCache::put` walks `CachePolicyResolver`'s gate list; the first
//! gate that returns `Bypass` or `Cache` wins. `Continue` defers to the next
//! gate. If no gate decides, the resolver returns `Bypass(NoMatch)` so the
//! caller never has to handle a "Continue" terminal state.
//!
//! Phase 2 ships four gates (tier, method, upstream Cache-Control, tier
//! default). Phase 3 will add Auth + `RouteRule` gates without touching `put`.

use std::sync::Arc;
use std::time::Duration;

use waf_common::tier::{CachePolicy, Tier};

/// Why a request/response was excluded from the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassReason {
    /// CRITICAL-tier touch — never cacheable. Counts toward `bypassed_critical`.
    CriticalTier,
    /// Per-host policy is `NoCache`. Counts toward `bypassed_critical`.
    NoCachePolicy,
    /// Method is not GET/HEAD.
    NonIdempotentMethod,
    /// Response status not in 2xx.
    NonCacheableStatus,
    /// Response carries `Set-Cookie` — per-user, never shared.
    SetCookie,
    /// Upstream `Cache-Control: no-store`.
    UpstreamNoStore,
    /// Upstream `Cache-Control: no-cache`.
    UpstreamNoCache,
    /// Upstream `Cache-Control: private`.
    UpstreamPrivate,
    /// Request bears `Authorization` or `Cookie` — never shared in v1.
    /// `AuthGate` (FR-009 Phase 3).
    Authenticated,
    /// A matched route rule has `ttl_seconds: 0` — operator opt-out.
    /// `RouteRuleGate` (FR-009 Phase 3).
    ExplicitDeny,
    /// No gate produced a definitive verdict (defensive terminal).
    NoMatch,
}

/// Outcome of a single gate's evaluation.
pub enum Verdict {
    /// Skip caching for this exact reason.
    Bypass(BypassReason),
    /// Cache with this TTL. `tags` reserved for Phase 4 (tag-based purge).
    Cache { ttl: Duration, tags: Vec<Arc<str>> },
    /// Defer to the next gate.
    Continue,
}

/// Borrowed view passed through the gate chain. Keeps gates allocation-free.
pub struct CacheCtx<'a> {
    pub tier: Tier,
    pub method: &'a str,
    /// Request authority host (already lowercased upstream when possible).
    /// FR-009 Phase 3: consumed by `RouteRuleGate`.
    pub host: &'a str,
    /// Request path (no query). FR-009 Phase 3: consumed by `RouteRuleGate`.
    pub path: &'a str,
    pub status: u16,
    pub headers: &'a [(String, String)],
    pub cache_control: Option<&'a str>,
    pub policy: &'a CachePolicy,
    /// Hard ceiling from `ResponseCache::max_ttl`.
    pub max_ttl_secs: u64,
    /// Fallback when policy has no TTL (defensive — `NoCache` is bypassed
    /// upstream by `TierGate`, so this is rarely reached).
    pub default_ttl_secs: u64,
    /// Pre-probed: request had an `Authorization` header. FR-009 Phase 3.
    pub has_authorization: bool,
    /// Pre-probed: request had a `Cookie` header. FR-009 Phase 3.
    pub has_cookie: bool,
}

/// Single decision step. Implementors live in `cache::gates`.
pub trait CacheGate: Send + Sync {
    fn name(&self) -> &'static str;
    fn evaluate(&self, ctx: &CacheCtx<'_>) -> Verdict;
}

/// Runs gates in order; first non-`Continue` wins.
pub struct CachePolicyResolver {
    gates: Vec<Box<dyn CacheGate>>,
}

impl CachePolicyResolver {
    pub fn new(gates: Vec<Box<dyn CacheGate>>) -> Self {
        // FR-009 AC-1 invariant: TierGate MUST run first so CRITICAL bypass
        // cannot be shadowed by a later gate.
        debug_assert!(
            gates.first().is_some_and(|g| g.name() == "tier"),
            "TierGate must be the first gate in the resolver chain"
        );
        Self { gates }
    }

    pub fn resolve(&self, ctx: &CacheCtx<'_>) -> Verdict {
        for gate in &self.gates {
            let v = gate.evaluate(ctx);
            if !matches!(v, Verdict::Continue) {
                return v;
            }
        }
        Verdict::Bypass(BypassReason::NoMatch)
    }

    /// Used by tests/asserts to verify gate ordering.
    pub fn gate_names(&self) -> Vec<&'static str> {
        self.gates.iter().map(|g| g.name()).collect()
    }
}

/// Per-tier policy ceiling — caps an upstream-supplied `max-age`.
/// `NoCache` returns 0 (defensive; it's bypassed upstream).
pub fn policy_ceiling_secs(policy: &CachePolicy, hard_max: u64) -> u64 {
    match policy {
        CachePolicy::NoCache => 0,
        CachePolicy::ShortTtl { ttl_seconds } | CachePolicy::Aggressive { ttl_seconds } => u64::from(*ttl_seconds),
        CachePolicy::Default { .. } => hard_max,
    }
}

/// TTL to use when upstream sent no `Cache-Control`. Falls back to the
/// caller-supplied `fallback_secs` only for `NoCache` (unreachable in practice).
pub fn policy_default_secs(policy: &CachePolicy, fallback_secs: u64) -> u64 {
    match policy {
        CachePolicy::NoCache => fallback_secs,
        CachePolicy::ShortTtl { ttl_seconds }
        | CachePolicy::Aggressive { ttl_seconds }
        | CachePolicy::Default { ttl_seconds } => u64::from(*ttl_seconds),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::gates::{MethodGate, TierDefaultGate, TierGate, UpstreamCcGate};

    #[test]
    fn resolver_runs_gates_in_order_tier_first() {
        let resolver = CachePolicyResolver::new(vec![
            Box::new(TierGate),
            Box::new(MethodGate),
            Box::new(UpstreamCcGate),
            Box::new(TierDefaultGate),
        ]);
        assert_eq!(
            resolver.gate_names(),
            vec!["tier", "method", "upstream_cc", "tier_default"]
        );
    }

    #[test]
    #[should_panic(expected = "TierGate must be the first")]
    fn resolver_rejects_non_tier_first_gate() {
        let _ = CachePolicyResolver::new(vec![Box::new(MethodGate), Box::new(TierGate)]);
    }

    // Defensive arms: every CachePolicy variant resolved by the helpers.
    #[test]
    fn policy_ceiling_handles_no_cache_and_default() {
        assert_eq!(policy_ceiling_secs(&CachePolicy::NoCache, 3600), 0);
        assert_eq!(
            policy_ceiling_secs(&CachePolicy::Default { ttl_seconds: 60 }, 3600),
            3600,
            "Default falls back to hard_max"
        );
    }

    #[test]
    fn policy_default_secs_handles_no_cache_fallback() {
        // NoCache is unreachable in practice (TierGate bypasses upstream), but
        // the defensive arm must still return the caller-provided fallback.
        assert_eq!(policy_default_secs(&CachePolicy::NoCache, 42), 42);
    }
}
