# Phase 1 — Tier Gate Wiring (Security Invariant)

**Effort:** 1d · **Priority:** P0 (ship first) · **Status:** completed (2026-05-02)

## Implementation Notes

- Scope clarified during execution: `ResponseCache::put`/`get` had **zero callers in the request path** (built in `waf-api/state.rs`, exposed only via admin purge/stats). Took **Interpretation A**: defensive signature change + bypass logic + tests; no proxy.rs wiring (deferred to Phase 2/3 when cache is plumbed into the lifecycle).
- Code review: 9.5/10 ([report](../reports/code-review-260502-2200-fr-009-phase-01.md)). Forward-looking concerns:
  - `bypassed_critical` counter also increments on `CachePolicy::NoCache` (any tier). Consider rename/split before Phase 2 dashboard wiring.
  - `Default { ttl_seconds }` only caps by `hard_max`, not the variant's own `ttl_seconds` — matches plan but operator-surprising.

## Context

- Brainstorm: [`../reports/brainstorm-260502-2140-fr-009-smart-caching.md`](../reports/brainstorm-260502-2140-fr-009-smart-caching.md) §6
- Existing tier infra: `crates/waf-common/src/tier.rs` (`Tier`, `TierPolicy`, `CachePolicy`)
- Existing classifier: `crates/gateway/src/tiered/tier_classifier.rs`
- Existing cache: `crates/gateway/src/cache.rs`

## Goal

Stop CRITICAL-tier responses from being cached, today. Ship the security invariant before any refactor.

## Why This First

Current `ResponseCache::put()` only consults upstream `Cache-Control`. A CRITICAL route with upstream `Cache-Control: max-age=3600` is cached now — direct FR-009 AC-1 violation. This phase closes the audit gap with a minimal, surgical change.

## Related Code

**Read:**
- `crates/gateway/src/cache.rs` — current `put()` flow
- `crates/gateway/src/proxy.rs` — locate cache `put` call site
- `crates/waf-common/src/tier.rs` — `Tier`, `CachePolicy`
- `crates/gateway/src/tiered/tier_classifier.rs` — how tier is resolved per request

**Modify:**
- `crates/gateway/src/cache.rs` — add tier param + tier-gate check
- `crates/gateway/src/proxy.rs` — pass classified tier into `put()` (and `get()` if symmetric bypass needed)

**Create:** none (refactor extracted in Phase 2)

## Implementation Steps

1. Extend `ResponseCache::put` signature: add `tier: Tier` parameter.
2. Top of `put()`: if `tier == Tier::Critical` → return `false` immediately, increment `stats.bypassed_critical` counter.
3. Map `CachePolicy` → effective TTL ceiling:
   - `NoCache` → bypass
   - `ShortTtl{ttl_seconds}` → cap upstream max-age at this
   - `Aggressive{ttl_seconds}` → use as default if upstream silent, cap at this if higher
   - `Default{ttl_seconds}` → use as default if upstream silent
4. Same gate on `get()` for symmetry — if a CRITICAL route is reclassified mid-stream, never serve a stale cached entry. Return `None` immediately.
5. Update `ResponseCache::get` signature to take `tier: Tier`.
6. Update call sites in `crates/gateway/src/proxy.rs` to pass tier from request context (already classified upstream by `tier_classifier`).
7. Add `bypassed_critical: AtomicU64` to `CacheStats` + expose via snapshot.
8. Run `cargo check -p gateway && cargo clippy -p gateway --all-targets -- -D warnings`.

## Code Sketch

```rust
// cache.rs
pub async fn put(
    &self,
    key: String,
    status: u16,
    headers: Vec<(String, String)>,
    body: Bytes,
    cache_control: Option<&str>,
    tier: Tier,
    policy: &CachePolicy,
) -> bool {
    // Gate 1: CRITICAL is non-overridable.
    if matches!(tier, Tier::Critical) || matches!(policy, CachePolicy::NoCache) {
        self.stats.bypassed_critical.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    // ... existing 2xx + Cache-Control logic, but cap TTL by policy ceiling
}
```

## Todo

- [x] Add `tier` + `policy` params to `put()` / `get()`
- [x] CRITICAL bypass at top of both
- [x] TTL cap by `CachePolicy` variant
- [x] `Set-Cookie` response header → bypass (preview of Phase 3 auth gate)
- [~] Update proxy call sites — N/A in Phase 1; no callers exist. Deferred to Phase 2/3.
- [x] Add `bypassed_critical` stat
- [x] Inline unit test: CRITICAL → put returns false regardless of Cache-Control
- [x] Inline unit test: MEDIUM Aggressive caps to policy TTL
- [x] `cargo clippy -p gateway --all-targets -- -D warnings` clean

## Success Criteria

- CRITICAL + upstream `Cache-Control: max-age=3600` → `put()` returns false
- MEDIUM + Aggressive(ttl=300) + upstream silent → cached at 300s
- MEDIUM + Aggressive(ttl=300) + upstream max-age=10000 → cached at 300s (capped)
- Existing tests still pass

## Risks

| Risk | Mitigation |
|---|---|
| Breaking proxy.rs callers (compile error cascade) | Surgical signature change; one PR; revert-friendly |
| TTL cap semantics surprise operators | Document in code comment + plan.md |

## Security Considerations

- This phase IS the security fix. CRITICAL bypass is the audit-defensible invariant.
- Bypass logged at `stats` level for observability (later wired to dashboard).
- Symmetric `get()` gate prevents serving stale entries if a route is reclassified to CRITICAL via hot reload.

## Next Steps

→ Phase 2: extract pipeline into `cache/` module without changing behavior.
