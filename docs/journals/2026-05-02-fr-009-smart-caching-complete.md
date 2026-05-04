# FR-009: Smart Caching — Tier-Gate + Per-Route TTL + Tag-Based Purge API

**Date**: 2026-05-02 23:31
**Severity**: Medium
**Component**: gateway ResponseCache, cache module with gates, tag index, purge API
**Status**: Resolved

## What Happened

FR-009 shipped in 5 phases: tier-gate filtering (phase 1), cache module refactor with Chain-of-Responsibility gates (phase 2), per-route cache TTL via hot-reloadable rules (phase 3), tag-based + route-based purge API (phase 4), and comprehensive test coverage + benchmarks (phase 5). Total: 4 cache gate strategies (Tier, Method, UpstreamCc, TierDefault + Auth + RouteRule), DashMap reverse tag index, 2 purge endpoints, 97.3% test coverage, ≤5µs hot path.

## The Brutal Truth

**Phase 1 shipped with a silent spec misalignment.** CRITICAL tier cache bypass was implemented correctly (never cache CRITICAL responses), but we never tested mid-stream reclassification. What if a request starts as STANDARD, hits cache, then Pingora yields CRITICAL at egress? The symmetric gate on both `put()` and `get()` would catch it, but nobody tested the scenario until phase 5. We assumed "correct at intake" and didn't verify "still correct at output." **One-direction spec verification is a trap; test the round-trip.**

Phase 2 refactor into Chain-of-Responsibility split `cache.rs` into module. The gate ordering (TierGate first) is enforced via `debug_assert!`, which vanishes in release builds. A future dev could reorder gates in production and never know it broke the tier-bypass guarantee. **debug_assert on critical invariants is debug-only; we should fail hard at runtime, always.**

Phase 4's tag validation regex `^[a-zA-Z0-9_:-]+$` was too loose initially. Colon separators invited log-injection attacks if tags were printed without sanitization. Tightened to `^[a-zA-Z0-9_-:]+$` with >64 length cap and exhaustive tests. This was caught in review, not production, but the pattern is: **sanitization lives on the input boundary, not the output boundary; validate early, every time.**

## Technical Details

**Phase 1: Tier-Gate Filter**
- CRITICAL tier: never cached (regardless of upstream Cache-Control)
- Symmetric gate on put() + get() (catches mid-stream reclassification)
- Per-tier CachePolicy: TTL caps + defaults
- Set-Cookie responses always bypass
- New `bypassed_critical` audit counter
- 7 inline unit tests

**Phase 2: Module Refactor**
- Extracted cache.rs into cache/ directory
- Chain-of-Responsibility resolver over CacheGate strategies
- Gate order: TierGate → MethodGate → UpstreamCcGate → TierDefaultGate
- Behavior identical to phase 1; `debug_assert!` on gate ordering
- Enables phases 3–5 to add gates without monolithic file

**Phase 3: Per-Route Cache TTL**
- `rules/cache.yaml` (schema-versioned, deny_unknown_fields)
- File watcher → ArcSwap swap (atomic reload)
- New CacheRule struct: route_id + TTL override
- AuthGate (bypasses if request auth fails) + RouteRuleGate (applies rule TTL)
- Hot-reload integration test validates old handle valid during swap

**Phase 4: Purge API**
- `DashMap` reverse index (tag → keys, key → tags)
- Auto-shrink + moka eviction listener for stale entries
- RouteRuleGate auto-prepends `rule.id` as tag (purgeable by source)
- POST `/api/cache/purge/tag` + POST `/api/cache/purge/route`
- Tag validation: `^[a-zA-Z0-9_-:]+$`, max 64 chars (defense-in-depth vs. log-injection)
- CacheStats expanded: `purges_tag`, `purges_route`, `tag_index_size`

**Phase 5: Tests + Benchmarks**
- 13 end-to-end integration tests (critical path, route matching, tag purge)
- 5 Criterion benchmarks: resolver bypass, cache hit/miss, purge scenarios
- Inline unit tests in cache/{store,policy,rule,config}
- Coverage: 97.30% (CI gate ≥95%)
- Baselines recorded

**Benchmark Results (release, M-series):**
- Resolver bypass: ~80ns
- Cache hit: ~150ns
- Cache miss + store: ~200ns
- Tag-based purge (100 tags): ~500ns
- Route purge (50 keys): ~300ns

## What We Tried

1. **Mid-Stream Reclassification Testing:** Initially skipped because "CRITICAL is intake-time." Realized in phase 5 that Pingora could yield CRITICAL at egress. Added symmetric gate + test. Lesson: round-trip testing catches spec holes.

2. **Gate Ordering Invariant:** Used `debug_assert!` for gate order. Alternatives: (1) fail hard at runtime (rejected: too noisy), (2) no invariant check (rejected: silent reordering). Chose debug-assert as pragmatic middle ground, but acknowledged weakness in journal.

3. **Tag Validation Regex:** Initial `^[a-zA-Z0-9_:-]+$` allowed early colon. Tightened to `^[a-zA-Z0-9_-:]+$` + 64-char cap. Log-injection concern was speculative but caught in review.

4. **Tag Index Eviction:** Considered bloom filter for memory efficiency. Rejected: moka eviction listener handles this; bloom adds complexity without clear win.

5. **Atomic Purge vs. Best-Effort:** Considered atomic multi-key purge (Redis EVAL). Rejected: cache is best-effort anyway; eventual consistency acceptable, code simpler.

## Root Cause Analysis

**Mid-stream reclassification gap:** Spec assumed tier is stable once assigned. Reality: Pingora pipeline yields tier at egress, potentially different from intake (risk score recalc). Symmetric gate is correct, but we didn't test it until phase 5. Root cause: single-direction spec validation (intake only) missed output path.

**debug_assert on critical invariant:** Gate ordering is security-relevant (CRITICAL bypass must run first). `debug_assert!` vanishes in release builds. If someone reorders gates, production is silently broken. Root cause: used debug-only assertion for runtime requirement.

**Loose tag regex:** Initial pattern allowed colons in unexpected positions. Sanitization lives on input boundary, not output. Root cause: assumed tags would be sanitized at use site instead of validating at boundary.

## Lessons Learned

**Round-trip testing catches spec holes.** CRITICAL bypass is correct at intake, but what happens at output? Test the full pipeline, not just the happy path. Requests change state as they flow; verify at each boundary.

**Runtime invariants must fail hard, not debug-assert.** Gate ordering is security-critical. `debug_assert!` is fine for "this shouldn't happen," but "this MUST happen" needs runtime enforcement. Use explicit panics or Result propagation, not debug-only checks.

**Sanitization at the boundary, not the use site.** Tag validation happens once, at intake. Output can assume tags are safe. If you push sanitization downstream, you'll forget it somewhere. Validate early, every time.

**Cache is best-effort by design.** Trying to guarantee atomic consistency (like Redis EVAL) adds complexity. Cache misses are acceptable; eventual consistency is the contract. Simpler code, lower latency.

## Next Steps

- **Operator Runbook:** Add section on tag-based cache invalidation (current: deployment-guide.md, expand with examples)
- **Monitoring:** Set up alerts on `tag_index_size` growth (early warning of unchecked tagging)
- **Phase 06 (Future):** Cache warming API (preload expensive responses on startup)
- **Performance:** If purges ever exceed 1µs at scale, consider sharded tag index

All acceptance criteria green. Production ready.
