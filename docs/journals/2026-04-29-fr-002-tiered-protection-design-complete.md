# FR-002 Tiered Protection: Design Phase Complete

**Date**: 2026-04-29 10:30  
**Severity**: Medium  
**Component**: Policy System / Request Classification  
**Status**: Planning Complete → Ready for Implementation  

## What Happened

Completed full design and planning phase for FR-002 (Tiered Protection), a foundational policy classification system that downstream features (FR-005/006/009/027) depend on. Locked five architectural decisions and created comprehensive 6-phase implementation plan.

## The Brutal Truth

This feels right. FR-002 is the *policy bus* — everything else plugs into it. Getting the architecture wrong here cascades downstream. High-stakes design work, but we've documented it thoroughly enough that implementation should be mechanical.

## Technical Details

**Five Key Decisions Locked:**
1. **Classifier inputs**: path + host + method + header (no body, no latency-sensitive features)
2. **Storage**: TOML in `configs/default.toml` (mirrors existing rule storage pattern)
3. **Pattern**: Strategy + Registry using `ArcSwap` for hot-reload (mirrors `crates/gateway/src/policies/`)
4. **Hot-reload**: Built in from day one, not bolted on later
5. **Tier type**: Closed enum (4 variants: CRITICAL/HIGH/MEDIUM/CATCH-ALL) — no String escape hatch

**Architecture Insight:**  
Classifier is a *request→tier mapper* (precompiled rules as bitset for MethodSet). Registry is *tier→policy resolver*. Two clean halves, ArcSwap at seams for lock-free hot-reload.

## Lessons Learned

**Constraint-first design works.** Saying "no body, no unbound strings" forced us toward simpler, more testable patterns. Pattern mirrors existing gateway code — good signal we're not inventing.

**Async-notify for config watching beats polling.** Locked that now rather than discovering it during tests.

**Unresolved questions don't kill plans.** Two open questions (header case-sensitivity, regex flavor) documented in design § 15 — implementation can lock these with explicit test cases, no guessing.

## Next Steps

Plan blocked on FR-001 (reverse proxy) completion — expected 48h. When FR-001 lands, Phase 1 (types/schema in waf-common) can start immediately. Estimated total effort: 3 dev-days across 6 phases.

**Artifacts**: `plans/260429-1006-fr-002-tiered-protection/` (plan.md + phases) + design doc in plans/reports/.
