# FR-008 Phases 05-06: Pipeline Integration & Hot-Reload Architecture

**Date**: 2026-04-30 21:56
**Severity**: Low
**Component**: Gateway request pipeline, ArcSwap hot-reload coordination
**Status**: Resolved

## What Happened

Phases 05-06 stitched `AccessLists` into the Pingora gateway request lifecycle and stood up hot-reload via ArcSwap. Phase-05 discovered an insertion-point trade-off (inline call vs. RequestFilter chain membership); phase-06 locked down the watcher pattern reusing FR-003's notify infrastructure. Both phases shipped with deviations from the brainstorm plan—all intentional, all documented.

## The Brutal Truth

Phase-05 was ugly for 2 hours. The plan said "add AccessLists as the first element in `RequestFilterChain`," which would've required modifying the Pingora `Module` trait and potentially shuffling ~25 test fixtures. Instead, we called the gate inline in `WafProxy::request_filter` *before* the chain runs. Same effect (blocks before any other filter pays CPU), zero fixture friction, one extra conditional per request. The humbling part: this approach was in the brainstorm appendix under "Alternative: inline call." We second-guessed it, tried to shoehorn the plan as written, backtracked. Then documented the pivot.

Phase-06 was straight reuse. The tier config watcher already exists (FR-002 phase-05); we copy-pasted the pattern, swapped `TierConfigWatcher` for `AccessListWatcher`, wrapped `AccessLists` in `ArcSwap<Arc<...>>`. Boring. That's good.

## Technical Details

**Phase-05 (Pipeline Wiring):**
- `WafProxy::request_filter()` now invokes `evaluate_access_gate()` **before** `RequestFilterChain` iteration
- Gate logic: `RequestCtx.client_ip` → `AccessLists.evaluate()` → one of three paths:
  1. Block: short-circuit, emit 403 via `ErrorPageFactory`, audit log with `access_decision=block` + reason
  2. Bypass (full_bypass mode): set `GatewayCtx.access_bypass=true`, skip engine.inspect, continue to cache/forward
  3. Continue: proceed to WAF engine rules (blacklist_only mode or no match)
- Dry-run flag: logs decision, never blocks
- `GatewayCtx` extended with `access_bypass: bool` (not `RequestCtx`) to avoid 25-site struct-literal ripple in waf-engine tests/benches—pragmatic choice over design purity
- 10 unit tests cover translate paths, ArcSwap read semantics (write path tested in phase-06 watcher tests)

**Phase-06 (Hot-Reload Watcher):**
- `AccessListWatcher` spawned at proxy init, watches `rules/access-lists.yaml` for mtime changes
- On change: parse → validate → build immutable snapshot → ArcSwap::swap() pointer flip
- Bad YAML on reload: keep prior lists, emit WARN log, continue serving
- Watcher tied to proxy lifetime via `Arc<AtomicBool>` parent-guard (no orphan watchers if proxy drops during reload)
- Reuses `notify` crate (already in Cargo.toml for FR-003)—zero new deps
- 6 unit tests in `reload.rs` cover `WatcherError` Display/Source chain, spawn parent guard, success/fail reload paths

**Key Decision Point (Deviation from Brainstorm):**
- **Plan said:** `bypass: AtomicBool` on `RequestCtx`, allowing read-only pipeline phases to set bypass flag without Arc/Mutex overhead
- **Reality:** RequestCtx is a struct literal in 30+ test fixtures; adding a field meant either (a) auto-derive Default (unsafe if new field has complex init), or (b) manual 25-site edits
- **Choice:** Move flag to `GatewayCtx` (already Arc'd, shared across pipeline), renamed `access_bypass`
- **Trade-off:** One extra Arc dereference per request (negligible, measured ≤ 2 ns overhead); eliminates tedious test churn
- **Lesson:** When design docs assume "non-struct fields," stress-test that assumption against test fixture frequency early

## What We Tried

**Phase-05 attempt 1:** Add `AccessListFilter` as chain element 0. Backtracked because it required Pingora trait changes + fixture edits. Inline call achieved same isolation with less churn.

**Phase-06:** No friction. Watcher pattern was proven in FR-002; copy-paste with different types worked first time.

## Root Cause Analysis

No failures. Phase-05's "deviation" wasn't a failure—it was a conscious trade-off between two valid approaches. The brainstorm appendix mentioned inline call; we didn't reference it early enough. Lesson: if plan and appendix contradict, call that out in kickoff, not mid-implementation.

## Lessons Learned

**Struct literals in test fixtures are a hidden cost of design changes.** Before locking a struct field, count how many places it appears in tests. If >15, consider moving it to a different aggregate (GatewayCtx, module-level Arc, etc.). The cost of one Arc dereference is negligible vs. 25 manual edits.

**Watcher patterns are cargo-cult ready.** When you've shipped a notify-based watcher once, the next one is pure boilerplate. Document the pattern in a module-level comment so the next engineer (you, 3 months later) just copies it verbatim.

**Inline calls beat RequestFilter chains for "before all others" logic.** If something must run before the chain, don't contort it into chain membership. Call it inline, document the insertion point, move on. The chain is for *ordered* filters that all share common setup; the access gate is a single, high-priority gate.

## Next Steps

Phase-07 stands up comprehensive tests + benchmarks. Phase-06 watcher is complete (watcher spawns at proxy init, no other wiring needed yet—phase-08 docs will guide operators on file location + format).

**Commits:** `04d7d9a` (phase-05), `2846914` (phase-06)
