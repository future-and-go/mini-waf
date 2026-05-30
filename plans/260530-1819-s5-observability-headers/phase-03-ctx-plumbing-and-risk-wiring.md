---
phase: 3
title: "Ctx Plumbing + Risk/Rule Wiring"
status: pending
priority: P1
effort: "6h"
dependencies: [2]
---

# Phase 3: Ctx Plumbing + Risk/Rule Wiring

## Overview
Make decision-derived values reachable from `response_filter` and cache paths via a lightweight
snapshot on `GatewayCtx`, set on EVERY outcome (incl. access-bypass), and attempt the deferred
scorer→decision wiring (§3 RT-05).

## Requirements
- Functional: after the request pipeline, `GatewayCtx` carries action/risk/rule/mode + cache status for ALL outcomes.
- Non-functional: snapshot avoids cloning `DetectionResult`; no per-request heap churn on the allow path.

## Architecture
```rust
// crates/gateway/src/context.rs
pub struct WafDecisionMeta {
    pub action: &'static str,     // default "allow" (NEVER "")  ← red-team F13
    pub risk_score: u8,
    pub rule_id: Option<String>,  // None on allow (no alloc); map to "none" only at inject time
    pub mode: &'static str,       // "enforce"/"log_only"
}
impl Default for WafDecisionMeta { /* action:"allow", risk:0, rule_id:None, mode:"enforce" */ }

// add to GatewayCtx (derive(Default) already present):
pub waf_decision_meta: Option<WafDecisionMeta>,
pub cache_status: CacheStatus,   // default Bypass
```

Population in `proxy.rs::request_filter`:
- After `engine.inspect()` (line 681): set `ctx.waf_decision_meta = Some(meta_from(&decision))` —
  set BEFORE the conditional `write_waf_decision` and BEFORE the cache HIT branch (so HIT reads it).
- On the **access-bypass fast-path** (line 677, `return Ok(false)`): set
  `ctx.waf_decision_meta = Some(WafDecisionMeta::default())` (action="allow") so passthrough never
  sees `None` (red-team F6). Remove any "should not happen" comment.
- `cache_status`: HIT at line 706 (before `write_cached_entry`); MISS where `response_cache_store`
  is set (line 710); else leave default `Bypass`. Also set `Bypass` when `meta.action != "allow"`
  (high-risk/non-allow responses are not clean cache candidates — red-team F14, contract §5.3).

`meta.mode` fallback: where a snapshot is genuinely absent, derive mode from the engine/global
default mode — NEVER hardcode `enforce` (red-team F8).

### Scorer wiring (§3 RT-05) — FIRM SCOPE (validate decision: wire now)
`engine.inspect()` (engine.rs:538) does NOT call the `Scorer`; `make_block_decision` (engine.rs:750)
and all constructors set `risk_score: 0`. This phase WIRES the scorer into decision assembly:
1. Read `waf-engine/src/risk/scorer.rs` — `Scorer<S: RiskStore>` produces `ScorerResult { action, score, is_new }`
   (score clamped 0..=100); deltas feed `dominant_contributor(&deltas) -> Option<&str>` (score.rs:57).
2. Establish how the `Scorer` is constructed/owned (RiskStore backend + `RiskConfig` via `ArcSwap`,
   `RiskKey` built from `RequestCtx` — IP/fingerprint/session triple-index, key.rs). Reuse the existing
   wiring if the engine already holds a scorer instance; otherwise inject one into `WafEngine`.
3. In `inspect()` decision assembly: call the scorer for the request, set `decision.risk_score`
   (`with_risk_score(result.score)`) and `decision.rule_id = dominant_contributor(&deltas)` when the
   decision has no explicit rule id. Keep the score clamped 0..=100 (injector also clamps, belt-and-suspenders).
4. Preserve existing behavior: scoring must not change allow/block outcomes beyond setting metadata
   (the score→action threshold gate already lives in the scorer; do not double-apply). Verify no
   regression in `inspect()` decision outcomes (existing engine tests stay green).

**Scope guard:** if scorer construction requires infra not available at the engine boundary
(e.g. a store backend not yet instantiated), keep the change minimal — instantiate the in-memory
`MemoryRiskStore` path the engine already uses; do NOT build new persistence. Flag if blocked.

## Related Code Files
- Modify: `crates/gateway/src/context.rs` (`WafDecisionMeta` + 2 ctx fields + Default impl)
- Modify: `crates/gateway/src/proxy.rs` (`request_filter`: snapshot + cache_status; bypass arm)
- Modify (conditional): `crates/waf-engine/src/engine.rs` (scorer→decision wiring, if in scope)
- Read for context: `crates/waf-engine/src/risk/{scorer.rs,score.rs}` (`ScorerResult`, `dominant_contributor`:57)

## Implementation Steps
1. Add `WafDecisionMeta` (+ explicit `Default`) + ctx fields; update all `GatewayCtx { ... }` init sites (grep).
2. `request_filter`: build + set meta after inspect; set meta on bypass arm; set `cache_status` at 3 branches.
3. Map `cache_status = Bypass` when `meta.action != "allow"`.
4. Wire the scorer into `inspect()` decision assembly per the FIRM-SCOPE steps above.
5. `cargo check --workspace`.

## Success Criteria
- [ ] `waf_decision_meta` is `Some` for block, allow, AND access-bypass outcomes (tested)
- [ ] `WafDecisionMeta::default().action == "allow"` (not "")
- [ ] `cache_status` correct for HIT/MISS/BYPASS incl. non-allow → Bypass
- [ ] mode fallback derives from default mode, never hardcoded `enforce`
- [ ] scorer wired: `decision.risk_score` reflects `ScorerResult.score`; `rule_id` uses `dominant_contributor` when unset; a scored test request yields NON-zero score
- [ ] existing engine `inspect()` outcome tests still green (no behavior regression from scoring)
- [ ] `cargo check --workspace` clean

## Risk Assessment
- Risk: many `GatewayCtx` init sites → additive `Option`/`Default` fields minimize churn.
- Risk: scorer wiring balloons scope → bounded by the scope guard (reuse in-memory store path; no new persistence). Flag if engine boundary lacks a store.
- Risk: double-applying the score→action threshold → only set metadata here; the scorer owns the gate.

## Security Considerations
- `cache_status` defaults to `Bypass` (fail-safe). Non-allow responses forced to `Bypass`.
- Keep `rule_id` `None` in the snapshot (no `Some("none")`) to avoid per-request alloc (Rule 7, red-team F12/F14).
