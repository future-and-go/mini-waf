---
phase: 1
title: "Engine enforcement wiring"
status: completed
priority: P1
dependencies: []
---

# Phase 1: Engine enforcement wiring

<!-- Updated: Validation Session 1 - escalate plain Allow only; dropped ScorerReason enum; full FR-028 canary wiring (ban table + config TTL) -->

## Overview

Make `WafEngine::inspect()` consume the full `ScorerResult` and escalate a plain-Allow pipeline decision to Block/Challenge when the scorer says so, respecting the mode registry. Wire the FR-028 canary layer fully into the engine scorer: config-driven paths, DDoS ban table, and config-driven ban TTL.

## Requirements

- Functional: scorer Block/Challenge becomes the returned `WafDecision` only when the pipeline decision's action is plain `WafAction::Allow`; any decision carrying a detection (enforced or LogOnly'd) is returned untouched; scorer Allow changes nothing; monitor mode on `risk_assessment` downgrades risk enforcement to LogOnly; canary hits IP-ban via the DDoS `DynamicBanTable` with `CanaryConfig.ban_ttl_secs`.
- Non-functional: zero extra work on the fast paths (GH-206 invariant preserved); no new allocations on the Allow path.

## Architecture

Data flow in the wrapper (`engine.rs:673-690`), after `inspect_pipeline` returns `(decision, fast_path)`:

```text
if fast_path == Miss:
    scorer_result = scorer.score(ctx, None, &[], None, now_ms)   # unchanged call
    decision.risk_score = scorer_result.score.min(100)
    if matches!(decision.action, WafAction::Allow)                # plain Allow only (Validation S1)
       and scorer_result.action is Block|Challenge:
        risk_decision = make_risk_decision(ctx, &scorer_result)
            - DetectionResult { phase: Phase::RiskScore,
                                rule_name: "cumulative_risk",     # single name (Validation S1)
                                detail: "risk score {score}",
                                rule_id: None, rule_action: None, action_status: None }
            - Block{status, ..}  -> WafDecision::block(status, render_block_page(ctx, "cumulative_risk"), result)
            - Challenge          -> WafDecision { action: Challenge, result: Some(result), .. }
        apply_mode(ctx, &mut risk_decision, "risk_assessment", Some("cumulative_risk"))
        log_security_event(ctx, &risk_decision)
        report_community_signal(ctx, &risk_decision)              # reporter.rs:92 already maps RiskScore -> 0.65
        risk_decision.risk_score = scorer_result.score.min(100)
        decision = risk_decision
send_audit_event(ctx, &decision, inspect_time)                    # unchanged — audits risk blocks for free
```

Key decisions (post-validation):

1. **Escalate plain Allow only** (Validation S1, Q1): gate on `matches!(decision.action, WafAction::Allow)`. A detection downgraded to LogOnly keeps its decision in the return value even if the scorer says Block — the monitored feature's outcome is preserved. `ScorerResult` remains untouched (no reason enum); all risk events use `rule_name = "cumulative_risk"` (Q2).
2. **Block body**: use `render_block_page(ctx, "cumulative_risk")` for consistency with every other block path; `threshold::decide`'s plain `"Access denied."` body is not the rendered surface and stays as-is.
3. **Full FR-028 canary wiring** (Q3): in `WafEngine::new` (engine.rs:253), construct the layer with the DDoS ban table already available in `new()`:
   `let canary = Arc::new(CanaryLayer::with_ban_table(Vec::new(), Arc::clone(ddos_check.ban_table()), DEFAULT_CANARY_BAN_TTL_SECS));`
   (constructor at `risk/canary.rs:60`; accessor at `checks/ddos/check.rs:76` — if `ddos_check` is constructed after the scorer in `new()`, reorder locally). Call `scorer.set_canary(Arc::clone(&canary))` **before** `Arc::new(scorer)` (`set_canary` takes `&mut self`, scorer.rs:109). Store `risk_canary: Arc<CanaryLayer>` as a new engine field.
4. **Config consumption in `replace_risk_config`** (engine.rs:296): apply `cfg.canary.paths` and `cfg.canary.ban_ttl_secs` to the layer. `CanaryLayer::reload` (canary.rs:119) currently swaps paths only; extend it to also accept the TTL (or convert `ban_ttl_secs` to `AtomicU32` with a setter — implementer's choice; update the few `reload` callers the compiler flags). `ban_ttl_ms()` (canary.rs:144) feeds the force-max pin duration, so the config TTL now governs both the IP ban and the score pin.

## Related Code Files

- Modify: `crates/waf-engine/src/engine.rs` — wrapper (`inspect`) + `make_risk_decision` helper, `new` (canary construction with ban table + field), `replace_risk_config` (paths + TTL reload), struct field docs at lines 151-157 (score is no longer observability-only).
- Modify: `crates/waf-engine/src/risk/canary.rs` — TTL reload support (signature extension or atomic field).
- Read-only reference: `crates/waf-engine/src/risk/scorer.rs`, `crates/waf-engine/src/risk/threshold.rs`, `crates/waf-engine/src/checks/ddos/check.rs`, `crates/waf-engine/src/interop/checker_feature_map.rs`.

## Implementation Steps

1. Add `risk_canary: Arc<CanaryLayer>` engine field; construct via `with_ban_table` using `ddos_check.ban_table()` in `new()`; install on scorer pre-Arc-wrap.
2. Extend `CanaryLayer` TTL hot-reload (canary.rs); consume `cfg.canary.{paths, ban_ttl_secs}` in `replace_risk_config`.
3. Rewrite the scoring block in `inspect()` per the architecture flow above; keep `inspect()` readable with a `fn make_risk_decision(&self, ctx: &RequestCtx, result: &ScorerResult) -> WafDecision` helper.
4. Update the stale `risk_cfg`/`scorer` field doc comments (engine.rs:151-157) — score now drives enforcement, not just headers.

## Success Criteria

- [x] `cargo build -p waf-engine` clean; no remaining `map_or(0, |r| r.score)` in `inspect()`.
- [x] Scorer `Block` → returned decision is `WafAction::Block` with `Phase::RiskScore` result and `rule_name == "cumulative_risk"`; `Challenge` → `WafAction::Challenge`; `Allow` → pipeline decision untouched.
- [x] Non-Allow pipeline decisions (enforced or LogOnly'd) are returned unmodified apart from `risk_score`.
- [x] Canary hit inserts the IP into the DDoS `DynamicBanTable` with the configured TTL and pins the score.
- [x] Monitor mode on `risk_assessment` yields `mode: LogOnly` decision (request proceeds, event logged).
- [x] Fast-path requests still never touch the scorer (existing test `fast_path_exits_skip_risk_scoring` green).
- [x] Default (disabled) config: zero behavior change — full existing suite green.

## Risk Assessment

- **False-positive blocking once #196 lands**: thresholds come from `ctx.tier_policy.risk_thresholds` (tier defaults at `waf-common/src/tier.rs:88`); monitor mode via mode registry is the operator rollout valve. Document rollout order in Phase 3.
- **LogOnly'd detections shield actors from risk enforcement** (accepted trade-off, Validation S1 Q1): while a feature is in monitor mode, its detections suppress risk escalation for that request. Operators should not leave broad features in monitor mode with risk enforcement active. Call out in Phase 3 docs.
- **Ban-table coupling**: canary hits now surface as DDoS-phase blocks on subsequent requests (Phase 19 runs before scoring). Intended FR-028 behavior; Phase 2 tests assert it explicitly so it is a contract, not an accident.
