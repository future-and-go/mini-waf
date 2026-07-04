---
phase: 3
title: "Scoring after fast-path exits"
status: completed
priority: P2
dependencies: []
---

# Phase 3: Scoring after fast-path exits

<!-- Updated: Validation Session 1 - confirmed all 5 exits skip scoring, including blacklist blocks -->

## Overview

`WafEngine::inspect()` (`crates/waf-engine/src/engine.rs:665-678`) runs `self.scorer.score(ctx, None, &[], None, now_ms)` — a risk-store **write** (velocity record + state apply) — unconditionally, *before* `inspect_pipeline()` gets a chance to short-circuit on guard-disabled (685), IP whitelist (695), or IP blacklist (705). Requests the WAF rejects or bypasses in its cheapest paths still pay the full scoring cost (Redis RTT when the redis backend is active). Currently latent — risk is disabled by default (`cfg.enabled` gate in `scorer.rs:142`) — but it binds the moment risk is enabled. Move scoring after the fast-path exits.

## Requirements

- Functional: decisions produced by guard-disabled, IP-whitelist, IP-blacklist, URL-whitelist, and URL-blacklist exits carry `risk_score = 0` and do **not** touch the risk store (no velocity record, no state apply, no clean-streak increment). All other decisions keep today's behavior: risk score attached, store updated.
- Non-functional: no extra latency added to the non-fast-path flow (one score call, same position relative to audit event emission).

## Architecture

Intentional, issue-sanctioned semantics change: fast-path-rejected/bypassed requests stop feeding risk state. Consequences to accept and document:

- Blacklisted-IP floods no longer accumulate risk score — acceptable: they are already blocked by a cheaper, earlier layer.
- Whitelisted/guard-off traffic no longer earns `clean_streak` decay credit — acceptable: those requests bypass inspection anyway.

Mechanism: `inspect_pipeline` currently returns plain `WafDecision` from ~20 branches. Rather than rewriting every return site, tag only the five fast-path exits. Two options; pick (a) unless a `WafDecision` field is clearly cheaper on inspection:

a. Change `inspect_pipeline` signature to return `(WafDecision, FastPath)` where `FastPath` is a two-variant enum (`Hit`/`Miss`) — only the five early returns at engine.rs:685-726 construct `Hit`; the fall-through wraps `Miss`. A tuple keeps the change local to `engine.rs`.
b. Add a non-serialized `fast_path: bool` to `WafDecision` — rejected if `WafDecision` is a public/shared contract (it is used across crates and in responses; do not widen it for an internal signal).

Then in `inspect()`:

```rust
let mut decision = self.inspect_pipeline(ctx).await;   // now returns tuple
if fast_path == FastPath::Miss {
    let scorer_score = self.scorer.score(ctx, None, &[], None, now_ms).await.map_or(0, |r| r.score);
    decision.risk_score = scorer_score.min(100);
}
self.send_audit_event(ctx, &decision, inspect_time);
```

Note: scoring moves from *before* the pipeline to *after* it. The scorer does not read anything the pipeline mutates except `ctx.geo` (populated at 690-692) — verify during implementation that later-ctx-state is either unused by the scorer or benign (geo enrichment happening before scoring is an improvement, not a regression). `send_audit_event` must still see the final `risk_score`.

DDoS-phase interaction: `RiskBumpAction` (issue #202) is unwired; no other scorer callers exist in `inspect`. Confirm with a grep for `scorer.score(` before assuming.

## Related Code Files

- Modify: `crates/waf-engine/src/engine.rs` — `inspect()` (665-678), `inspect_pipeline()` signature + five fast-path return sites (683-726); any direct `inspect_pipeline` callers/tests.
- Modify: engine tests covering `inspect` (search `tests/` and `#[cfg(test)]` in engine.rs for callers).

## Implementation Steps

1. Grep `scorer.score(` and `inspect_pipeline(` across the workspace to enumerate all call/return sites.
2. Introduce the `FastPath` marker (private to engine.rs) and thread it through the five early returns; all remaining returns are `Miss`.
3. Move the `scorer.score` call after the pipeline, gated on `Miss`; keep `decision.risk_score = score.min(100)` and audit-event ordering.
4. Tests: (with risk enabled via test config) assert a whitelisted-IP request leaves the risk store `len() == 0` / velocity empty, while a normal allowed request scores. Reuse the memory store for this — no Redis needed.
5. Verify no test relied on blocked-by-blacklist decisions carrying a non-zero risk score.

## Success Criteria

- [x] Guard-disabled / IP-whitelist / IP-blacklist / URL-whitelist / URL-blacklist decisions perform zero risk-store operations.
- [x] Non-fast-path decisions still carry `risk_score` and update the store exactly once per request.
- [x] New unit test proves both sides (fast-path: no store write; normal path: store written).
- [x] `WafDecision` public shape unchanged.

## Risk Assessment

- Semantics change is the risk, not the code. It is explicitly required by issue acceptance criterion 3. Document it in the commit body.
- Ordering: scoring now sees geo-enriched `ctx`; if the scorer ever keys on mutations the pipeline makes mid-flight (it doesn't today), this would shift scores — the grep in step 1 guards this.
