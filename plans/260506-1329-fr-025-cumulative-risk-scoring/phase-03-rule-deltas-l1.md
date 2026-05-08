---
phase: 3
title: "Rule Deltas L1"
status: completed
priority: P1
effort: "2d"
dependencies: [1, 2]
---

# Phase 3: Rule Deltas L1 — Per-Rule Score Contributions

## Overview

Wire the existing rule engine (FR-003) into the scorer. Each matched rule emits a `(rule_id, delta)` pair appended to the request's `SyncDeltas`. The scorer folds them into `RiskState` via `store.apply` in the sync hot path. Rule YAML schema extends with optional `risk_delta: i16`.

## Why P3 (Sync Path Before Async)

Rule matches are deterministic, fast, and trustworthy. They MUST land in the sync path so the current request's score reflects its own rule outcome (FR-RS-013). Async ingest (P4) handles best-effort signals; this is best-known evidence.

## Requirements

**Functional:**
- Rule YAML schema gains optional `risk_delta: i16`. Default 0 (no contribution).
- High-severity rules can set `risk_action: "block"` → `override_block` flag fires regardless of score (FR-RS-102).
- Rule engine output extended with `Vec<(RuleId, i16)>` propagated via `RequestCtx`.
- Scorer reads `ctx.risk_deltas` post-rule-engine, folds into deltas vector for `store.apply`.
- Per-request raw delta clamp `[0, 100]` BEFORE tier multiplier (Iron Rule §3 / brainstorm §6 pitfall #4).
- `X-WAF-Rule-Id` header set to dominant contributor (highest |delta|) — FR-RS-121.

**Non-functional:**
- Score-fold p99 ≤ 50µs (criterion).
- Rule engine itself NOT modified beyond output type extension.

## Architecture

### Rule YAML Extension

```yaml
- id: "sqli-001"
  pattern: "..."
  action: "block"
  risk_delta: 40            # NEW (optional)
  risk_action: "block"      # NEW (optional override)
```

### Plumbing

```
rule_engine.evaluate(req) ─►  RuleVerdict {
                                 matches, risk_deltas, override_block,
                              }
                                          │
                                          ▼
                              RequestCtx.{risk_deltas, override_block}
                                          │
                                          ▼
                              Scorer::evaluate(ctx)
                                  → store.apply(key, deltas)
                                  → decide(state.clamped_score, cfg, override_block)
```

### Dominant Contributor

`X-WAF-Rule-Id` value = `max_by_key(|c| c.delta.abs())` from CURRENT-REQUEST contributors only (NOT historical). Omit header if no rule fired.

## Related Code Files

**Create:**
- `crates/waf-engine/src/risk/tests/rule_deltas.rs`
- `crates/waf-engine/src/risk/tests/dominant_contributor.rs`

**Modify:**
- `crates/waf-engine/src/rules/` (YAML loader) — add `risk_delta`, `risk_action`.
- `crates/waf-engine/src/rules.rs` — extend `RuleVerdict`.
- `crates/waf-engine/src/checker.rs` — pass `risk_deltas` + `override_block` into `RequestCtx`.
- `crates/waf-engine/src/risk/scorer.rs` — read ctx, build sync delta list, call `store.apply`, set `X-WAF-Rule-Id`.
- `crates/waf-engine/src/risk/score.rs` — clamp helper `clamp_per_request_raw`.
- `rules/*.yaml` — populate sample deltas (SQLi=40, XSS=35, RCE=60, LFI=50, traversal=45, scanner UA=20, suspicious header=15).
- `docs/system-architecture.md` — extended rule schema.
- `docs/code-standards.md` — delta convention table.

## Implementation Steps

1. **Schema extension.** Add `Option<i16>` + `Option<String>`; `#[serde(default)]` keeps backwards compat.
2. **Rule engine output.** Extend `RuleVerdict`. On match: push `(rule_id, delta)` if delta set; `override_block = true` if `risk_action == "block"`.
3. **`RequestCtx` plumbing.** Add fields. Populated post-rule-engine, before scorer.
4. **Per-request clamp.** Sum positive deltas — if >100, TRUNCATE oldest (preserves rule-id ordering, audit-honest about cap source). Document in code comment.
5. **Scorer integration.** After seed: `let deltas = clamp_per_request_raw(ctx.risk_deltas)`; build `Contributor` vec; `store.apply(key, &contribs, now).await?`; pass `ctx.override_block` to `decide`.
6. **Dominant contributor header.** From returned post-state, compute dominant by |delta| across current-request contribs; set `X-WAF-Rule-Id` if non-empty.
7. **Sample rule deltas.** Update `rules/*.yaml`. Document table in `docs/code-standards.md`.
8. **Tests.**
   - matched rule delta=40 → state-read returns 40.
   - 40+40+40 → clamped 100, raw_score=120 in audit.
   - delta=10 + override_block → score=10, decision=Block.
   - deltas (a:30, b:50, c:20) → header `X-WAF-Rule-Id: b`.
   - Existing rule-engine tests still green.
9. **Compile gates.**

## Common Pitfalls

- **Mutable rule schema breaks existing YAMLs** — `Option<T>` + `#[serde(default)]`.
- **Score-explosion via N rule matches** — clamp PER-REQUEST raw before tier mult.
- **Double-counting same rule multiple matches** — rule engine de-dups; multi-match in distinct contexts allowed but cap via clamp.
- **Audit log loses rule_id** — `Contributor.kind = Rule(RuleId)` is the audit anchor.

## Success Criteria

- [x] Rule engine extended; existing tests green.
- [x] Per-request clamp enforced; raw_score retained in audit.
- [x] `X-WAF-Rule-Id` set to dominant contributor.
- [x] `override_block` short-circuits to Block.
- [x] Sample rules populated, documented.
- [x] Score-fold p99 ≤ 50µs.
- [x] No `.unwrap()` introduced.

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Operators set extreme deltas | Low | i16 type-bounded; per-request clamp |
| YAML schema drift breaks parsing | Medium | `#[serde(default)]` + snapshot tests |
| `override_block` overused → telemetry meaningless | Medium | Document in deployment-guide: reserve for high-confidence patterns |
| Dominant-contributor pick races state | Low | Compute on returned post-state clone |

## Verify

```bash
cargo test -p waf-engine rules::
cargo test -p waf-engine risk::
cargo bench -p waf-engine --bench risk_skeleton -- score_fold
curl -sv "http://localhost:16880/?q=1%27%20OR%201=1--" 2>&1 | grep -E "X-WAF-(Risk-Score|Rule-Id)"
```
