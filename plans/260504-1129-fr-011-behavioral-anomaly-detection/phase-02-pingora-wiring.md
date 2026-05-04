---
phase: 2
title: "Pingora Wiring"
status: completed
priority: P1
effort: "0.5d"
dependencies: [1]
---

# Phase 2: Pingora Wiring

## Overview

Hook `Recorder::record(...)` into the Pingora `request_filter` after `FpKey` resolution but before risk aggregation. One call site only — keep the integration surface tiny.

## Requirements

- **Functional:** Every inbound request with a non-empty `FpKey` produces exactly one `Sample` in the recorder.
- **Non-functional:** Adds <1 µs to the request path. Must not block on a poisoned shard or fall back to a slow path.

## Architecture

```
Pingora request_filter
  ├── (existing) device_fp capture → FpKey
  ├── (existing) RuleEngine evaluation → Tier
  ├── NEW: Recorder::record(key, path, had_referer, tier)
  └── (existing) RiskAggregator.evaluate(...)
```

The Recorder is owned by the gateway lifecycle struct (alongside `IdentityStore`). Pass `Arc<Recorder>` into the filter context the same way `Arc<IdentityStore>` already flows.

### Decision: tier source

Open question #1 from research — resolve here: **read tier from rule-engine output**. Reason: the rule engine already classifies tier per request; precomputing in Recorder duplicates that logic and drifts from the live rule set. Cost: tier must be available at call site (verify in step 1).

## Related Code Files

- **Modify:**
  - The Pingora filter entry point in `crates/waf-engine/` — locate via `grep -rn "request_filter" crates/waf-engine/src/` (likely `engine.rs` or `filter.rs`).
  - Gateway bootstrap that constructs `IdentityStore` — add `Recorder` construction + janitor spawn alongside.
- **Reference:**
  - `crates/waf-engine/src/device_fp/aggregator.rs` (where signals are gathered).

## Implementation Steps

1. Locate the request filter: `grep -rn "fn request_filter\|impl ProxyHttp" crates/waf-engine/src/ crates/gateway/src/`. Confirm tier + FpKey + path + Referer header are all in scope at the call site. If tier is computed *after* this point, defer the recorder call to where it is available.
2. Locate gateway bootstrap (where `IdentityStore` is built): `grep -rn "IdentityStore\|spawn_janitor" crates/waf-engine/src/ crates/gateway/src/`.
3. In bootstrap: construct `Arc<Recorder>`, call `Recorder::spawn_janitor(period=60s)`, store handle on the gateway state struct. Janitor handle dropped on shutdown — verify graceful.
4. In filter: extract `had_referer = req.headers().contains_key("referer")`, normalize path (strip query, lowercase), call `recorder.record(&fp_key, &path, had_referer, tier)`. Skip if `fp_key.is_empty()`.
5. `cargo check -p waf-engine -p gateway` clean.
6. Add a smoke integration test under `crates/waf-engine/tests/`: spin up the filter with a stub upstream, send 3 requests, assert `recorder.snapshot(&key).samples.len() == 3`.

## Success Criteria

- [ ] One call site, ≤ 5 added LOC in the filter.
- [ ] `cargo check -p waf-engine -p gateway` clean.
- [ ] Smoke test passes: 3 requests → 3 samples in snapshot.
- [ ] `fp_key.is_empty()` skips the call (no panic, no insert).
- [ ] Janitor handle stored on gateway state and dropped on shutdown.

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Tier not yet computed at filter entry | Move recorder call to post-rule-eval point. Document. |
| Path normalization mismatch with rule engine | Reuse the same normalization helper the rule engine uses; do not invent. |
| Janitor leak on shutdown | Store `JoinHandle` on gateway; abort on `Drop`. |

## Security Considerations

- Skip recording when `fp_key.is_empty()` — prevents an "all-empty-key" actor entry that would aggregate every unidentified request.
- Do not store the Referer value, only the boolean presence.
