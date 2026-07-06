# GH-206 Hot-Path Perf: 5-Phase Plan + Validation Complete

**Date:** 2026-07-03 22:16 +07:00
**Severity:** Medium
**Component:** waf-engine (risk scoring, geoip, velocity window, Redis store)
**Status:** Plan validated; ready for Phase 1 implementation

## What Happened

Created a complete 5-phase implementation plan for GitHub issue #206 (WAF hot-path waste: O(10k) LRU scan + 2-RTT Redis apply + scoring before fast-path exits + per-request clones/allocs). Conducted grep-verification pass (~20 claims checked), all confirmed. Held validation interview (4 questions); user chose to fold bug #199's max-score convergence fix INTO Phase 2's single-RTT Lua merge (deviates from recommendation but justified). Updated GitHub issues #206 and #199 with fold-in decision; applied `ready to review` label to #206.

Plan structure: Phase 1 (lru crate O(1) cache), Phase 2 (single-RTT atomic apply + #199 fix), Phase 3 (skip scoring on all 5 fast-path exits), Phase 4 (velocity clone + geo alloc removal), Phase 5 (tests + benches). Phases 1–4 can execute in any order.

## The Brutal Truth

Grep verification succeeded cleanly (0 failed claims). This should feel solid — it does. But the planning toolchain introduced two friction points:

1. `ck plan create` scaffolded the plan dir at repo root instead of `plans/`. Had to `mv` it manually; the expected path from `.claude/rules/documentation-management.md` was ignored.

2. `scripts/bin/harness-cli` (referenced by AGENTS.md as the operational tool) is absent from the working tree. Story registration via `harness-cli story add` was a clean skip; GitHub issue #206 is the tracked artifact instead. This is a minor UX hiccup but worth flagging for future planning sessions.

The actual plan content is sound. The validation interview landed cleanly: lru crate (confirmed ubiquitous, O(1), less code), skip all 5 exits (faster than allow-only exits; matches acceptance criterion), and the #199 fold-in choice makes engineering sense even though it deviated from the recommendation.

## Technical Details

**Five findings in GH-206:**
- Hand-rolled LRU: `VecDeque::retain` O(capacity=10k) + `key.to_string()` per get/insert under global `Mutex`.
- `apply()`: 2 sequential RTTs (MINT_OR_GET_OWNER → APPLY/FORCE_MAX), non-atomic.
- `scorer.score()` runs before inspect_pipeline's guard-disabled / IP-whitelist / blacklist short-circuits.
- `windows.entry(key.clone())` clones RiskKey per request.
- Per-request `ip.to_string()` in geoip lookup; `iso_code` re-uppercased per rule per request.

**Verification successes:** `scorer.score()` has exactly 1 production caller (engine.rs:670); `inspect_pipeline` called only from `inspect()` (engine.rs:674); `ip2region` accepts `Ipv4Addr`/`Ipv6Addr` directly (no string bridge required); `GeoIpInfo` is public; benches exist (tx_velocity_bench.rs, risk_anomaly.rs, rule_eval.rs, access_lookup.rs). Phase 5 test env: Valkey on `redis://127.0.0.1:6379` (protocol-compatible, Lua-compatible; gated tests now required proof, not optional).

**Scope fold:** Bug #199's acceptance criterion 3 anticipated this ("merge must be atomic with apply"). Phase 2 now writes a merged APPLY/FORCE_MAX script that selects max-score owner on colliding index hits. Conformance test `test_triple_index_max` (crates/waf-engine/src/risk/store/conformance.rs:66) verified to exist. Bug #198 (state encoding quirks) kept out of scope; state semantics preserved as-is.

## What We Tried

**Decision point: Phase 2 vs #199 land order** (Q3, Validation Session 1)
- Recommended: Merge first, #199 later (separate script edits).
- User chose: Fix #199 inside the merge (one script, atomic with apply).
- Rationale: matches #199's criterion 3; one edit instead of two; less friction.

**Outcome:** Phase 2 semantics/steps/success-criteria rewritten. Phases 1, 3, 4 confirmed as written.

## Root Cause Analysis

**Why hot-path waste exists:**
- LRU was hand-rolled to avoid a dependency; the crate `lru` is now justified and available (ubiquitous, O(1), reduces code surface).
- Redis apply was designed to preserve convergence byte-for-byte (memory ↔ Redis parity) without explicitly naming atomicity as a contract; two RTTs naturally fell out. Fixing #199 (max-score convergence) forces the issue into the open: the script must be atomic.
- Scoring ran unconditionally before fast-path exits; no semantic reason given. Acceptance criterion (fast-path-rejected do not pay scoring cost) is the justification for the change.
- Clone on velocity hit is a convenience (HashMap::entry API); same with geo string normalization per rule per request.

**Friction sources:**
- Tooling mismatch: `ck plan create` does not consult `.claude/rules/documentation-management.md` for output location.
- Missing operational tool: `scripts/bin/harness-cli` is not in the tree; workflows cite it; story registration skipped gracefully.

## Lessons Learned

1. **Grep verification at plan time catches load-bearing claims early.** ~20 specific line numbers, function names, and file paths checked against live source; 0 failures = confidence in phase decomposition.

2. **Validation interview should force explicit choice between recommendations, not just surface them.** User deviation from recommendation (fold #199 into Phase 2) is correct; the recommended path would have worked but cost an extra script edit. Next time, frame as trade-off explicitly.

3. **Tooling consistency matters.** When docs cite a tool path (scripts/bin/harness-cli), make it present or make the absence a loud error, not a silent skip.

4. **Semantics changes (scoring skip on fast-path exits) need explicit acceptance criteria to justify the deviation.** This one had it; issue #206's acceptance criterion was the anchor. Good pattern to repeat.

5. **Scope folding works if the folded issue's acceptance criteria anticipated the merge.** #199 criterion 3 did; Phase 2 now delivers both. If it hadn't, the fold would have been risky.

## Next Steps

- [x] Grep verification pass (complete).
- [x] Validation interview (complete).
- [x] Update GitHub issues #206 and #199 (complete).
- [x] Rewrite Phase 2 semantics for max-score convergence (complete).
- [ ] Phase 1 implementation (pending; independent of other phases).
- [ ] Phase 5: Valkey-gated tests required (documented; not optional).
- [ ] Record friction (missing harness-cli, ck plan location) in next planning session for tooling review.

---

**Status:** DONE
**Summary:** 5-phase plan created and validated; 20 claims verified, 0 failed. User chose to fold #199 into Phase 2 (sound decision). Ready to implement Phase 1.
**Concerns/Blockers:** None blocking. Noted friction: ck plan scaffolding location and missing scripts/bin/harness-cli from tree (skip only, not blocking).
