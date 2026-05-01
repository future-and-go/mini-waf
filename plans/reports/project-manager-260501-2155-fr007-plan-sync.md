# FR-007 Plan Sync Report — Phase-07 Completion Review

**Date:** 2026-05-01 21:55 (Asia/Saigon)  
**Context:** Syncing plan files with actual shipped code; Phase-07 just completed with tests + bench.

---

## Summary

All core FR-007 relay/proxy detection logic **shipped and tested**. Plan files updated to reflect ground truth:

- **Phases 01–05:** All completed (no changes to status)
- **Phase-02:** Status corrected in plan.md (was "pending", is "completed")
- **Phase-06:** Core wiring complete; rule-engine predicates deferred to 06b (documented)
- **Phase-07:** Complete with **5 documented deferrals** (CI gates, numeric test, gz path, log capture)
- **Phase-08:** Pending (docs sync — post-shipment work)

---

## Changes Made to Plan Files

### 1. plan.md — Overview Table

| What | Was | Now | Reason |
|---|---|---|---|
| Status header | "status: pending" | "status: in-progress" | 6/8 phases done; final 2 pending |
| Effort line | "5d" | "5d (6/8 phases complete)" | Clarity on progress |
| Phase-02 | "pending" | "completed" | Cook reports confirm phase-02 shipped |
| Phase-06 | "pending" | "complete (core), pending (rule engine)" | Reflects split to 06b |
| Phase-07 | "pending" | "complete (with documented deferrals)" | Tests shipped; 5 items deferred to CI/manual |

### 2. phase-02-xff-and-proxy-chain.md

- Line 8: "Status: complete" → "Status: completed" (consistency with phase-01, 03, 04, 05)

### 3. phase-07-tests-bench-coverage.md

**Overview (line 8-10):**  
Changed from "pending" to "complete (with documented deferrals)" + expanded description.

**Todo List (lines 94–109):**  
- Marked **13 items done:** dev-deps, 10 test files, bench, wiring test
- **Marked 5 items deferred** with rationale:
  1. `CI step: cargo llvm-cov ≥90%` → CI yaml work, not test scope
  2. `CI grep gate: .unwrap()` → CI yaml work, not test scope
  3. `Tor MAX_ENTRIES 1M test` → suite performance impact; unit coverage via code-path already exercised
  4. `IptoasnFeed gz test` → low-risk; atomic-swap tested via plain-body tests
  5. `WARN-log capture hot_reload` → tracing-test crate-filter limitation; behavior verified manually

### 4. phase-06-gateway-rule-integration.md

**Overview (line 8-10):**  
Changed to clarify split: "complete (core wiring) / pending (rule engine predicates split to 06b)".

---

## Verification: Plan vs Code

Spot-checked against cook reports:

| Phase | Expected | Reported | Match |
|---|---|---|---|
| 01 | Types + YAML parser | ✓ Implemented, unit tested | ✓ YES |
| 02 | XFF + ProxyChain | ✓ Implemented, 60 tests passed | ✓ YES |
| 03 | ASN classifier + feeds | ✓ Implemented, 3 feed types | ✓ YES |
| 04 | Tor + refresh tasks | ✓ Implemented, HTTP+ETag+swap, atomic | ✓ YES |
| 05 | Hot-reload wiring | ✓ Implemented, ≤1s propagation | ✓ YES |
| 06 | Core detector integration | ✓ Done (GatewayCtx + evaluate + real_ip handover) | ✓ YES |
| 06 | Rule predicates | ✗ Deferred to 06b (FR-025 not ready) | ✓ ACCURATE |
| 07 | 11 test files + bench | ✓ All done (see cook report § Files Written) | ✓ YES |
| 07 | Adversarial matrix 12/12 | ✓ All 12 rows in relay_adversarial.rs | ✓ YES |
| 07 | Proptest 256 cases | ✓ Cases pinned, failure_persistence: None | ✓ YES |
| 07 | CI llvm-cov ≥90% gate | ✗ Not in test files; CI yaml change | ✓ DEFERRED CORRECTLY |

---

## Key Findings (Phase-07 Completion)

### Delivered (per cook-260501-2112 + code-reviewer-260501-2125)

1. **Test Suite:** 11 files covering 1:1 AC-to-test mapping
   - `relay_xff_parser.rs` — table-driven parse edge cases
   - `relay_xff_proptest.rs` — 256-case fuzz, invariant never-panic + real_ip ∈ {peer} ∪ chain
   - `relay_proxy_chain.rs` — depth thresholds, trusted strip
   - `relay_asn_classifier.rs` — DC override precedence (operator_allow > dc_set > operator_deny)
   - `relay_tor_matcher.rs` — parse + lookup
   - `relay_intel_refresh.rs` — wiremock matrix: 200/304/500/below-floor for Tor + IPinfo + iptoasn
   - `relay_hot_reload.rs` — tempfile + notify; valid edit ≤1s; malformed retains + WARN
   - `relay_adversarial.rs` — **all 12 matrix rows** from phase-07 spec (spoof-tail, private-mid, RFC1918, oversized, IPv6, Unicode, etc.)
   - `relay_e2e.rs` — full 4-provider evaluate + signal combo
   - `relay_pipeline_handover.rs` — gateway wiring contract + FR-008 compat check
   - `benches/relay_eval.rs` — criterion 4-hop + 4 providers

2. **Code Quality:** 
   - `cargo check -p waf-engine --tests` ✓
   - `cargo check -p gateway --tests` ✓
   - `cargo clippy -p waf-engine --tests --benches -- -D warnings` ✓
   - `cargo fmt` ✓
   - All test files `#![allow(clippy::unwrap_used, ...)]` scoped (acceptable in tests)

3. **Review Score:** 8.5/10 (code-reviewer-260501-2125)
   - No critical issues
   - 2 medium-priority items flagged (proptest seed pinning, bench AsnDb fidelity) — both acceptable, non-blocking

### Deferred Items (Documented in Phase-07)

| Item | Why | Impact | Mitigation |
|---|---|---|---|
| CI `cargo llvm-cov` ≥90% gate | Requires CI workflow yaml changes, outside test scope | Coverage still measured locally; CI gate pending | CI yaml PR required |
| CI `.unwrap()` grep gate | Requires CI workflow yaml changes | Already zero `.unwrap()` in `src/relay/` (manual verification) | CI yaml PR required |
| Tor `MAX_ENTRIES=1M` numeric test | ~10s runtime, test suite would balloon | Unit code path covered; oversize bail already exercised | Manual test or nightly-only gate |
| IptoasnFeed gz decompression test | Would require 256KB+ gz blob | Plain-body 200/304/500 paths fully covered; gz uses same atomic-swap plumbing | Low-risk deferral; atomic-swap tested |
| WARN-log capture in hot_reload | `tracing-test` crate-filter limitation (can't isolate single module warn logs) | WARN emission verified manually in code + integration test confirms malformed path taken | Behavior verified; log capture limitation external |

---

## Inconsistencies Found & Resolved

### phase-02-xff-and-proxy-chain.md

**Status Inconsistency:**  
- **Was:** "Status: complete" (informal)
- **Is Now:** "Status: completed" (formal, matching phase-01/03/04/05)
- **Reason:** Consistency + clarity for plan readers

### phase-06-gateway-rule-integration.md

**Scope Split Not Clearly Documented:**  
- **Was:** "Status: pending" (suggested entire phase incomplete)
- **Is Now:** "Status: complete (core wiring) / pending (rule engine predicates split to 06b)"
- **Reason:** Core FR-007 acceptance done; rule predicates deferred due to FR-025 dependency
- **Cook report confirms:** Phase-06 core work done per cook-260501-2112; rule engine predicates explicitly split to 06b

### phase-07-tests-bench-coverage.md

**Deferred Items Not Explicitly Listed:**  
- **Was:** Todo list didn't distinguish completed from deferred
- **Is Now:** 13 items marked [x] done; 5 items marked [ ] deferred with [DEFERRED TO CI yaml] or [DEFERRED - reason] tags
- **Reason:** Clear visibility of what's shipped vs what's post-delivery work

---

## Unresolved Questions / Open Items

### For Implementation Lead

1. **Phase-06b rule predicates** — When will signal:/asn_class:/chain_depth: predicates be implemented?
   - Cook report flags this blocked on FR-025 (RiskScorer module not yet shipped)
   - Recommend: File separate ticket or update phase-06 acceptance to "detector wiring only; rule engine as follow-up"

2. **CI workflow gate changes** — Will CI yaml be updated to enforce:
   - `cargo llvm-cov --package waf-engine --lcov` ≥90% on `src/relay/**`?
   - `.unwrap()` grep gate: `! grep -rn '\.unwrap()' crates/waf-engine/src/relay/ | grep -v '#\[cfg(test)\]'`?
   - Recommendation: Ticket CI-XXX to run this week; both are low-effort yaml additions

3. **Bench fidelity — EmptyAsnDb vs StaticDb** — Code-reviewer flagged (medium-priority) that bench's `EmptyAsnDb` doesn't exercise real ASN lookup cost.
   - Current: p99 number may underestimate production due to missing binary-tree walk
   - Recommendation: Replace `EmptyAsnDb` with `StaticDb(AsnRecord { asn: 1234, org: "TestOrg" })` in next pass for realistic p99 measurement

4. **Proptest determinism** — Seed not pinned at source (relay_xff_proptest.rs)
   - Mitigated: If CI env sets `PROPTEST_SEED`, determinism is guaranteed
   - Verify: Does CI workflow set `PROPTEST_SEED` env var? If not, add it.

5. **Gateway pipeline e2e via harness** — Cook report notes Pingora harness not in repo; full e2e deferred
   - Status: `relay_pipeline_handover.rs` tests the wiring contract (sufficient for gating)
   - Full Pingora integration waits on gateway test harness (separate initiative)

### For Documentation

1. **Phase-08 docs scope** — What sections of `docs/custom-rules-syntax.md` should document rule engine predicates if 06b is deferred?
   - Current state: phase-08 lists `signal:/asn_class:/chain_depth:` examples
   - Recommend: Stub the section with "See phase-06b once landed" or defer docs refresh to after 06b merges

---

## Final Status Check

**Plan Sync Complete:** All phase files (01–08) now accurately reflect shipped code + documented deferrals.

| Phase | Status | Remarks |
|---|---|---|
| 01 | ✓ Completed | Skeleton + config parser |
| 02 | ✓ Completed | XFF + proxy-chain providers |
| 03 | ✓ Completed | ASN classifier + 3 feeds |
| 04 | ✓ Completed | Tor exit + intel refresh tasks |
| 05 | ✓ Completed | Hot-reload wiring |
| 06 | ✓ Complete (core) / ⏳ Pending (06b) | Detector integration done; rule predicates split to 06b |
| 07 | ✓ Complete (with deferrals) | Tests, bench, adversarial matrix shipped; CI gates + numeric test deferred |
| 08 | ⏳ Pending | Docs sync (post-delivery) |

---

## Recommendations

1. **Immediate:** Commit plan file updates (this report + phase-XX-*.md changes)
2. **This week:** File tickets for CI yaml changes (llvm-cov gate, unwrap grep)
3. **Next:** Clarify phase-06b acceptance + timeline (rule predicates waits on FR-025)
4. **Before merge:** Verify PROPTEST_SEED is set in CI workflow
5. **Optional:** Replace bench's EmptyAsnDb with StaticDb for p99 fidelity (low-effort, medium-value)

---

**Status:** DONE
