# GH-195 Risk Action Enforcement — Test Verification Report

**Date:** 2026-07-05  
**Branch:** fix/gh-195-risk-action-enforcement  
**Tester:** gh195-tester  
**Environment:** Linux, Postgres 127.0.0.1:15433, --test-threads=1

---

## Executive Summary

All 5 enforcement tests passed. All 233 risk unit-test modules passed. Code format check passed. Test bodies confirm proper coverage of risk-enforcement contract: threshold-driven decisions (Block/Challenge/Allow), canary honeypot with IP-ban integration, monitor-mode LogOnly downgrade, pipeline-decision protection (risk never overrides detections), and fast-path scoring bypass.

---

## Test Execution Results

### 1. Enforcement Tests (5 tests)

**Command:** `PG_TEST_URL="postgres://postgres:postgres@127.0.0.1:15433/postgres" cargo test -p waf-engine --lib -- --test-threads=1 risk_threshold canary_hit risk_block risk_never fast_path_exits`

**Result:** ✅ **ALL PASSED**

```
test engine::tests::canary_hit_bans_and_pin_blocks ... ok
test engine::tests::fast_path_exits_skip_risk_scoring ... ok
test engine::tests::risk_block_respects_monitor_mode ... ok
test engine::tests::risk_never_overrides_pipeline_decisions ... ok
test engine::tests::risk_threshold_matrix_enforced ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured
```

### 2. Risk Unit-Test Modules (233 tests)

**Command:** `PG_TEST_URL="postgres://postgres:postgres@127.0.0.1:15433/postgres" cargo test -p waf-engine --lib -- risk::`

**Result:** ✅ **ALL PASSED**

```
test result: ok. 233 passed; 0 failed; 0 ignored; 0 measured
```

Coverage includes: anomaly detection (header sanity, JA4/UA mismatch, XFF chain), canary layer, challenge-credit (nonce store, secret, token), config parsing, decay, ingest pipeline, key builder, scoring, state management, store conformance, threshold decision, velocity (window + sequence), and reload logic.

### 3. Code Format Check

**Command:** `cargo fmt --all --check`

**Result:** ✅ **PASSED** (no output = compliant)

---

## Test Body Verification

### Test 1: risk_threshold_matrix_enforced (lines 1401–1439)

**Purpose:** Enforce threshold-driven decisions (Block/Challenge/Allow)

**Assertions Verified:**

1. ✅ **Block 403 + Phase::RiskScore + rule_name "cumulative_risk"**
   - Lines 1407–1416: score 0 at thresholds [allow=0, block=0] → WafAction::Block {status: 403}
   - result.phase == waf_common::Phase::RiskScore
   - result.rule_name == "cumulative_risk"

2. ✅ **Challenge band**
   - Lines 1418–1428: score 0 in band [allow=0, block=101) → WafAction::Challenge
   - result.phase == waf_common::Phase::RiskScore
   - result.rule_name == "cumulative_risk"

3. ✅ **disabled-config Allow**
   - Lines 1430–1438: RiskConfig::default() (enabled=false) → WafAction::Allow
   - No enforcement occurs when risk config is disabled

---

### Test 2: canary_hit_bans_and_pin_blocks (lines 1445–1524)

**Purpose:** FR-028 canary contract: honeypot hit → score pin + IP ban

**Assertions Verified:**

1. ✅ **Canary 403 with score 100**
   - Lines 1476–1487: canary path "/admin-test" hit → WafAction::Block {status: 403}
   - decision.risk_score == 100
   - result.phase == waf_common::Phase::RiskScore
   - result.rule_name == "cumulative_risk"

2. ✅ **Same-IP follow-up blocked at Phase::Ddos**
   - Lines 1489–1503: same IP "203.0.113.50" on normal path "/" → WafAction::Block
   - result.phase == waf_common::Phase::Ddos (NOT Phase::RiskScore)
   - Proves canary inserted the IP into DDoS ban table; Phase 19 (Ddos) runs pre-scoring

3. ✅ **Different-IP force_max pin block**
   - Lines 1505–1523: IP "203.0.113.51" pinned via force_max() → WafAction::Block {status: 403}
   - decision.risk_score == 100
   - result.phase == waf_common::Phase::RiskScore
   - Proves threshold override (pin) blocks even with default permissive thresholds

---

### Test 3: risk_block_respects_monitor_mode (lines 1529–1552)

**Purpose:** Monitor mode on risk_assessment downgrades Block to LogOnly

**Assertions Verified:**

1. ✅ **monitor-mode LogOnly downgrade**
   - Lines 1537–1548: risk block at block-at-0 thresholds + mode LogOnly
   - decision.action matches WafAction::Block {...} (intent preserved)
   - decision.mode == InteropMode::LogOnly
   - decision.is_enforcement_allowed() == true (request proceeds)
   - result.phase == waf_common::Phase::RiskScore
   - result.rule_name == "cumulative_risk"

---

### Test 4: risk_never_overrides_pipeline_decisions (lines 1557–1597)

**Purpose:** Escalation gate applies to plain-Allow only; enforced/monitored detections keep their own phase

**Assertions Verified:**

1. ✅ **SQLi-decision-not-overridden (enforced)**
   - Lines 1562–1576: SQLi payload at block-at-0 thresholds → WafAction::Block
   - result.phase == waf_common::Phase::SqlInjection (NOT Phase::RiskScore)
   - Proves enforced detection keeps its own phase despite risk threshold

2. ✅ **SQLi-decision-not-overridden (LogOnly'd)**
   - Lines 1578–1596: SQLi payload with injection_control in LogOnly mode
   - decision.result.phase == waf_common::Phase::SqlInjection (NOT Phase::RiskScore)
   - decision.mode == InteropMode::LogOnly
   - decision.is_enforcement_allowed() == true (request proceeds)
   - Proves LogOnly'd detection is not replaced by risk escalation

---

### Test 5: fast_path_exits_skip_risk_scoring (lines 1270–1346)

**Purpose:** Fast-path exits (whitelist hit) skip risk scoring entirely

**Assertions Verified:**

1. ✅ **Fast-path exits skip risk scoring entirely**
   - Lines 1328–1336: whitelisted IP "203.0.113.7" → WafAction::Allow
   - decision.risk_score == 0
   - engine.scorer.store().is_empty() == true (no store write)

2. ✅ **Normal allowed request still scores**
   - Lines 1338–1345: clean request IP "198.51.100.9" → WafAction::Allow
   - engine.scorer.store().is_empty() == false (store written)

---

## Coverage Matrix

| Requirement | Test | Coverage | Status |
|-------------|------|----------|--------|
| Block 403 + Phase::RiskScore + "cumulative_risk" | risk_threshold_matrix_enforced | lines 1407–1416 | ✅ |
| Challenge band decision | risk_threshold_matrix_enforced | lines 1418–1428 | ✅ |
| Disabled config Allow | risk_threshold_matrix_enforced | lines 1430–1438 | ✅ |
| Canary 403 with score 100 | canary_hit_bans_and_pin_blocks | lines 1476–1487 | ✅ |
| Same-IP follow-up Phase::Ddos | canary_hit_bans_and_pin_blocks | lines 1489–1503 | ✅ |
| Force-max pin block | canary_hit_bans_and_pin_blocks | lines 1505–1523 | ✅ |
| Monitor-mode LogOnly downgrade | risk_block_respects_monitor_mode | lines 1537–1548 | ✅ |
| Enforced detection not overridden | risk_never_overrides_pipeline_decisions | lines 1562–1576 | ✅ |
| LogOnly'd detection not overridden | risk_never_overrides_pipeline_decisions | lines 1578–1596 | ✅ |
| Fast-path skip scoring | fast_path_exits_skip_risk_scoring | lines 1328–1336 | ✅ |

---

## Critical Path Validation

✅ **Risk-threshold enforcement chain intact:**
- Threshold decision (decide()) → WafAction escalation → Phase::RiskScore output
- Escalation gate applies to Allow only; detections keep original phase

✅ **Canary → DDoS ban integration working:**
- Canary hit pins score to 100 + inserts IP into dynamic ban table
- Follow-up request hits Phase::Ddos (pre-scoring), not risk-scored again

✅ **Monitor mode rollout valve working:**
- Risk enforcement respects mode downgrades; LogOnly requests proceed
- Intent (Block) preserved in decision for audit/logging

✅ **Fast-path scoring bypass working:**
- Whitelist hit exits early; no risk-store writes
- Normal allowed requests still score for state tracking

---

## Summary

**Tests Run:** 238 (5 enforcement + 233 risk modules)  
**Tests Passed:** 238  
**Tests Failed:** 0  
**Format Compliant:** Yes  

**Conclusion:** All enforcement tests pass. Test bodies confirm complete coverage of GH-195 risk-action enforcement contract. No regressions detected. Code ready for integration.

