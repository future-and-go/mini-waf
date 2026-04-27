# Gap Analysis Evaluation: Issue #9 vs Report

**Date:** 2026-04-21 | **Source:** GitHub Issue #9 vs `pm-260421-1031-requirements-gap-analysis.md`

---

## Summary

| Aspect | Original Report | Issue #9 Feedback | Delta |
|--------|-----------------|-------------------|-------|
| P0 MISSING count | 9 | 9 (confirmed) | Match |
| Priority accuracy | 6 items misclassified | 4 items should be HIGH | -4 corrections |
| Technical details | 5 errors/omissions | 5 corrections needed | -5 corrections |
| Scoping gaps | 3 missing scopes | 4 missing scopes | -1 additional |
| Unresolved questions | 4 questions | 4 answers provided | Resolved |

**Verdict:** Report 77% accurate. 10 corrections needed.

---

## Priority Misclassifications (CRITICAL)

Section 5.7 Response Filtering is **MANDATORY** per competition rules but report underestimated:

| ID | Report Priority | Correct Priority | Fix Needed |
|----|-----------------|------------------|------------|
| FR-033 | PARTIAL (implicit medium) | **PARTIAL — HIGH** | Active blocking required |
| FR-034 | MISSING — MEDIUM | **MISSING — HIGH** | 5.7 mandatory |
| FR-035 | MISSING — LOW | **MISSING — HIGH** | 5.7 mandatory |
| Bidirectional | MISSING — NF | **MISSING — CORE** | 5.1 + 5.7 mandatory |

---

## Status Reclassifications

| ID | Report Status | Correct Status | Reason |
|----|---------------|----------------|--------|
| FR-004 Rate Limiting | EXISTS | **PARTIAL** | Missing per-user-session (only has per-IP) |
| FR-022 Rule format | EXISTS | **PARTIAL** | TOML required per 5.4; JSON/ModSec not mandatory |

---

## Technical Detail Errors

| Item | Report Says | Competition Requires | Action |
|------|-------------|---------------------|--------|
| Rule format | YAML, JSON, ModSec | **YAML or TOML** | Add TOML parser |
| Rate limiting | per-IP | **per-IP + per-user-session** | Add user-session dimension |
| Rule schema | condition + action | **+ `risk_score_delta`** | Extend schema |
| Action types | allow/block | **+ challenge, rate-limit** | Add action types |
| Audit log | request_id, ts_ms, ip, rule_id, action | **+ device_fp, risk_score** | Extend schema |
| Binary name | `prx-waf run` | **`waf run`** | Rename/alias |

---

## Scoping Gap Update (FR-023)

| Scope | Report Listed | Correct | Status |
|-------|---------------|---------|--------|
| global | Yes | Yes | EXISTS |
| per-tier | Missing | Required | MISSING |
| per-route-pattern | Missing | Required | MISSING |
| per-IP | Implied | Required | EXISTS |
| per-user-session | **Not listed** | Required | MISSING |
| per-device-fingerprint | Missing | Required | MISSING |

Report missed `per-user-session` as required scope.

---

## Unresolved Questions (Now Answered)

| Question | Answer from Issue #9 |
|----------|---------------------|
| PostgreSQL vs Redis for risk score? | DashMap in-memory + PostgreSQL snapshot. Redis only for Auto Scaling bonus. |
| JA3/JA4 location? | Pingora layer via TLS ClientHello callback. Use `ja4` crate or self-parse. |
| Challenge page design? | Simple static HTML + PoW (SHA256 target). No UI spec required. |
| Transaction velocity retention? | 5-60 seconds reasonable. In-memory state with 5-minute TTL. |

---

## Revised Gap Count

| Category | Original | Revised | Change |
|----------|----------|---------|--------|
| P0 EXISTS | 24 | 22 | -2 (FR-004, FR-022 → PARTIAL) |
| P0 PARTIAL | 6 | 8 | +2 |
| P0 MISSING | 9 | 9 | — (count same, priority raised) |
| Coverage | 77% | 72% | -5% |

---

## Corrective Actions Required

### Immediate (Before Next Implementation)

1. **Update report** — reclassify FR-033/034/035 to HIGH, FR-004/022 to PARTIAL
2. **Add TOML parser** — competition mandatory, JSON/ModSec are extras
3. **Extend rule schema** — add `risk_score_delta`, action types `challenge`/`rate-limit`
4. **Audit log schema** — verify `device_fp` + `risk_score` fields (blocked by FR-010/025)

### Implementation Priority Reorder

| Rank | Feature | Reason |
|------|---------|--------|
| 1 | FR-010 Device Fingerprinting | Blocks audit log completeness |
| 2 | FR-025 Risk Scoring | Blocks audit log + decision thresholds |
| 3 | FR-006 Challenge Engine | Enables threshold middle-band |
| 4 | FR-033/034/035 Response Filtering | **HIGH priority per 5.7** |
| 5 | FR-012 Transaction Velocity | Fraud detection |

---

## Report Quality Assessment

| Criterion | Score | Notes |
|-----------|-------|-------|
| Completeness | 85% | Missed 1 scope, 2 status errors |
| Priority accuracy | 60% | 4 HIGH items marked lower |
| Technical detail | 70% | 5 spec mismatches |
| Actionability | 90% | Clear roadmap provided |
| **Overall** | **76%** | Usable with corrections |

---

## Remaining Questions

None — Issue #9 resolved all open questions.
