# Codebase Validation & User Stories

**Date:** 2026-04-21 | **Reviewer:** code-reviewer | **Mode:** Codebase scan

---

## Executive Summary

| Metric | Original Gap Analysis | Actual Codebase | Delta |
|--------|----------------------|-----------------|-------|
| P0 EXISTS | 24 | 21 | -3 |
| P0 PARTIAL | 6 | 9 | +3 |
| P0 MISSING | 9 | 9 | 0 |
| Coverage | 77% | **69%** | -8% |

**Additional Issues Found:**
- Audit log schema missing 3 required fields
- Rule schema missing `risk_score_delta` and action types
- No tiered protection system (CRITICAL/HIGH/MEDIUM/CATCH-ALL)

---

## Validation Results by Requirement

### CONFIRMED EXISTS (21)

| ID | Requirement | Implementation Evidence |
|----|-------------|------------------------|
| FR-001 | Full reverse proxy | `gateway/` crate, Pingora-based |
| FR-003 | Rule Engine | `waf-engine/src/rules/` — YAML/JSON/ModSec |
| FR-005 | DDoS Protection | `checks/cc.rs` — token bucket + auto-ban |
| FR-008 | Whitelist + Blacklist | `checker.rs`, `models.rs` AllowIp/BlockIp |
| FR-009 | Smart Caching | `gateway/src/cache.rs` — moka LRU |
| FR-013 | SQL Injection | `checks/sql_injection.rs` — libinjection |
| FR-014 | XSS | `checks/xss.rs` — libinjection |
| FR-015 | Path Traversal | `checks/dir_traversal.rs` |
| FR-016 | SSRF | `url_validator.rs` — RFC-1918 blocking |
| FR-017 | HTTP Header Injection | OWASP CRS rules |
| FR-018 | Brute Force | `rules/builtin/bot.rs` |
| FR-019 | Error Scanning | `checks/scanner.rs` |
| FR-020 | Request Body Abuse | OWASP rules |
| FR-021 | Hot-reload rules | `rules/hot_reload.rs` — file watcher |
| FR-029 | Live request feed | `websocket.rs` — /ws/events |
| FR-030 | Attack visualization | Vue 3 Dashboard |
| FR-031 | Hot config | API endpoints in `waf-api/` |
| FR-036 | Fail-close | CrowdSec config option |
| FR-037 | Fail-open | CrowdSec config option |
| FR-038 | Configurable fail mode | Per-config toggle |
| FR-039 | Circuit breaker | Pingora upstream health |

### DOWNGRADED TO PARTIAL (3 reclassified)

| ID | Original | Actual | Evidence | Gap |
|----|----------|--------|----------|-----|
| FR-004 | EXISTS | **PARTIAL** | `cc.rs:19` — `Per-IP token bucket state` | Missing per-user-session rate limiting |
| FR-022 | EXISTS | **PARTIAL** | `formats/mod.rs:17-22` — Only YAML/ModSec/JSON | **TOML required per 5.4**, not implemented |
| FR-032 | EXISTS | **PARTIAL** | `models.rs:79-96` — AttackLog struct | Missing `device_fp`, `risk_score`, `ts_ms` fields |

### CONFIRMED PARTIAL (6 original)

| ID | Requirement | Current State | Missing |
|----|-------------|---------------|---------|
| FR-002 | Tiered protection | Single severity level | **4 tiers (CRITICAL/HIGH/MEDIUM/CATCH-ALL) not implemented** |
| FR-007 | Relay & Proxy Detection | GeoIP + Tor exit list | ASN classification, X-Forwarded-For validation |
| FR-023 | Rule scoping | Global + per-host | per-tier, per-route, per-session, per-device-fp |
| FR-024 | Rule priority | `priority: i32` in CustomRule | No conflict resolution logic |
| FR-033 | Response filtering | SensitivePattern model exists | No active outbound inspection |
| FR-041 | Geographic Restriction | `checks/geo.rs` exists | VPN geo bypass detection |

### CONFIRMED MISSING (9 critical)

| ID | Requirement | Search Evidence | Impact |
|----|-------------|-----------------|--------|
| FR-006 | Challenge Engine | No "challenge", "PoW" matches | No bot challenge system |
| FR-010 | Device Fingerprinting | No "ja3", "ja4", "fingerprint" | Cannot track device across IPs |
| FR-011 | Behavioral Anomaly | No anomaly detection code | Bot timing evasion vulnerable |
| FR-012 | Transaction Velocity | No cross-endpoint tracking | Fraud detection missing |
| FR-025 | Cumulative Risk Scoring | No "risk.*score" matches | No adaptive risk model |
| FR-026 | Risk Score Dynamics | No risk accumulation logic | Binary allow/block only |
| FR-027 | Decision Thresholds | No threshold system | No Allow/Challenge/Block bands |
| FR-028 | Canary / Honeypot | No canary/honeypot code | No trap detection |
| FR-034/035 | Outbound Protection | No "outbound", "redact" matches | Response leaks possible |

---

## Schema Gaps

### Rule Schema (`registry.rs:9-29`)

```rust
// CURRENT
pub action: String,        // "block | log | allow"
pub severity: Option<String>,

// REQUIRED (per 5.4)
pub action: String,        // "block | log | allow | challenge | rate-limit"
pub risk_score_delta: Option<i32>,  // MISSING
pub scope: RuleScope,      // MISSING - global/tier/route/ip/session/device
```

### Audit Log Schema (`models.rs:79-96`)

```rust
// CURRENT AttackLog fields
pub client_ip: String,
pub created_at: DateTime<Utc>,  // Not milliseconds

// REQUIRED (per 5.6) - MISSING
pub device_fp: Option<String>,
pub risk_score: Option<i32>,
pub ts_ms: i64,  // Millisecond precision
```

---

## User Stories — Development Backlog

### Epic 1: Risk Scoring Engine (FR-025, FR-026, FR-027)

**US-001: Cumulative Risk Score Tracking**
```
As a WAF operator
I want each request to have a cumulative risk score per {IP + device + session}
So that repeat offenders accumulate risk over time rather than starting fresh

Acceptance Criteria:
- Risk score persists across requests (DashMap in-memory)
- Score keyed by IP + device_fp + session_id
- Score does not reset per request
- Score retrievable via API for debugging
```

**US-002: Risk Score Increase Rules**
```
As a security engineer
I want risk scores to increase on rule match, failed challenge, anomaly detection
So that suspicious behavior is penalized cumulatively

Acceptance Criteria:
- Rule match: +risk_score_delta from rule config
- Failed challenge: +20 (configurable)
- Anomaly detection: +15 (configurable)
- Suspicious ASN (datacenter/Tor): +10
- Device fingerprint conflict: +25
```

**US-003: Risk Score Decrease Rules**
```
As a WAF operator
I want risk scores to decrease on successful challenge and sustained normal behavior
So that legitimate users aren't permanently penalized

Acceptance Criteria:
- Successful challenge: -30 (configurable)
- 10 consecutive normal requests: -5
- Decay over time: -1 per minute if no new events
```

**US-004: Decision Threshold Actions**
```
As a WAF operator
I want configurable thresholds that determine Allow/Challenge/Block actions
So that I can tune the sensitivity of my protection

Acceptance Criteria:
- Default thresholds: <30 Allow, 30-70 Challenge, >70 Block
- Thresholds configurable per-tier
- Challenge action triggers JS challenge (FR-006)
- Threshold changes hot-reloadable
```

---

### Epic 2: Challenge Engine (FR-006)

**US-005: JS Challenge Page**
```
As a WAF operator
I want suspicious requests to receive a JS challenge page
So that bots without JavaScript execution fail automatically

Acceptance Criteria:
- Challenge page served for risk score 30-70
- Page contains JavaScript that must execute to pass
- Cookie set on successful challenge
- Subsequent requests with valid cookie bypass challenge
- Challenge page customizable (logo, message)
```

**US-006: Proof-of-Work Challenge**
```
As a security engineer
I want a PoW challenge option for DDoS mitigation
So that attackers must expend computational resources

Acceptance Criteria:
- SHA256-based target difficulty
- Configurable difficulty level (leading zeros)
- Client submits nonce solution
- Server validates within 100ms
- Failed PoW increases risk score
```

---

### Epic 3: Device Fingerprinting (FR-010)

**US-007: JA3/JA4 TLS Fingerprinting**
```
As a security engineer
I want TLS fingerprints extracted from ClientHello
So that I can track devices across IP changes

Acceptance Criteria:
- JA3 fingerprint extracted during TLS handshake
- JA4 fingerprint extracted (improved algorithm)
- Fingerprint stored in request context
- Fingerprint logged in audit log
- API endpoint to query fingerprint statistics
```

**US-008: HTTP/2 Settings Fingerprinting**
```
As a security engineer
I want HTTP/2 SETTINGS frame fingerprinting
So that I can detect browser impersonation

Acceptance Criteria:
- Extract SETTINGS_MAX_CONCURRENT_STREAMS, SETTINGS_INITIAL_WINDOW_SIZE
- Hash settings into fingerprint
- Compare against known browser profiles
- Flag mismatches between User-Agent and HTTP/2 fingerprint
```

---

### Epic 4: Behavioral Anomaly Detection (FR-011)

**US-009: Inter-Request Timing Analysis**
```
As a security engineer
I want requests with <50ms inter-arrival time flagged
So that automated tooling is detected

Acceptance Criteria:
- Track last request timestamp per IP
- Flag if interval < 50ms (configurable)
- Add risk_score_delta on detection
- Log anomaly type in audit log
```

**US-010: Zero-Depth Session Detection**
```
As a security engineer
I want sessions that never visit intermediate pages flagged
So that direct-to-target bots are detected

Acceptance Criteria:
- Track pages visited per session
- Flag sessions going directly to /login, /api without homepage
- Configurable depth threshold
- Whitelist certain direct-access paths
```

**US-011: Missing Referer Detection**
```
As a security engineer
I want internal navigation without Referer header flagged
So that programmatic access is detected

Acceptance Criteria:
- Track navigation flow per session
- Flag requests to internal pages with missing Referer
- Whitelist first page load and bookmarked URLs
- Add risk score on violation
```

---

### Epic 5: Transaction Velocity (FR-012)

**US-012: Cross-Endpoint Sequence Tracking**
```
As a fraud analyst
I want Login→OTP→Deposit sequences tracked
So that rapid transaction patterns are detected

Acceptance Criteria:
- State machine tracks: Login → OTP → Transaction
- Flag if sequence completes in < 5 seconds
- Configurable sequence definitions
- Per-user-session tracking
```

**US-013: Withdrawal Velocity Detection**
```
As a fraud analyst
I want rapid withdrawal attempts detected
So that account takeover fraud is blocked

Acceptance Criteria:
- Track withdrawal count per session in time window
- Flag if > 3 withdrawals in 60 seconds
- Configurable thresholds per tier
- Block + alert on violation
```

---

### Epic 6: Outbound Protection (FR-033, FR-034, FR-035)

**US-014: Response Body Filtering**
```
As a security engineer
I want stack traces, internal IPs, and API keys blocked in responses
So that sensitive information doesn't leak

Acceptance Criteria:
- Inspect response body before sending to client
- Detect: stack traces, 10.x/172.16.x IPs, API key patterns
- Replace with generic error message
- Log redaction event
```

**US-015: Sensitive Field Redaction**
```
As a compliance officer
I want card_number, bank_account fields masked in JSON responses
So that PCI-DSS requirements are met

Acceptance Criteria:
- Configurable field names to mask
- Mask pattern: show last 4 digits
- Apply to JSON and form-encoded responses
- Log redaction without logging actual values
```

**US-016: Header Leak Prevention**
```
As a security engineer
I want X-Debug, X-Internal-* headers stripped from responses
So that internal infrastructure details don't leak

Acceptance Criteria:
- Configurable header patterns to strip
- Default list: X-Debug-*, X-Internal-*, X-Powered-By
- Log stripped headers (names only)
- Hot-reloadable configuration
```

---

### Epic 7: Canary/Honeypot (FR-028)

**US-017: Decoy Path Configuration**
```
As a security engineer
I want configurable honeypot paths
So that attackers probing for admin panels are caught

Acceptance Criteria:
- Configure decoy paths: /admin-test, /api-debug, /.env
- Any request to decoy path triggers max risk score
- IP immediately blocked
- Alert sent to notification channel
```

---

### Epic 8: Tiered Protection (FR-002)

**US-018: Four-Tier Route Classification**
```
As a WAF operator
I want routes classified into 4 protection tiers
So that critical paths get stricter policies

Acceptance Criteria:
- CRITICAL tier: /login, /otp, /withdrawal — fail-close, no cache
- HIGH tier: /deposit, /transfer — aggressive rate limiting
- MEDIUM tier: /api/* — standard protection
- CATCH-ALL tier: /static, /* — fail-open, cacheable
```

**US-019: Per-Tier Policy Configuration**
```
As a WAF operator
I want each tier to have distinct fail-mode, cache, and rate-limit policies
So that protection matches business criticality

Acceptance Criteria:
- Per-tier: fail_mode (close/open), cache_ttl, rate_limit
- Per-tier: risk score thresholds
- Configuration in YAML/TOML
- Hot-reloadable tier config
```

---

### Epic 9: Rule System Enhancements (FR-022, FR-023, FR-024)

**US-020: TOML Rule Format Support**
```
As a security engineer
I want rules definable in TOML format
So that the competition requirement is met

Acceptance Criteria:
- Add TOML parser in rules/formats/
- Support same schema as YAML
- File extension detection: .toml
- Validation on load
```

**US-021: Extended Rule Scoping**
```
As a security engineer
I want rules scoped to tier, route-pattern, session, device-fingerprint
So that granular policies are possible

Acceptance Criteria:
- Scope enum: Global, PerTier, PerRoute, PerIP, PerSession, PerDeviceFp
- Rules filtered by scope during evaluation
- Scope inheritance: Global < Tier < Route < Session
```

**US-022: Rule Schema Extension**
```
As a security engineer
I want rules to have risk_score_delta and new action types
So that risk scoring integration works

Acceptance Criteria:
- Add field: risk_score_delta: Option<i32>
- Add actions: challenge, rate-limit
- Validate schema on rule load
- Migrate existing rules with default values
```

---

### Epic 10: Audit Log Enhancement (FR-032)

**US-023: Extended Audit Log Schema**
```
As a SIEM operator
I want audit logs with device_fp, risk_score, and millisecond timestamps
So that full context is available for analysis

Acceptance Criteria:
- Add columns: device_fp, risk_score, ts_ms
- ts_ms as Unix epoch milliseconds
- device_fp from FR-010 implementation
- risk_score from FR-025 implementation
```

---

### Epic 11: Rate Limiting Enhancement (FR-004)

**US-024: Per-User-Session Rate Limiting**
```
As a security engineer
I want rate limits applied per user session, not just per IP
So that shared IP users aren't unfairly limited

Acceptance Criteria:
- Session ID from cookie or header
- Separate token bucket per session
- Fallback to IP if no session
- Configurable per-tier
```

---

## Priority Matrix

| Priority | Epic | User Stories | Est. Days | Blocks |
|----------|------|--------------|-----------|--------|
| P0-CRITICAL | Risk Scoring | US-001→004 | 5 | Audit log, thresholds |
| P0-CRITICAL | Device Fingerprinting | US-007→008 | 4 | Audit log, risk scoring |
| P0-CRITICAL | Challenge Engine | US-005→006 | 4 | Risk scoring |
| P0-CRITICAL | Outbound Protection | US-014→016 | 3 | — |
| P0-HIGH | Behavioral Anomaly | US-009→011 | 3 | Risk scoring |
| P0-HIGH | Transaction Velocity | US-012→013 | 3 | Session tracking |
| P0-HIGH | Tiered Protection | US-018→019 | 3 | — |
| P0-MEDIUM | Rule Enhancements | US-020→022 | 2 | — |
| P0-MEDIUM | Canary/Honeypot | US-017 | 1 | Risk scoring |
| P0-MEDIUM | Audit Log | US-023 | 1 | Device FP, Risk |
| P0-LOW | Rate Limit Enhancement | US-024 | 2 | Session tracking |

**Total Estimated Effort:** 31 days

---

## Dependency Graph

```
US-007 (Device FP) ─┬─> US-023 (Audit Log)
                    │
US-001 (Risk Score) ┼─> US-004 (Thresholds) ─> US-005 (Challenge)
                    │
US-009 (Anomaly) ───┘

US-018 (Tiers) ─> US-019 (Tier Policy) ─> US-024 (Session Rate Limit)

US-020 (TOML) ─> US-021 (Scoping) ─> US-022 (Schema)
```

---

## Unresolved Questions

None — Issue #9 feedback resolved all open questions.

---

## Recommendations

1. **Start with FR-010 Device Fingerprinting** — unblocks audit log and risk scoring
2. **Implement FR-025 Risk Scoring next** — core dependency for Challenge, Anomaly, Thresholds
3. **FR-033-035 Outbound Protection has no dependencies** — can parallelize
4. **TOML parser (US-020) is quick win** — 1 day effort, competition requirement
