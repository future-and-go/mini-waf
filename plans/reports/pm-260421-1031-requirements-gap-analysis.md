# Requirements Gap Analysis: PRX-WAF vs Hackathon Requirements

**Date:** 2026-04-21
**Source:** `analysis/requirements.md` vs current codebase

---

## Summary

| Category | Total | Exists | Partial | Missing | Coverage |
|----------|-------|--------|---------|---------|----------|
| P0 Must-Have | 39 | 24 | 6 | 9 | 77% |
| P1 Should-Have | 7 | 3 | 2 | 2 | 57% |
| Non-Functional | 9 | 7 | 1 | 1 | 83% |

**Overall Readiness: ~75%** — Core proxy, detection, rules engine solid. Major gaps in risk scoring, behavioral analysis, challenge engine, and outbound filtering.

---

## P0 Must-Have Requirements (39 total)

### EXISTS (24)

| ID | Requirement | Implementation |
|----|-------------|----------------|
| FR-001 | Full reverse proxy | Pingora-based gateway crate, HTTP/1.1/2/3 support |
| FR-003 | Rule Engine | `waf-engine/rules/` — YAML/JSON/ModSec formats, regex/wildcard/exact match |
| FR-004 | Rate Limiting | `checks/cc.rs` — token bucket per IP, sliding window, auto-ban |
| FR-005 | DDoS Protection | CC check + burst detection + configurable thresholds |
| FR-008 | Whitelist + Blacklist | `checker.rs` — IP/URL allow/block lists from PostgreSQL |
| FR-009 | Smart Caching | `gateway` crate — moka LRU cache with TTL per route |
| FR-013 | SQL Injection | `checks/sql_injection.rs` — libinjection-based, URL/headers/body |
| FR-014 | XSS | `checks/xss.rs` — libinjection XSS detection |
| FR-015 | Path Traversal | `checks/dir_traversal.rs` — ../ sequences, URL-encoded variants |
| FR-016 | SSRF | `url_validator.rs` — RFC-1918 blocking, DNS rebinding guard |
| FR-017 | HTTP Header Injection | OWASP CRS rules cover CRLF, Host header injection |
| FR-018 | Brute Force | `rules/bot-detection/credential-stuffing.yaml` + scanner detection |
| FR-019 | Error Scanning / Recon | `checks/scanner.rs` — rapid 4xx/5xx pattern detection |
| FR-020 | Request Body Abuse | OWASP rules for malformed JSON, content-type mismatch |
| FR-021 | Hot-reload rules | `rules/hot_reload.rs` — file watcher + SIGHUP handler |
| FR-022 | Rule format | YAML, JSON, ModSecurity formats supported |
| FR-029 | Live request feed | WebSocket `/ws/events` + `/ws/logs` real-time streaming |
| FR-030 | Attack visualization | Vue 3 Dashboard with attack timelines, charts |
| FR-031 | Hot config | API endpoints for rule updates without restart |
| FR-032 | Structured audit log | PostgreSQL attack_logs table, JSON format |
| FR-036 | Fail-close | CrowdSec config `fail_open: false` option |
| FR-037 | Fail-open | CrowdSec config `fail_open: true` option |
| FR-038 | Configurable fail mode | Per-config fail mode toggle |
| FR-039 | Circuit breaker | Pingora upstream health checks + 503 on backend failure |

### PARTIAL (6) — Needs Improvement

| ID | Requirement | Current State | Gap |
|----|-------------|---------------|-----|
| FR-002 | Tiered protection (4 tiers) | Single severity level in rules | **Need 4 distinct tiers: CRITICAL/HIGH/MEDIUM/CATCH-ALL with separate policies** |
| FR-007 | Relay & Proxy Detection | GeoIP + Tor exit list rules | **Missing: ASN classification (residential/datacenter), X-Forwarded-For chain validation** |
| FR-023 | Rule scoping | Global + per-host rules | **Missing: per-tier, per-route-pattern, per-device-fingerprint scoping** |
| FR-024 | Rule priority | Basic rule ordering | **Need explicit numeric priority field for conflict resolution** |
| FR-033 | Response filtering | Rules detect SQL errors in response | **Need active blocking of stack traces, internal IPs, API keys** |
| FR-041 | Geographic Restriction | `checks/geo.rs` exists | **Need VPN geo bypass detection** |

### MISSING (9) — Critical Gaps

| ID | Requirement | Impact | Effort |
|----|-------------|--------|--------|
| FR-006 | **Challenge Engine** (JS Challenge, PoW) | No bot challenge system; direct block only | HIGH |
| FR-010 | **Device Fingerprinting** (JA3/JA4, HTTP/2 settings) | Cannot track device across IP changes | HIGH |
| FR-011 | **Behavioral Anomaly Detection** (timing, zero-depth, inter-request < 50ms) | Bot evasion vulnerable | MEDIUM |
| FR-012 | **Transaction Velocity & Sequence** (Login→OTP→Deposit tracking) | Fraud detection missing | HIGH |
| FR-025 | **Cumulative Risk Scoring** (per IP+device+session) | No adaptive risk model | HIGH |
| FR-026 | **Risk Score Dynamics** (increase/decrease rules) | No risk accumulation | MEDIUM |
| FR-027 | **Decision Thresholds** (<30 Allow, 30-70 Challenge, >70 Block) | Binary allow/block only | MEDIUM |
| FR-028 | **Canary / Honeypot** (decoy paths, auto max risk) | No trap detection | LOW |
| FR-034 | **Sensitive Field Redaction** (mask card_number, bank_account in response) | Response leaks possible | MEDIUM |
| FR-035 | **Header Leak Prevention** (X-Debug, X-Internal-*) | Internal headers may leak | LOW |

---

## P1 Should-Have Requirements (7 total)

| ID | Requirement | Status | Notes |
|----|-------------|--------|-------|
| FR-040 | HTTPS/TLS termination | **EXISTS** | Let's Encrypt automation, configurable ciphers |
| FR-041 | Geographic Restriction | **PARTIAL** | GeoIP exists; missing VPN bypass detection |
| FR-042 | IP Reputation Feed | **EXISTS** | Tor exit list, bad ASN from files, CrowdSec integration |
| FR-043 | Multi-region Deployment | **PARTIAL** | Cluster exists; no `waf deploy --region` CLI |
| FR-044 | Zero-downtime Config Sync | **EXISTS** | Hot-reload + cluster rule sync |
| FR-045 | Auto Scaling | **MISSING** | No horizontal scaling / Redis/etcd shared state |
| FR-046 | Behavioral ML Scoring | **MISSING** | No ML model for bot vs human classification |

---

## Non-Functional Requirements (9 total)

| Requirement | Target | Status | Notes |
|-------------|--------|--------|-------|
| Latency overhead | p99 <= 5ms | **EXISTS** | Rust + Pingora inherently fast; k6 benchmarks included |
| Throughput | >= 5,000 req/s | **EXISTS** | Benchmark scripts show >10K RPS capability |
| Memory footprint | Low | **EXISTS** | Efficient data structures (DashMap, moka) |
| Behavior under DDoS | Graceful degradation | **EXISTS** | Token bucket + auto-ban + fail modes |
| Binary format | Single binary, zero deps | **EXISTS** | Cargo builds single binary |
| Startup | `./waf run` | **PARTIAL** | `./prx-waf run` (different name) |
| Language: Core WAF | Rust mandatory | **EXISTS** | 100% Rust core |
| Language: Dashboard | Any | **EXISTS** | Vue 3 |
| Bidirectional inspection | Inbound & outbound | **MISSING** | Inbound only; outbound filtering not implemented |

---

## Priority Recommendations

### Week 1: High-Impact Security Gaps (40 pts at stake)

1. **Cumulative Risk Scoring Engine** (FR-025, FR-026, FR-027)
   - Add `RiskScoreManager` with per-IP+session accumulation
   - Implement threshold-based actions: Allow/Challenge/Block

2. **Device Fingerprinting** (FR-010)
   - JA3/JA4 TLS fingerprinting in gateway layer
   - HTTP/2 settings hash for browser detection

3. **Behavioral Anomaly Detection** (FR-011)
   - Inter-request timing analysis
   - Session depth tracking (pages visited)
   - Missing Referer on internal navigation

### Week 2: Challenge & Transaction Tracking

4. **Challenge Engine** (FR-006)
   - JS challenge page for suspicious requests
   - Proof-of-Work option for DDoS mitigation

5. **Transaction Velocity** (FR-012)
   - Cross-endpoint tracking state machine
   - Rapid action sequence detection

6. **Tiered Protection** (FR-002)
   - Route→Tier mapping configuration
   - Per-tier fail modes and policies

### Week 3: Outbound & Polish

7. **Response Filtering** (FR-033, FR-034, FR-035)
   - Outbound inspection phase in pipeline
   - Sensitive field masking
   - Header leak prevention

8. **Canary/Honeypot** (FR-028)
   - Decoy endpoint configuration
   - Auto-block on canary hit

---

## Architecture Impact

Adding missing features requires:

1. **New crate or module**: `waf-engine/src/risk/` for risk scoring
2. **Gateway modification**: JA3/JA4 extraction during TLS handshake
3. **State management**: Session/device tracking (Redis or in-memory with cluster sync)
4. **Response phase**: New pipeline phase for outbound filtering
5. **Challenge page**: Static HTML/JS assets + verification endpoint

---

## Unresolved Questions

1. Is PostgreSQL sufficient for high-throughput risk score updates, or need Redis?
2. Should JA3/JA4 fingerprinting be in Pingora or separate TLS layer?
3. Challenge page design: custom HTML or integrate with existing block page?
4. Transaction velocity: how long to retain cross-endpoint state?
