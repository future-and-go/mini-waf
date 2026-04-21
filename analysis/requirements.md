# Requirements Analysis: WAF Mini Hackathon 2026

**Source:** `source/WAF_MINI_HACKATHON_2026.pdf`
**Analysis Date:** 2026-04-10
**Type:** Internal hackathon competition (not client RFP)

---

## 1. Project Overview

**What:** Build a production-ready Mini WAF (Web Application Firewall) / Security Gateway in Rust. Full reverse proxy that sits in front of an entire website, inspecting all inbound and outbound traffic with tiered protection policies.

**Why:** 
- Create a core security platform deployable to production immediately after competition
- Discover security engineering talent within the Tech Division
- Protect company systems against real-world threats (bots, fraud, DDoS, relay attacks)

**Who:**
- **Builders:** Tech Division employees, teams of 3+ members
- **Evaluators:** Security Leads + external security experts (Red Team)
- **End users:** The target website and its users (transparent proxy)

**Format:** Team competition → 3 weeks dev → 1 week hardening → Attack Battle (45 min live attack per team, fully autonomous defense)

---

## 2. Business Objectives

1. **Production-ready WAF** — not a prototype; must be deployable immediately after competition
2. **Talent discovery** — identify Security Engineers & Future Tech Leaders
3. **Real-world protection** — defend against bots, fraud, DDoS, relay attacks on actual company systems

---

## 3. Functional Requirements

### 3.1 P0 — Must-Have (MANDATORY — Disqualification if missing)

| ID | Category | Requirement | Acceptance Criteria |
|----|----------|-------------|---------------------|
| FR-001 | Core | Full reverse proxy | All requests/responses pass through WAF; backend unaware of WAF |
| FR-002 | Core | Tiered protection | 4 tiers: CRITICAL, HIGH, MEDIUM, CATCH-ALL with distinct policies per tier |
| FR-003 | Core | Rule Engine | Match by IP, Path, Header, Payload, Cookie; regex, wildcard, exact match, AND/OR |
| FR-004 | Core | Rate Limiting | Sliding window per IP + per user-session; token bucket for burst |
| FR-005 | Core | DDoS Protection | Burst detection + auto block; configurable threshold per tier; fail-close/fail-open per tier |
| FR-006 | Core | Challenge Engine | JS Challenge, Proof-of-Work; adaptive Allow/Challenge/Block by cumulative risk score |
| FR-007 | Core | Relay & Proxy Detection | Proxy chain detection, X-Forwarded-For validation, ASN classification (residential/datacenter/Tor) |
| FR-008 | Core | Whitelist + Blacklist | IP/FQDN whitelist; threat intel blacklist from file; Tor exit list, bad ASN |
| FR-009 | Core | Smart Caching | No cache for CRITICAL; aggressive cache for MEDIUM; configurable TTL per route |
| FR-010 | Core | Device Fingerprinting | TLS fingerprint (JA3/JA4), HTTP/2 settings, User-Agent entropy; detect same device switching IPs |
| FR-011 | Core | Behavioral Anomaly Detection | Bot timing detection, zero-depth sessions, missing Referer, inter-request interval < 50ms |
| FR-012 | Core | Transaction Velocity & Sequence | Cross-endpoint tracking: Login→OTP→Deposit timing; withdrawal velocity; rapid limit-change |
| FR-013 | Detection | SQL Injection | Classic, blind, time-based, UNION-based in URL params, headers, JSON body |
| FR-014 | Detection | XSS | Reflected & stored; script injection in query string, form data, JSON |
| FR-015 | Detection | Path Traversal | ../ sequences, URL-encoded variants, in URL path & query params |
| FR-016 | Detection | SSRF | Requests to internal IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x), metadata endpoints |
| FR-017 | Detection | HTTP Header Injection | Host header injection, CRLF response splitting, X-Forwarded-For spoofing |
| FR-018 | Detection | Brute Force / Credential Stuffing | Per-user failed login counter, password spraying pattern detection |
| FR-019 | Detection | Error Scanning / Recon | Rapid 4xx/5xx patterns, endpoint enumeration, OPTIONS method abuse |
| FR-020 | Detection | Request Body Abuse | Malformed JSON, oversized payload, deeply nested objects, content-type mismatch |
| FR-021 | Rules | Hot-reload rules | Add/edit/delete rules WITHOUT rebuilding binary |
| FR-022 | Rules | Rule format | YAML or TOML; condition + action + risk_score_delta |
| FR-023 | Rules | Rule scoping | Global, per-tier, per-route-pattern, per-IP, per-user-session, per-device-fingerprint |
| FR-024 | Rules | Rule priority | Numeric priority to resolve conflicts when multiple rules match |
| FR-025 | Risk | Cumulative risk scoring | Per {IP + device fingerprint + session}; does not reset per request |
| FR-026 | Risk | Risk score dynamics | Increases on: rule match, failed challenge, anomaly, suspicious ASN, fingerprint conflict. Decreases on: successful challenge, sustained normal behavior |
| FR-027 | Risk | Decision thresholds | Configurable: < 30 = Allow, 30-70 = Challenge, > 70 = Block |
| FR-028 | Risk | Canary / Honeypot | Decoy paths (/admin-test, /api-debug); auto max risk score + block IP on hit |
| FR-029 | Dashboard | Live request feed | Realtime log: request ID, timestamp (ms), risk score, action, triggered rule |
| FR-030 | Dashboard | Attack visualization | Attack type distribution chart, top attacker IPs, endpoint heatmap |
| FR-031 | Dashboard | Hot config | Update rules, toggle actions, adjust thresholds — NO service restart |
| FR-032 | Dashboard | Structured audit log | JSON, append-only, SIEM-ingestible: request_id, ts_ms, ip, device_fp, risk_score, rule_id, action |
| FR-033 | Outbound | Response filtering | Block stack traces, internal IPs, API keys, verbose error messages in responses |
| FR-034 | Outbound | Sensitive field redaction | Mask configurable fields in response JSON (card_number, bank_account, etc.) |
| FR-035 | Outbound | Header leak prevention | Detect and block PII leaks in response headers (X-Debug, X-Internal-*) |
| FR-036 | Resilience | Fail-close (CRITICAL) | Reject all traffic if WAF has internal errors on CRITICAL tier routes |
| FR-037 | Resilience | Fail-open (MEDIUM/CATCH-ALL) | Allow-through if WAF overloaded on non-critical tiers; log warnings |
| FR-038 | Resilience | Configurable fail mode | Fail-close vs fail-open configurable per route tier in rule file |
| FR-039 | Resilience | Circuit breaker | If backend unresponsive, WAF returns 503 instead of hanging |

### 3.2 P1 — Should-Have (BONUS — Extra Points)

| ID | Category | Requirement | Difficulty | Notes |
|----|----------|-------------|------------|-------|
| FR-040 | Security | HTTPS/TLS termination | Medium | TLS termination & mTLS, configurable cipher suites |
| FR-041 | Security | Geographic Restriction | Medium | GeoIP (MaxMind lite DB), block/challenge restricted jurisdictions, detect VPN geo bypass |
| FR-042 | Intelligence | IP Reputation Feed | Low | Tor exit list + bad ASN from file at startup, periodic refresh, auto risk boost |
| FR-043 | Deployment | Multi-region Deployment | High | `waf deploy --region=sg,eu,us`, config sync across regions |
| FR-044 | Deployment | Zero-downtime Config Sync | High | Rolling config update without downtime, config versioning |
| FR-045 | Deployment | Auto Scaling | High | Horizontal scaling on traffic, shared state via Redis/etcd |
| FR-046 | Intelligence | Behavioral ML Scoring | Very High | Lightweight ML model to classify bot vs human from request sequence patterns |

---

## 4. Non-Functional Requirements

| Category | Requirement | Target | Priority |
|----------|-------------|--------|----------|
| Performance | Latency overhead | p99 <= 5ms | P0 |
| Performance | Throughput | >= 5,000 req/s baseline | P0 |
| Performance | Memory footprint | Low — evaluated during scoring | P0 |
| Resilience | Behavior under DDoS | Graceful degradation, not crash | P0 |
| Deployment | Binary format | Single binary, zero runtime deps | P0 |
| Deployment | Startup | `./waf run` — single command | P0 |
| Language | Core WAF | Rust — mandatory, no exceptions | P0 |
| Language | Dashboard | Any language (Node.js, etc.) | Flexible |
| Inspection | Direction | Bidirectional — inbound & outbound | P0 |
| Autonomy | Attack Battle | Fully autonomous — no human intervention | P0 |

---

## 5. Constraints

### Technical Constraints
- **Rust mandatory** for core WAF — no exceptions
- **Single binary** output — no Docker, no runtime dependencies
- **`./waf run`** startup command
- **Full reverse proxy** — all traffic must pass through, not selective
- **Bidirectional inspection** — both requests and responses
- Dashboard/control plane may use any language

### Competition Constraints
- **Team size:** Minimum 3 members, no maximum
- **Duration:** 7 weeks (2 weeks kick-off + 3 weeks dev + 1 week hardening + 1 week Attack Battle)
- **Effective dev time:** ~4 weeks (weeks 3-6)
- **Code freeze:** End of week 6
- **No manual intervention** during Attack Battle
- **No fake data/mocks** — real traffic only
- **No hardcoded rules** for specific test cases

### Competition Disqualifiers
- Fake data or fake demos
- Hardcoded rules to pass specific test cases
- Manual intervention during Attack Battle
- Attacking other teams' sandboxes

---

## 6. Assumptions

1. Organizers provision sandbox environments with a running backend application
2. Backend application has routes matching the tier structure (/login, /otp, /deposit, /withdrawal, /game/*, /api/*, /user/*, /static/*, /assets/*)
3. Teams have access to Rust development environment and build tools
4. Threat intel files (Tor exit list, bad ASN list) will be provided or teams source their own
5. Red Team attack patterns follow the 8 documented attack scenarios
6. Network connectivity allows the WAF to sit between internet and backend
7. Dashboard can be served on a separate port from the proxy

---

## 7. Scoring & Strategy Analysis

### 7.1 Scoring Breakdown

| Criteria | Points | Weight | Priority Focus |
|----------|--------|--------|---------------|
| **Security Effectiveness** | 40 | 33% | **HIGHEST** — OWASP detection + device fingerprinting + behavioral anomaly + canary |
| Performance | 20 | 17% | p99 <= 5ms, >= 5,000 req/s, DDoS resilience |
| Intelligence & Adaptiveness | 20 | 17% | Risk score accuracy, transaction velocity, graceful degradation, fail-close/fail-open |
| Architecture & Code Quality | 15 | 12.5% | Idiomatic Rust, error handling, docs, tests |
| Extensibility | 10 | 8% | Hot-reload rules, per-scope, plugin-ready |
| Dashboard UI/UX | 10 | 8% | Live feed, visualization, hot config, JSON audit log |
| Deployment & Operability | 5 | 4% | Single binary, one-command, circuit breaker |

### 7.2 Win Strategy — Point Maximization

**Tier 1 Focus (60 pts / 50%):** Security Effectiveness + Intelligence
- OWASP Top 5 detection with low false positives → 40 pts
- Risk scoring + transaction velocity + graceful degradation → 20 pts

**Tier 2 Focus (35 pts / 29%):** Performance + Architecture
- Rust performance is inherent advantage; focus on efficient data structures → 20 pts
- Clean module boundaries, idiomatic Rust, test coverage → 15 pts

**Tier 3 Focus (25 pts / 21%):** Extensibility + Dashboard + Deployment
- Hot-reload rules, scoped rules → 10 pts
- Live dashboard with attack viz → 10 pts
- Single binary, circuit breaker → 5 pts

### 7.3 Attack Battle Preparation

Red Team will test 8 attack vectors. Map each to defensive features:

| Attack Vector | Primary Defense | Secondary Defense |
|--------------|----------------|-------------------|
| DDoS L4 & L7 | CF-05 DDoS Protection | FR-036/037 Graceful Degradation |
| Bot Login & Credential Stuffing | CF-04 Rate Limiting + CF-06 Challenge | AD-06 Brute Force Detection |
| Relay & Proxy Attack | CF-05 Relay Detection | CF-06 Blacklist (Tor, bad ASN) |
| Device Fingerprint Evasion | CF-08 Device Fingerprinting | CF-09 Behavioral Anomaly |
| Behavioral Bypass | CF-09 Behavioral Anomaly | FR-025 Cumulative Risk Score |
| Transaction Fraud | CF-10 Transaction Velocity | FR-028 Canary/Honeypot |
| OWASP Injection | AD-01→05 Attack Detection | CF-01 Rule Engine |
| Canary / Recon Scan | FR-028 Canary/Honeypot | AD-07 Error Scanning Detection |

---

## 8. Requirement Summary

| Priority | Count | Categories |
|----------|-------|------------|
| P0 (Mandatory) | 39 | Core Features (12), Attack Detection (8), Rule System (4), Risk Engine (4), Dashboard (4), Outbound Protection (3), Resilience (4) |
| P1 (Bonus) | 7 | HTTPS/TLS, GeoIP, IP Reputation, Multi-region, Config Sync, Auto Scaling, ML Scoring |
| **Total** | **46** | |

### Complexity Assessment

| Dimension | Rating | Justification |
|-----------|--------|---------------|
| Technical complexity | **Very High** | Rust reverse proxy, TLS fingerprinting (JA3/JA4), behavioral analysis, cumulative risk scoring — all in a single binary |
| Security complexity | **Very High** | 8 attack vectors, OWASP Top 5+, device fingerprinting, transaction sequence analysis |
| Performance complexity | **High** | p99 <= 5ms overhead at >= 5,000 req/s while running all detection engines |
| Time pressure | **High** | ~4 effective weeks of development for 39 mandatory features |
| Domain complexity | **High** | WAF/security domain requires deep knowledge of attack patterns, evasion techniques |

---

## 9. Clarification Questions

1. **Backend app specification:** What routes does the target backend application expose? Do they match the tier structure exactly, or will teams discover routes during development?
2. **Threat intel files:** Are Tor exit lists and bad ASN lists provided, or must teams source them?
3. **Sandbox environment specs:** What hardware/OS is provisioned? (CPU cores, RAM, network bandwidth) — affects performance tuning
4. **Red Team dry run:** Is the Week 6 dry run scored, or purely for testing? Can teams adjust after the dry run?
5. **Dashboard deployment:** Can the dashboard run on a separate port/process from the WAF binary? Or must everything be in the single binary?
6. **SSL/TLS during Attack Battle:** Does the backend serve HTTPS, or is traffic HTTP-only between WAF and backend?
7. **State persistence:** Is the WAF expected to survive restarts with state intact (risk scores, blacklist), or can state be ephemeral?
8. **Concurrent Attack Battle:** Are multiple teams attacked simultaneously, or one at a time? This affects if shared infra is a concern.
9. **Scoring false positives:** How are false positives measured during Attack Battle? Is there legitimate traffic mixed with attacks?
10. **IP Reputation Feed (Bonus):** Is it sufficient to load files at startup, or must it support runtime refresh?
