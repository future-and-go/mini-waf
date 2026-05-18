---
title: "Mini WAF Security Gateway"
description: "Production-ready Rust WAF with 46 features: reverse proxy, tiered protection, attack detection, risk scoring, and autonomous defense"
type: prd
status: ready-for-plan
priority: P0
created: 2026-05-12
tags: [security, waf, rust, hackathon]
source: conversation-synthesis
---

# Mini WAF Security Gateway

## Problem Statement

The Tech Division needs a production-ready Web Application Firewall to protect company systems against real-world threats (bots, fraud, DDoS, relay attacks). Current solutions are either too expensive, lack customization, or cannot be deployed immediately. The WAF must sit transparently in front of websites, inspect all inbound/outbound traffic, and defend autonomously during attacks without human intervention.

## Solution

A single-binary Rust WAF that acts as a full reverse proxy with tiered protection policies, cumulative risk scoring, and 16-phase attack detection. Operators configure rules via YAML/TOML with hot-reload. The system adapts to threats in real-time using device fingerprinting, behavioral anomaly detection, and transaction velocity tracking. A Vue 3 dashboard provides live monitoring and hot configuration. The WAF must survive a 45-minute live attack battle with zero human intervention.

## User Stories

### Core Proxy (FR-001)
1. As a backend service, I want the WAF to proxy all requests transparently, so that I don't need to know the WAF exists.
2. As an operator, I want HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) support, so that modern clients work without degradation.
3. As an operator, I want weighted round-robin load balancing, so that I can distribute traffic across backends.

### Tiered Protection (FR-002)
4. As an operator, I want 4 protection tiers (Critical/High/Medium/CatchAll), so that I can apply distinct policies per route sensitivity.
5. As a security engineer, I want tier-specific DDoS thresholds, so that critical routes have stricter limits.
6. As a security engineer, I want tier-specific fail modes (fail-close vs fail-open), so that critical routes never degrade to allow-all.

### Rule Engine (FR-003, FR-021-024)
7. As an operator, I want to define rules in YAML or TOML, so that I can version-control my security policies.
8. As an operator, I want rules to match by IP, Path, Header, Payload, and Cookie, so that I can target specific attack vectors.
9. As an operator, I want regex, wildcard, and exact match operators, so that I have flexible pattern matching.
10. As an operator, I want AND/OR condition combinators, so that I can express complex rule logic.
11. As an operator, I want to hot-reload rules without restarting the WAF, so that I can respond to incidents in real-time.
12. As an operator, I want numeric rule priority to resolve conflicts, so that I know which rule wins when multiple match.
13. As an operator, I want rule scoping (global, per-tier, per-route, per-IP, per-session, per-device), so that I can apply rules precisely.

### Rate Limiting (FR-004)
14. As a security engineer, I want sliding-window rate limiting per IP, so that I can stop sustained abuse.
15. As a security engineer, I want token-bucket rate limiting for burst protection, so that I can stop sudden floods.
16. As an operator, I want per-user-session rate limiting, so that authenticated abuse is caught even across IPs.
17. As an operator, I want Memory and Redis store backends, so that I can scale horizontally.

### DDoS Protection (FR-005)
18. As a security engineer, I want automatic burst detection, so that I don't need to monitor manually during attacks.
19. As a security engineer, I want configurable thresholds per tier, so that I can tune sensitivity.
20. As a security engineer, I want auto-block with TTL escalation (60s → 5m → 1h), so that repeat offenders get longer bans.
21. As an operator, I want fail-close on CRITICAL tier during WAF errors, so that security is never compromised.
22. As an operator, I want fail-open on MEDIUM/CATCH-ALL during overload, so that availability isn't sacrificed for non-critical routes.
23. As an operator, I want circuit breaker fallback when Redis is down, so that the WAF degrades gracefully.

### Challenge Engine (FR-006)
24. As a security engineer, I want JS Challenge pages, so that I can verify browser capability.
25. As a security engineer, I want Proof-of-Work challenges, so that I can impose computational cost on attackers.
26. As a security engineer, I want risk-based challenge dispatch (Allow/Challenge/Block by score), so that legitimate users aren't annoyed.

### Relay & Proxy Detection (FR-007)
27. As a security engineer, I want ASN classification (residential/datacenter/Tor), so that I can risk-score by network type.
28. As a security engineer, I want proxy chain detection, so that I can identify multi-hop evasion.
29. As a security engineer, I want X-Forwarded-For validation with max-hops, so that I can trust the real client IP.
30. As an operator, I want Tor exit node blocking, so that I can stop anonymous abuse.

### Whitelist & Blacklist (FR-008)
31. As an operator, I want IP whitelist per tier, so that trusted partners bypass checks.
32. As an operator, I want IP blacklist from threat intel files, so that known bad actors are blocked on first request.
33. As an operator, I want FQDN/Host whitelist, so that I can protect specific domains differently.
34. As an operator, I want hot-reload of access lists, so that I can respond to incidents without restart.

### Smart Caching (FR-009)
35. As an operator, I want no-cache for CRITICAL tier, so that sensitive responses are never stored.
36. As an operator, I want aggressive caching for MEDIUM tier, so that static content is fast.
37. As an operator, I want per-route TTL configuration, so that I can tune cache duration.
38. As an operator, I want tag-based cache purge, so that I can invalidate related entries at once.

### Device Fingerprinting (FR-010)
39. As a security engineer, I want TLS fingerprinting (JA3/JA4), so that I can identify clients by their TLS stack.
40. As a security engineer, I want HTTP/2 settings fingerprinting, so that I can detect spoofed User-Agents.
41. As a security engineer, I want User-Agent entropy analysis, so that I can detect low-entropy bot UAs.
42. As a security engineer, I want to detect same device switching IPs, so that I can track evasion attempts.

### Behavioral Anomaly Detection (FR-011)
43. As a security engineer, I want bot timing detection (inter-request interval < 50ms), so that I can catch automated traffic.
44. As a security engineer, I want zero-depth session detection, so that I can catch bots that don't browse.
45. As a security engineer, I want missing Referer detection, so that I can flag direct API abuse.
46. As a security engineer, I want cadence classification, so that I can build behavioral profiles.

### Transaction Velocity & Sequence (FR-012)
47. As a security engineer, I want Login→OTP→Deposit timing analysis, so that I can detect credential stuffing bots.
48. As a security engineer, I want withdrawal velocity limits, so that I can stop rapid fund extraction.
49. As a security engineer, I want limit-change burst detection, so that I can catch account takeover prep.

### SQL Injection Detection (FR-013)
50. As a security engineer, I want classic SQLi detection in URL params, so that I block `' OR 1=1`.
51. As a security engineer, I want blind/time-based SQLi detection, so that I catch advanced probes.
52. As a security engineer, I want UNION-based SQLi detection in headers and JSON body, so that I cover all injection surfaces.

### XSS Detection (FR-014)
53. As a security engineer, I want reflected XSS detection in query strings, so that I block `<script>` payloads.
54. As a security engineer, I want stored XSS detection in form data and JSON, so that I protect databases.
55. As a security engineer, I want iterative JSON walking with depth cap, so that nested payloads don't bypass.

### Path Traversal Detection (FR-015)
56. As a security engineer, I want `../` sequence detection, so that I block directory escape.
57. As a security engineer, I want URL-encoded variant detection (`%2e%2e`), so that encoding bypass fails.
58. As a security engineer, I want recursive URL decoding (up to 3 rounds), so that double-encoding fails.

### SSRF Detection (FR-016)
59. As a security engineer, I want RFC-1918 blocking, so that internal networks aren't reachable.
60. As a security engineer, I want cloud metadata endpoint blocking (169.254.169.254), so that AWS/GCP credentials aren't leaked.
61. As a security engineer, I want obfuscated IP detection (hex, octal, dword), so that IP encoding bypass fails.
62. As an operator, I want outbound host allowlist, so that legitimate internal calls work.

### HTTP Header Injection (FR-017)
63. As a security engineer, I want CRLF injection detection (raw and encoded), so that response splitting fails.
64. As a security engineer, I want Host header whitelist with IPv6 awareness, so that Host injection fails.
65. As a security engineer, I want X-Forwarded-For leftmost-private detection, so that spoofing fails.

### Brute Force / Credential Stuffing (FR-018)
66. As a security engineer, I want per-user failed login counter, so that I detect account targeting.
67. As a security engineer, I want password spraying pattern detection, so that I catch low-and-slow attacks.
68. As a security engineer, I want credential hashing (SHA-256 truncated), so that plaintext never touches state.

### Error Scanning / Recon (FR-019)
69. As a security engineer, I want rapid 4xx/5xx pattern detection, so that I catch endpoint enumeration.
70. As a security engineer, I want OPTIONS method abuse detection, so that I catch CORS probing.
71. As a security engineer, I want per-IP sliding window state, so that distributed scans are caught.

### Request Body Abuse (FR-020)
72. As a security engineer, I want malformed JSON detection, so that parser exploits fail.
73. As a security engineer, I want oversized payload rejection, so that resource exhaustion fails.
74. As a security engineer, I want deeply nested object detection (depth cap 64), so that JSON bombs fail.
75. As a security engineer, I want Content-Type mismatch detection, so that smuggling fails.

### Cumulative Risk Scoring (FR-025-027)
76. As a security engineer, I want risk scores per {IP + device fingerprint + session}, so that identity is tracked holistically.
77. As a security engineer, I want scores that persist across requests, so that gradual attacks accumulate.
78. As a security engineer, I want risk increase on: rule match, failed challenge, anomaly, suspicious ASN, so that bad behavior compounds.
79. As a security engineer, I want risk decrease on: successful challenge, sustained normal behavior, so that false positives recover.
80. As an operator, I want configurable thresholds (< 30 Allow, 30-70 Challenge, > 70 Block), so that I can tune sensitivity.

### Canary / Honeypot (FR-028)
81. As a security engineer, I want decoy paths (/admin-test, /api-debug), so that I detect recon scans.
82. As a security engineer, I want auto max risk score + IP block on honeypot hit, so that attackers are immediately neutralized.

### Dashboard Live Feed (FR-029)
83. As an operator, I want realtime request log with request ID, timestamp, risk score, action, and triggered rule, so that I can monitor live traffic.
84. As an operator, I want WebSocket streaming, so that the feed updates without polling.

### Attack Visualization (FR-030)
85. As an operator, I want attack type distribution chart, so that I can see which attacks are most common.
86. As an operator, I want top attacker IPs list, so that I can identify persistent threats.
87. As an operator, I want endpoint heatmap, so that I can see which routes are targeted.

### Hot Config (FR-031)
88. As an operator, I want to update rules via dashboard, so that I don't need file access.
89. As an operator, I want to toggle actions via dashboard, so that I can respond instantly.
90. As an operator, I want to adjust thresholds via dashboard, so that I can tune sensitivity live.

### Structured Audit Log (FR-032)
91. As a compliance officer, I want JSON audit logs, so that I can ingest into SIEM.
92. As a compliance officer, I want append-only logs, so that tampering is detectable.
93. As a compliance officer, I want fields: request_id, ts_ms, ip, device_fp, risk_score, rule_id, action, so that forensics are complete.

### Response Filtering (FR-033)
94. As a security engineer, I want stack trace redaction in response bodies, so that implementation details aren't leaked.
95. As a security engineer, I want API key/token pattern redaction, so that secrets aren't leaked.
96. As a security engineer, I want internal IP redaction (RFC-1918, loopback), so that network topology isn't leaked.
97. As an operator, I want gzip/deflate decompression before scanning, so that compressed responses are inspected.

### Sensitive Field Redaction (FR-034)
98. As a security engineer, I want PCI field masking (card numbers, CVV), so that payment data isn't logged.
99. As a security engineer, I want banking field masking (account, routing, IBAN), so that financial data isn't leaked.
100. As a security engineer, I want PII field masking (SSN, passport, email, phone), so that identity data is protected.
101. As an operator, I want configurable mask token (`***REDACTED***`), so that I can customize output.

### Header Leak Prevention (FR-035)
102. As a security engineer, I want Server/X-Powered-By stripping, so that technology stack isn't revealed.
103. As a security engineer, I want X-PHP-Version/X-AspNet-Version stripping, so that version info isn't leaked.
104. As a security engineer, I want debug header stripping (X-Debug-*, X-Internal-*), so that internal state isn't exposed.
105. As an operator, I want CDN internal header stripping (X-Varnish, X-Amz-Cf-Id), so that infrastructure isn't revealed.

### Resilience (FR-036-039)
106. As an operator, I want fail-close on CRITICAL tier during WAF errors, so that security is never compromised.
107. As an operator, I want fail-open on non-critical tiers during overload, so that availability is maintained.
108. As an operator, I want configurable fail mode per route tier, so that I can customize behavior.
109. As an operator, I want circuit breaker for backend health, so that the WAF returns 503 instead of hanging.

### HTTPS/TLS Termination (FR-040)
110. As an operator, I want TLS termination with configurable cipher suites, so that I control security posture.
111. As an operator, I want Let's Encrypt automation (ACME v2), so that certificates renew automatically.
112. As an operator, I want mTLS support, so that I can authenticate clients via certificates.

### Geographic Restriction (FR-041)
113. As an operator, I want GeoIP blocking (MaxMind lite DB), so that I can restrict by country.
114. As an operator, I want jurisdiction-based challenge, so that high-risk geos get extra verification.
115. As a security engineer, I want VPN geo bypass detection, so that evasion is flagged.

### IP Reputation Feed (FR-042)
116. As an operator, I want Tor exit list loading at startup, so that Tor nodes are pre-blocked.
117. As an operator, I want bad ASN list loading, so that hosting provider abuse is caught.
118. As an operator, I want periodic refresh, so that lists stay current.
119. As a security engineer, I want auto risk boost for reputation-flagged IPs, so that known bad actors are scrutinized.

### Multi-region Deployment (FR-043)
120. As an operator, I want `waf deploy --region=sg,eu,us`, so that I can deploy globally.
121. As an operator, I want config sync across regions, so that policies are consistent.

### Zero-downtime Config Sync (FR-044)
122. As an operator, I want rolling config update without downtime, so that changes propagate safely.
123. As an operator, I want config versioning, so that I can rollback.

### Auto Scaling (FR-045)
124. As an operator, I want horizontal scaling on traffic, so that capacity grows with demand.
125. As an operator, I want shared state via Redis/etcd, so that nodes stay consistent.

### Behavioral ML Scoring (FR-046)
126. As a security engineer, I want lightweight ML model for bot/human classification, so that detection improves over time.
127. As a security engineer, I want request sequence pattern input, so that temporal behavior is modeled.

## Implementation Decisions

### Module Architecture

**Gateway Core** owns HTTP proxy, protocol handling (HTTP/1.1, HTTP/2, HTTP/3 via quinn), TLS termination (rustls), load balancing, and request/response lifecycle. Exposes `ProxyService` trait. Built on Pingora.

**Tier Classifier** owns route-to-tier mapping, tier policy lookup, and fail-mode dispatch. Exposes `classify(request) → Tier`. Configuration via TOML.

**Rule Engine** owns YAML/TOML parsing, rule indexing, hot-reload via `notify` + SIGHUP, and match evaluation. Exposes `RuleRegistry` with `evaluate(request) → Vec<Match>`. Supports regex (via `regex` crate), wildcard, exact match, AND/OR combinators.

**Rate Limiter** owns token-bucket and sliding-window algorithms, store abstraction (Memory via `DashMap`, Redis via single Lua roundtrip). Exposes `RateLimitCheck::check(key, tier) → Allow/Block`. Circuit breaker falls back to memory on Redis failure.

**DDoS Detector** owns three detector strategies: `PerIpDetector`, `PerFingerPrintDetector`, `PerTierDetector`. Exposes `DdosCheck::detect(request) → Action`. TTL-escalating bans stored in `access::ip_table`. Metrics via `tracing` + Prometheus.

**Challenge Engine** owns JS challenge page rendering, PoW verification (SHA-256 difficulty), challenge token issuance/validation (HMAC-SHA256). Exposes `ChallengeHandler::issue(type) → Challenge` and `verify(token) → bool`.

**Device Fingerprinter** owns TLS ClientHello capture (JA3/JA4 via vendored Pingora fork with inspector hooks), HTTP/2 frame capture, UA entropy calculation, and identity store (Memory or Redis). Exposes `FingerprintProvider::fingerprint(request) → FpKey`.

**Relay Intel** owns ASN classifier (via `ip2region` + `maxminddb`), Tor exit list loader, proxy chain detector, XFF validator. Exposes `RelayProvider::classify(ip) → ReputationSignal`. Hot-reload via `ArcSwap`.

**Access Controller** owns Patricia trie (via `ip_network_table`) for IP whitelist/blacklist, Host gate, deny-wins-over-allow semantics. Exposes `AccessGate::check(ip, host, tier) → Allow/Deny`. Hot-reload via `notify` + `ArcSwap`.

**Attack Detector Suite** owns 8 detection checks (SQLi, XSS, path traversal, SSRF, header injection, brute force, scanner, body abuse). Each check implements `Check` trait with `evaluate(request) → Vec<Detection>`. SQLi/XSS via `libinjectionrs`. Recursive URL decoding (3 rounds). JSON depth cap (64).

**Risk Aggregator** owns cumulative risk scoring per `{IP, FpKey, Session}`, L0 seed layer (reputation), L1 rule deltas, L2 anomaly/velocity signals, challenge credit system. Exposes `RiskAggregator::aggregate(signals) → RiskScore`. Store: Memory with Redis cluster backend. Hot-reload via `ArcSwap`.

**Transaction Velocity** owns per-session `ActorTx` state (16-slot `ArrayVec` ring), sequence timing classifiers (Login→OTP, OTP→Deposit), withdrawal velocity, limit-change burst. Emits `Signal` to Risk Aggregator. Hot-reload via `notify` watcher on `configs/tx-velocity.yaml`.

**Behavioral Anomaly** owns per-actor cadence tracking, zero-depth session detection, inter-request timing, Referer analysis. Emits `AnomalySignal` to Risk Aggregator.

**Canary Honeypot** owns decoy path list, hit detection, auto max-risk + IP block action. Lightweight module.

**Outbound Filter** owns response body decompression (gzip/deflate), stack trace/API key/internal IP scanning (Aho-Corasick + Regex), JSON field redaction (recursive `serde_json::Value` walker), header stripping. Exposes `OutboundFilter::filter(response) → Response`. Per-host configuration.

**Cache Controller** owns moka LRU cache, tier-aware bypass, tag-based purge index, per-route TTL. Exposes `CacheFacade::get/set/purge`. Valkey (Redis fork) for distributed mode.

**Dashboard API** owns REST endpoints under `/api/*`, WebSocket streaming for live feed, JWT + TOTP authentication, Vue 3 admin UI. Axum-based.

**Cluster Manager** owns QUIC mTLS mesh (quinn + rustls + rcgen), Raft-lite election, rule sync (incremental + full snapshot with lz4), attack log aggregation. Exposes `ClusterState` with `join/sync/elect` methods.

### Data Flow

Request pipeline: Gateway Core → Tier Classifier → Access Controller (Phase 0) → [16-phase detection pipeline: Rate Limiter → DDoS Detector → Attack Detector Suite → Transaction Velocity → Behavioral Anomaly → Canary Honeypot → Device Fingerprinter → Relay Intel → Risk Aggregator → Challenge Engine] → Backend.

Response pipeline: Backend → Outbound Filter (decompress → body scan → JSON redact → header strip → recompress) → Cache Controller → Gateway Core → Client.

### Performance Targets

- Latency overhead: p99 ≤ 5ms
- Throughput: ≥ 5,000 req/s baseline
- Memory footprint: optimized via `Cow<str>`, `Arc`, arena allocators
- DDoS resilience: graceful degradation, not crash

### Deployment Model

Single binary (`prx-waf`), zero runtime dependencies. Startup: `./waf run`. Database: PostgreSQL 16+ for persistence. Configuration: TOML + YAML. Dashboard on separate port.

## Testing Decisions

All 18 modules will have tests. Test strategy:

- **Unit tests**: Test public interface of each module in isolation. Mock dependencies via traits.
- **Integration tests**: Test module interactions (e.g., Risk Aggregator consuming signals from Attack Detector Suite).
- **Scenario tests**: Test attack vectors end-to-end (e.g., DDoS scenario, credential stuffing scenario).
- **Property tests**: Use `proptest` for rule engine (arbitrary inputs) and fingerprinter (collision resistance).
- **Soak tests**: Long-running tests for memory leaks and state accumulation.
- **E2E browser tests**: Playwright for Challenge Engine (JS challenge, PoW verification).

Prior art test suites to model after:
- `crates/waf-engine/tests/ddos_scenarios/` — scenario-based detector tests
- `crates/waf-storage/tests/` — PostgreSQL testcontainer integration
- `tests/e2e/browser/` — Playwright browser tests

Coverage target: 80%+ per crate, enforced via CI.

## Out of Scope

- **Layer 4 / TCP-level DDoS**: This WAF operates at Layer 7 only. L4 protection requires upstream (Cloudflare, AWS Shield).
- **WAF-as-a-Service multi-tenancy**: Single-tenant deployment only. No tenant isolation, billing, or quota management.
- **Full ModSecurity compatibility**: Basic subset only (ARGS, REQUEST_HEADERS, REQUEST_URI, REQUEST_BODY). No full SecLang parser.
- **Real-time ML training**: ML scoring uses pre-trained/heuristic models. No online learning during runtime.
- **Mobile SDK**: No client-side SDK. Device fingerprinting uses passive TLS/HTTP inspection only.
- **GraphQL-specific protections**: Focus on REST/JSON. GraphQL depth/complexity limits not implemented.

## Further Notes

### Competition Context
This WAF is built for the Mini WAF Hackathon 2026. Attack Battle is 45 minutes of live attacks with fully autonomous defense (no human intervention allowed). Scoring weights: Security Effectiveness (40%), Performance (20%), Intelligence (20%), Architecture (15%), Extensibility (10%), Dashboard (10%), Deployment (5%).

### Architecture Decision Records
- ADR-001: Pingora over Hyper for reverse proxy (performance, HTTP/3 support)
- ADR-002: libinjectionrs over regex-only SQLi/XSS (lower false positives)
- ADR-003: Cumulative risk scoring over per-request thresholds (gradual attack detection)
- ADR-004: JA3/JA4 via vendored Pingora fork (no upstream support yet)

### Open Questions
1. Should ML scoring (FR-046) use a WASM-sandboxed model or native Rust inference?
2. Should multi-region (FR-043) use anycast or DNS-based routing?
3. Should config sync (FR-044) use Raft consensus or leader-based push?

### Related Documentation
- `analysis/requirements.md` — Source requirements document
- `docs/system-architecture.md` — Current architecture overview
- `docs/ddos-protection.md` — FR-005 operator guide
- `docs/access-lists.md` — FR-008 operator guide
