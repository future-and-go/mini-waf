# Request Pipeline Step-by-Step Guide

A beginner-friendly walkthrough of how HTTP requests flow through the WAF. For detailed technical specifications, see [request-pipeline.md](./request-pipeline.md).

---

## Context

When a client (browser, mobile app, bot) sends an HTTP request to your server, it doesn't just go straight through. A **Web Application Firewall (WAF)** sits in between and acts like a security guard — inspecting every request before deciding whether to let it through or block it.

This WAF project uses a **multi-phase pipeline** architecture where each phase performs a specific security check. Think of it like an airport security checkpoint with multiple screening stations.

---

## Overview Flow

```
Client Request → Pre-Phases → Phase 0 (Access Gate) → Phases 1-18 (Security Checks) → Decision → Backend or Block
```

---

## Pre-Phase 1: Relay & Proxy Detection (FR-007)

**What happens:** Figures out who the REAL client is.

```
Client → [Load Balancer] → [CDN] → [WAF]
                                     │
                                     └─ "Wait, who's actually making this request?"
```

**Why this matters:** When requests come through proxies, the TCP connection shows the proxy's IP, not the client's. This phase:
1. Parses the `X-Forwarded-For` header (chain of IPs the request passed through)
2. Detects spoofing attempts (fake IPs in the header)
3. Classifies the IP source (residential ISP, datacenter, Tor exit node)
4. Emits signals like `TorExit`, `XffSpoofPrivate`, `AsnDatacenter`

**Output:** `ClientIdentity` containing the real IP and classification signals.

---

## Pre-Phase 2: Tier Classification (FR-002)

**What happens:** Categorizes the request by importance.

```
Request Parts (host, path, etc.)
       │
       ▼
TierPolicyRegistry.classify()
       │
       ▼
Returns: (Tier, TierPolicy)
  • Critical   ← Payment endpoints, admin panels
  • High       ← User authentication
  • Medium     ← Regular API calls
  • CatchAll   ← Everything else
```

**Why this matters:** Different endpoints need different protection levels. A `/admin` endpoint gets stricter rate limits than a `/public/images` endpoint.

---

## Phase 0: Access Gate (FR-008)

**What happens:** First line of defense — quick allow/block decisions.

```
Order of checks:
1. Host Gate    → Is this host even protected?
2. IP Blacklist → Is this IP explicitly banned?
3. IP Whitelist → Is this IP pre-approved? (per-tier: full bypass vs blacklist-only)
4. URL Whitelist → Is this URL path always allowed?
5. URL Blacklist → Is this URL path always blocked?
```

**Why blacklist before whitelist?** A common mistake is checking whitelist first. If an attacker's IP happens to be on both lists (leaked whitelist entry), checking blacklist first ensures explicit blocks win.

**Short-circuit behavior:** If blocked here, request never reaches the expensive detection phases.

---

## Phases 1-4: IP & URL Filtering (Fast Path)

These run the same checks as Phase-0 but in the structured phase system:

| Phase | Check | If Match | If No Match |
|-------|-------|----------|-------------|
| 1 | IP Whitelist (CIDR) | Continue (whitelist is permissive) | Continue |
| 2 | IP Blacklist (CIDR) | **BLOCK 403** | Continue |
| 3 | URL Whitelist | **BYPASS all remaining phases** | Continue |
| 4 | URL Blocklist | **BLOCK 403** | Continue |

**Common Pitfall:** URL whitelist (Phase 3) bypasses EVERYTHING including SQLi detection. Only whitelist URLs you're absolutely certain are safe (static assets, health checks).

---

## Phase 16a, 17, 18: Early-Path Reputation Checks

Before expensive detection, check reputation databases:

```
Phase 16a: CrowdSec Bouncer
├─ Local cache lookup (no network latency)
└─ Known-bad IP? → BLOCK

Phase 17: GeoIP Access Control
├─ Lookup country from IP (MaxMind/IP2region)
└─ Country blocked per tier policy? → BLOCK

Phase 18: Community Blocklist
├─ O(1) lookup against shared threat intel
└─ IP in community blocklist? → BLOCK
```

**Why early?** Blocking known-bad traffic before rate-limit phase saves resources.

---

## Phase 19: DDoS Detection (FR-005)

**What happens:** Detects flood attacks through multiple sliding-window detectors.

```
Three parallel detectors:
├─ PerIpDetector       → requests/sec per IP
├─ PerFingerprintDetector → requests/sec per device fingerprint (catches botnets)
└─ PerTierDetector     → tier-wide burst detection

On trigger:
├─ Add IP to ban table (60s TTL)
└─ Subsequent requests short-circuit → 403 DDOS-BAN
```

**Why fingerprint detection?** Sophisticated botnets rotate IPs but share device fingerprints. A single IP might look normal, but when you group by fingerprint, the flood becomes visible.

---

## Phase 5: Rate Limiting (FR-004)

**What happens:** Token-bucket + sliding-window rate limiting.

```
Two keys checked:
1. ip:<host>:<client_ip>     → IP-based limit
2. sess:<host>:<session_id>  → Session-based limit

If either fails → 429 Too Many Requests
```

**Algorithm:** Token bucket allows bursts (sudden legitimate traffic), sliding window limits sustained abuse.

---

## Phase 5.5: Transaction Velocity (FR-012)

**What happens:** Detects suspicious transaction sequences.

```
Classifiers:
├─ SequenceTimingClassifier → Login → OTP → Deposit too fast?
├─ WithdrawalVelocityClassifier → N withdrawals in X seconds?
└─ LimitChangeBurstClassifier → Rapid limit changes?

Output: SIGNALS (never blocks directly)
└─ Signals feed into risk scoring
```

**Why signals, not blocks?** One fast sequence might be legitimate (power user). The risk scorer accumulates multiple signals before deciding.

---

## Phases 6-14: Attack Detection Pipeline

First match blocks — ordered from common to rare attacks:

| Phase | Detector | What It Catches |
|-------|----------|-----------------|
| 6 | Scanner Detection | Nmap, Nikto, automated recon tools |
| 7 | Bot Detection | Headless browsers, known bot signatures |
| 8 | XSS Detection | `<script>`, event handlers, JS payloads |
| 9 | RCE Detection | Shell injection (`; rm -rf`), template injection |
| 10 | Directory Traversal | `../../../etc/passwd`, Windows ADS |
| 11 | SSRF Detection | Internal IPs in URLs (`http://169.254.169.254`) |
| 12 | Header Injection | CRLF (`\r\n`), Host header manipulation |
| 13 | Brute Force | Failed logins per user, password spray |
| 14 | Body Abuse | Oversized bodies, JSON bombs |

**Then:** SQL injection check (hot-reloadable, uses libinjection + regex patterns)

---

## Post-Detection: Custom Rules & Integrations

```
Phase 16b: CrowdSec AppSec (async HTTP check)
     │
     ▼
Custom Rules Engine (Rhai scripts + JSON DSL)
     │
     ▼
OWASP CRS (24 pre-compiled rules)
     │
     ▼
Sensitive Data Detection (credit cards, SSN, API keys in request)
     │
     ▼
Anti-Hotlink (Referer header validation)
```

---

## Risk Scoring (FR-025)

Throughout the pipeline, signals accumulate into a **risk score (0-100)**:

```
Sources:
├─ L0 Seed: Tor exit (+30), datacenter IP (+10)
├─ L1 Accumulation: per-actor state machine
├─ L2 Anomaly: JA4↔UA mismatch (+20), XFF issues (+10)
├─ L2 Velocity: burst detection (+25), sequence anomaly (+30)

Thresholds:
├─ score < 30  → Allow
├─ 30-60       → Challenge (CAPTCHA)
└─ score > 60  → Block
```

---

## Final Decision

```
Decision = Allow
├─ Route to backend server
├─ Cache response if eligible (FR-009)
└─ Return response to client

Decision = Block
├─ Return 403 Forbidden (or 429)
├─ Log to security_events table
├─ Report to community blocklist
└─ Increment security metrics

Decision = Challenge
├─ Return CAPTCHA/JS proof-of-work
└─ Wait for client to solve
```

---

## Visual Summary

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│                    PRE-PHASES                                │
│  ┌─────────────────┐  ┌─────────────────┐                   │
│  │ Relay Detection │→→│ Tier Classify   │                   │
│  │ (Real IP, ASN)  │  │ (Critical/High) │                   │
│  └─────────────────┘  └─────────────────┘                   │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 0: ACCESS GATE                      │
│  IP Blacklist → IP Whitelist → URL Allow → URL Block         │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                 REPUTATION CHECKS (16a, 17, 18)              │
│  CrowdSec Cache → GeoIP → Community Blocklist                │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 19: DDoS DETECTION                  │
│  Per-IP / Per-Fingerprint / Per-Tier sliding windows         │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 5: RATE LIMITING                    │
│  Token-bucket + Sliding-window per IP/Session                │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                PHASES 6-14: ATTACK DETECTION                 │
│  Scanner → Bot → XSS → RCE → Traversal → SSRF → Headers →   │
│  Brute Force → Body Abuse → SQLi                             │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                 POST-DETECTION RULES                         │
│  CrowdSec AppSec → Custom Rules → OWASP CRS → Sensitive →   │
│  Anti-Hotlink                                                │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                    RISK SCORING (FR-025)                     │
│  Accumulate signals → Apply decay → Threshold gate           │
│  0-30: Allow | 30-60: Challenge | 60+: Block                 │
└────────────────────────────┬────────────────────────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
         ┌────────┐    ┌──────────┐   ┌─────────┐
         │ ALLOW  │    │CHALLENGE │   │  BLOCK  │
         └───┬────┘    └────┬─────┘   └────┬────┘
             │              │              │
             ▼              ▼              ▼
         Backend       CAPTCHA/POW     403/429
```

---

## Common Pitfalls

1. **Whitelisting too broadly** — URL whitelist bypasses ALL security checks. Only use for truly static, safe paths.

2. **Forgetting tier configuration** — Without tiers, everything falls to `CatchAll` with permissive defaults.

3. **Blocking legitimate proxies** — If your app is behind Cloudflare/AWS ALB, configure `trusted_proxy_cidrs` or you'll block real users.

4. **Ignoring rate-limit fail-mode** — When Redis is down, should you block (safe) or allow (available)? Depends on your tier policy.

5. **Relying only on IP-based detection** — Botnets rotate IPs. Fingerprint-based detection (FR-010) catches what IP-based misses.

---

## Key Takeaways

- **Pipeline is ordered for efficiency** — Cheap checks (IP lookup, reputation) run before expensive checks (regex matching, payload analysis)
- **Short-circuit design** — Early blocks save CPU; URL whitelist bypasses everything
- **Signals vs. immediate blocks** — Many detectors emit signals that accumulate into risk scores, allowing nuanced decisions
- **Tiers customize protection** — Critical endpoints get strict limits; public content gets lenient treatment
- **Hot-reload everywhere** — Rules, configs, and threat intel update without restarts via `ArcSwap` atomic swaps

---

## Related Documentation

- [request-pipeline.md](./request-pipeline.md) — Full technical specification with config examples
- [tiered-protection.md](./tiered-protection.md) — How to configure tier policies
- [system-architecture.md](./system-architecture.md) — Component interactions and data flow
