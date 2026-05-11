# Brainstorm Report: FR-006 Challenge Engine

**Date:** 2026-05-11
**Status:** Approved for Implementation
**Effort:** 5 days

---

## Problem Statement

WAF needs to challenge suspicious traffic (risk score 30-70) before blocking. Current state:
- ✅ `WafAction::Challenge` enum exists
- ✅ `ChallengeIssuer` / `ChallengeVerifier` token system complete
- ✅ Risk thresholds wired (allow < score < block → Challenge)
- ❌ No challenge page rendering
- ❌ No proxy handler for Challenge action
- ❌ No PoW algorithm implementation

---

## Acceptance Criteria (FR-006)

| Criterion | Metric | Target |
|-----------|--------|--------|
| JS Challenge | Client-side computation | Blocks bots, curl, headless |
| Proof-of-Work | Adjustable difficulty | 100ms-2s solve time |
| Adaptive | Risk-driven decision | Per-tier thresholds |
| Performance | p99 overhead | ≤ 5ms |
| Resilience | Under DDoS | Lightweight page |
| Autonomy | Attack Battle | No human intervention |

---

## Design Decisions

| Setting | Value | Rationale |
|---------|-------|-----------|
| **Token Binding** | `fingerprint` | IP + JA3/JA4 + H2; strongest |
| **NoScript Fallback** | Block with message | Autonomous; no third-party |
| **Challenge Type** | JS PoW only | Attack Battle focus |
| **Nonce Store** | In-memory LRU | Simpler; accept cross-instance replay |

---

## Architecture

```
Request → Scorer (risk=55) → WafAction::Challenge
    │
    ├── Has valid __waf_cc cookie?
    │       │
    │       ├── YES → Verify token → Valid → Allow (-25 risk credit)
    │       │
    │       └── NO → Issue token → Render challenge page
    │                     │
    │                     ▼
    │               Browser solves PoW
    │                     │
    │                     ▼
    │               Auto-submit → Set cookie
    │                     │
    │                     ▼
    │               Redirect to original URL
    │
    └── Next request: cookie present → verify → allow
```

---

## Token Binding

```
fingerprint = hash(client_ip || ja3 || ja4 || h2_fingerprint)
token = hmac_sha256(secret, fingerprint || nonce || expiry)
```

Prevents:
- Token sharing across devices
- IP rotation attacks (fingerprint anchors)
- Headless browser with mismatched TLS stack

---

## PoW Algorithm

**HashCash-style SHA256:**
```
target = sha256(challenge_token || nonce)
difficulty = leading_zero_bits (14-18 based on risk)
nonce = client finds nonce where target < 2^(256-difficulty)
```

| Risk Score | Difficulty | Leading Zeros | Solve Time |
|------------|------------|---------------|------------|
| 30-40 | 14 | ~3.5 hex | ~100ms |
| 40-55 | 16 | 4 hex | ~250ms |
| 55-70 | 18 | 4.5 hex | ~750ms |

---

## Challenge Page Spec

```
Status: 429 Too Many Requests
Content-Type: text/html; charset=utf-8
Cache-Control: no-store, no-cache, must-revalidate
X-Robots-Tag: noindex

Body:
- Minimal HTML (<5KB)
- Inline CSS/JS (no external deps)
- PoW solver in JS
- Auto-submit on solve
- Noscript fallback (block message)
```

---

## Non-Functional Requirements

| Category | Requirement | Target |
|----------|-------------|--------|
| Performance | Challenge decision | ≤ 1ms |
| Performance | Token issue | ≤ 0.5ms |
| Performance | Token verify | ≤ 1ms |
| Scalability | Concurrent tokens | 10,000+ |
| Resilience | Page size | ≤ 5KB |
| Security | Token replay | Single-use nonce |
| Security | Token forgery | HMAC-SHA256 |
| Security | Token expiry | 300s TTL |

---

## Test Strategy

### Unit Tests
- Template renders valid HTML
- Risk→difficulty mapping
- PoW nonce verification
- Token binding verification
- TTL enforcement
- Nonce single-use

### Integration Tests
- Full challenge→solve→verify→allow flow
- Cookie reuse bypasses challenge
- Binding mismatch rejected
- 1000 concurrent challenges

### Browser Tests (Playwright)
- Real browser solves PoW
- NoScript shows block message
- Mobile compatibility (iOS/Android)

### Security Tests
- Token forge rejected
- Replay attack rejected
- Difficulty bypass rejected
- XFF spoofing blocked

---

## Deliverables

| Component | Files | Type |
|-----------|-------|------|
| Challenge Renderer | `challenge/renderer.rs`, `challenge/js_pow.rs` | New |
| Templates | `challenge/templates/js_challenge.html` | New |
| Proxy Handler | `proxy_waf_response.rs` | Modify |
| Config | `challenge.yaml`, `ChallengeConfig` | New |
| Nonce Store | `challenge_credit/nonce_store.rs` | Reuse |
| Tests | `tests/challenge_*.rs` | New |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Cross-instance replay | Medium | Low | Accept; add Redis later |
| Fingerprint drift | Low | Medium | JA3-only fallback |
| Mobile solve time | Medium | Medium | Cap difficulty at 16 |
| Template XSS | Low | High | Askama auto-escape + CSP |

---

## References

- `crates/waf-common/src/types.rs:92-107` — WafAction::Challenge enum
- `crates/waf-engine/src/risk/threshold.rs` — Decision logic
- `crates/waf-engine/src/risk/challenge_credit/` — Token system
- `crates/gateway/src/proxy_waf_response.rs` — Response handler
