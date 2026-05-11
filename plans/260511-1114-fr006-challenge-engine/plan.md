---
title: "FR-006 Challenge Engine"
description: "Production-ready JS Challenge + PoW engine with fingerprint-bound tokens"
status: pending
priority: P1
effort: "5d"
branch: "feat/fr-006-challenge-engine"
tags: [security, challenge, pow, fr-006]
blockedBy: []
blocks: []
created: "2026-05-11T04:23:59.253Z"
createdBy: "ck:plan"
source: skill
---

# FR-006 Challenge Engine

## Overview

Implement production-ready Challenge Engine with JS Proof-of-Work to intercept suspicious traffic (risk score 30-70). Challenges block automated attacks while allowing legitimate users through after solving a brief computational puzzle.

**Design Decisions (Approved):**
- Token Binding: `fingerprint` (IP + JA3/JA4 + H2)
- NoScript Fallback: Block with message
- Challenge Type: JS PoW only (no CAPTCHA)
- Nonce Store: In-memory LRU

**References:**
- Brainstorm: `plans/reports/brainstorm-260511-1114-fr006-challenge-engine.md`
- FR-006 Spec: `analysis/requirements.md` lines 44

## Architecture

```
Request → Scorer (risk=55) → WafAction::Challenge
    │
    ├── Has valid __waf_cc cookie?
    │       │
    │       ├── YES → Verify → Valid → Allow (risk -25)
    │       │
    │       └── NO → Issue token → Render challenge page (429)
    │                     │
    │                     ▼
    │               Browser solves SHA256 PoW
    │                     │
    │                     ▼
    │               Auto-submit → Set cookie → Redirect
    │
    └── Next request: verify cookie → allow
```

## Phases

| Phase | Name | Status | Effort |
|-------|------|--------|--------|
| 1 | [Challenge Page Renderer](./phase-01-challenge-page-renderer.md) | ✅ Complete | 1.5d |
| 2 | [PoW Algorithm](./phase-02-pow-algorithm.md) | ✅ Complete | 1d |
| 3 | [Gateway Handler Integration](./phase-03-gateway-handler-integration.md) | Pending | 0.5d |
| 4 | [Configuration Hot-Reload](./phase-04-configuration-hot-reload.md) | Pending | 0.5d |
| 5 | [Unit and Integration Tests](./phase-05-unit-and-integration-tests.md) | Pending | 1d |
| 6 | [Browser Tests](./phase-06-browser-tests.md) | Pending | 0.5d |

## Key Files

| Type | Path |
|------|------|
| Create | `crates/waf-engine/src/challenge/mod.rs` |
| Create | `crates/waf-engine/src/challenge/renderer.rs` |
| Create | `crates/waf-engine/src/challenge/pow.rs` |
| Create | `crates/waf-engine/src/challenge/page_template.rs` |
| Create | `configs/challenge.yaml` |
| Modify | `crates/gateway/src/proxy_waf_response.rs` (line 62+) |
| Modify | `crates/waf-engine/src/lib.rs` (export module) |
| Modify | `crates/waf-engine/src/risk/config.rs` (extend ChallengeConfig) |

## Dependencies

- Reuses `ChallengeIssuer` / `ChallengeVerifier` from `risk/challenge_credit/`
- Reuses `DeviceIdentity` fingerprint from `device_fp/`
- No new crate dependencies (hmac, sha2, base64 already present)

## Success Criteria

- [x] Challenge page renders in <5KB with inline JS
- [ ] PoW solves in 100ms-750ms based on risk
- [ ] Token binds to fingerprint (IP + JA3/JA4 + H2)
- [ ] Cookie bypass works on subsequent requests
- [x] NoScript shows block message
- [ ] Metrics: challenge_issued, challenge_verified, challenge_failed
- [ ] All tests pass (unit, integration, browser)
