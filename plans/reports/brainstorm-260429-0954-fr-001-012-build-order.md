# Brainstorm Report — FR-001 to FR-012 Build Order

**Date:** 2026-04-29
**Source:** `analysis/requirements.md` (WAF Mini Hackathon 2026)
**Scope:** Conflict-free priority order for the first 12 P0 must-have features
**Method:** Acceptance-criteria dependency analysis → topological sort

---

## 1. Problem Statement

Hackathon spec lists 12 core P0 features (FR-001..FR-012). Building them in catalog order produces AC contradictions: later-numbered features provide capabilities earlier-numbered features depend on. Need a build order where each feature's AC is fully testable using only previously-built features.

---

## 2. Dependency Map

| FR | Feature | Hard Prerequisites | AC-driven Reason |
|----|---------|--------------------|------------------|
| FR-001 | Reverse proxy | — | Foundation; all traffic flow |
| FR-002 | Tiered protection | FR-001 | Tier classifier requires request object |
| FR-003 | Rule engine | FR-001 | Matches request fields |
| FR-008 | Whitelist/Blacklist | FR-003 | "From file" + Tor/ASN — implemented as rules |
| FR-007 | Relay/Proxy detection | FR-001, FR-003 | Emits signals (proxy chain, ASN class) |
| FR-010 | Device fingerprinting | FR-001 (TLS hook) | JA3/JA4 captured at handshake |
| FR-004 | Rate limiting | FR-001, FR-010 | AC: "per IP + per user-session" needs stable session ID |
| FR-005 | DDoS protection | FR-002, FR-004 | AC: "threshold per tier", "fail-mode per tier" |
| FR-009 | Smart caching | FR-002 | AC: "no cache CRITICAL, aggressive MEDIUM" — per-tier policy |
| FR-011 | Behavioral anomaly | FR-010 | AC: "zero-depth", "inter-request interval" — needs identity tracking |
| FR-012 | Transaction velocity | FR-010, FR-011 | AC: "Login→OTP→Deposit" — cross-request sequence |
| FR-006 | Challenge engine | FR-007, FR-010, FR-011, risk score | AC: "adaptive by cumulative risk score" |

---

## 3. Recommended Build Order

```
Phase 1 — Foundation
  1. FR-001  Reverse proxy
  2. FR-002  Tier classifier
  3. FR-003  Rule engine

Phase 2 — Cheap signals & short-circuits
  4. FR-008  Whitelist/Blacklist
  5. FR-007  Relay/Proxy detection
  6. FR-010  Device fingerprinting

Phase 3 — Stateful per-identity controls
  7. FR-004  Rate limiting
  8. FR-009  Smart caching

Phase 4 — Behavioral / cross-request
  9.  FR-011  Behavioral anomaly
  10. FR-012  Transaction velocity
  11. FR-005  DDoS protection

Phase 5 — Adaptive response
  12. FR-006  Challenge engine
```

Spine features (unlock everything else): **FR-001, FR-002, FR-010**.

---

## 4. AC Conflicts If Built in FR-Number Order

1. **FR-006 before FR-007/010/011** — challenge engine AC requires cumulative risk score; signal sources don't exist yet. Either fake score (disqualifier per "no hardcoded rules") or refactor.
2. **FR-005 before FR-002** — per-tier threshold + per-tier fail mode unimplementable without tiers.
3. **FR-004 "per user-session" before FR-010** — session ID requires fingerprint or WAF-issued cookie.
4. **FR-009 before FR-002** — per-tier cache policy meaningless without tier classification.
5. **FR-012 before FR-010+FR-011** — sequence tracking requires actor identity + timing infra.
6. **FR-008 placement (non-blocker, perf insight)** — wire as first pipeline check for early short-circuit even though listed mid-order.

---

## 5. Architectural Decisions Needed Early

- **Capture JA3/JA4 during FR-001** (TLS layer hook). Bolting on later forces proxy refactor.
- **Risk-score accumulator stub in Phase 2.** FR-006 hard-depends on FR-025; build the store when first signals (FR-007, FR-010) come online.
- **Tier-policy schema in FR-002.** Includes fail-open/fail-close mode (consumed by FR-005) and cache TTL (consumed by FR-009).
- **Session ID source decision before FR-004.** Pick: device fingerprint hash, WAF-issued cookie, or composite. Affects FR-010, FR-011, FR-012.

---

## 6. Pitfalls

- Building by FR-number is wrong; FR numbers are catalog IDs, not build order.
- Skipping risk-score scaffolding leaves FR-006 unbuildable.
- Treating fingerprinting as "later" forces TLS-layer refactor.
- Forgetting fail-mode-per-tier schema in FR-002 causes FR-005 rework.

---

## 7. Success Criteria

- Each feature's AC fully satisfied using only previously-built features.
- No retroactive refactor of FR-001 TLS pipeline.
- Risk score has signal feeders before FR-006 starts.
- All 12 features pass independent AC validation in isolation.

---

## 8. Unresolved Questions

1. Risk engine (FR-025..028) ordering — out of scope here but FR-006 hard-depends. Extend?
2. Hackathon build is fresh or gap-fill on existing v0.2.0 codebase? Affects whether to skip already-implemented features.
3. Tier definition source — config-declared route patterns or inferred? Affects FR-002 design.
4. Session ID strategy — fingerprint hash vs WAF cookie vs composite?
