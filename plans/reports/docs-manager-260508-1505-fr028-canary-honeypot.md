# FR-028 Canary Honeypot Implementation — Documentation Impact Assessment

## Assessment Summary

**Docs impact: minor**

Existing `docs/system-architecture.md` already covers the FR-025 risk scoring subsystem in detail (L0 seed layer, L1 accumulation, L2 anomaly/velocity detectors, decay, threshold gating). FR-028 canary honeypot layer is a new **companion feature to FR-025** that slots into the same risk subsystem; addition requires brief mention in the architecture doc and a dedicated configuration section in deployment guide, but no structural redesign.

---

## Current Documentation Coverage

### system-architecture.md (1046 LOC)
- **§ WafEngine → Risk Scorer (FR-025)** extensively covers risk pipeline architecture
- Describes L0 seed layer (Tor/ASN/whitelist) evaluated before other layers
- Describes L1 accumulation (triple-index RiskKey), L2 anomalies (JA4↔UA, XFF, headers), L2 velocity (sliding window, sequence FSM)
- Covers decay mechanism, threshold gating, hot-reload semantics
- **Gap:** No mention of canary layer or FR-028

### deployment-guide.md (941 LOC)
- **§ Configuration Files** covers `configs/seed/` directory with Tor/ASN/whitelist files
- **§ Configuration Reference** mentions risk whitelist file format
- **Gap:** No canary configuration section (paths, ban_ttl_secs)

### Other docs
- `tiered-protection.md` — covers per-tier risk thresholds, not applicable to canary layer
- No dedicated risk subsystem guide exists

---

## Implementation Scope (FR-028)

Added canary honeypot layer to risk module:
- **CanaryLayer struct** (258 LOC) — evaluates request path against exact-match path list
- **Config:** `configs/risk.yaml` now includes `[canary]` section with `enabled`, `paths`, `ban_ttl_secs`
- **Behavior:** Exact-match trigger → score pinned to 100 → IP added to DynamicBanTable (FR-005) → Block decision (bypasses threshold gate)
- **Evaluated:** AFTER seed whitelist, BEFORE all other layers (Phase 0 context)
- **Hot-reload:** Via ArcSwap, consistent with existing FR-025 reload pattern

---

## Required Documentation Updates

### 1. system-architecture.md
**Location:** § WafEngine → Risk Scorer (FR-025), subsection after L2 Velocity Layer

**Add:** 2–3 sentence mention of canary layer in the risk scoring flow:
- "Canary honeypot layer (FR-028): Detects scanner payloads via exact-match path patterns (e.g., `/admin-test`, `/.git/config`, `/wp-admin/install.php`). Canary hits trigger score pin to 100 and immediate dynamic ban via DynamicBanTable (FR-005), bypassing threshold gate. Configurable via `configs/risk.yaml` `[canary]` section (enabled, paths, ban_ttl_secs)."

**Diagram update:** Extend risk flow diagram to show canary evaluation point:
```
Seed Layer (Tor/ASN/Whitelist) ──┐
Canary Layer (Honeypot paths)    ├──► Scorer::score(...)
L1 Accumulation (IP/FP/Session) ─┤
L2 Anomaly (JA4, XFF, headers) ──┤
L2 Velocity (sliding window)     ─┘
```

### 2. deployment-guide.md
**Location:** § Configuration Files → Add new subsection after risk-whitelist.txt section

**Add:** New "Canary Honeypot Paths" subsection:
```
| `configs/risk.yaml` | YAML config | `[canary]` enabled, paths, ban_ttl_secs | Hotstart admin UI path editor |
```

**Quick reference example:**
```yaml
[risk.canary]
enabled = true
paths = [
  "/admin-test",
  "/.git/config",
  "/wp-admin/install.php"
]
ban_ttl_secs = 3600
```

### 3. codebase-summary.md (if it covers risk module)
**Check:** Verify if existing FR-025 entry needs FR-028 addition
**Action:** Append "(+ FR-028 canary honeypot layer)" to FR-025 entry if regenerated

---

## Estimated Effort

- **system-architecture.md:** +15 LOC (2 subsections, 1 diagram update)
- **deployment-guide.md:** +20 LOC (new subsection + example)
- **codebase-summary.md:** 0 LOC (auto-generated, no manual edit)

**Total:** ~35 LOC added across 2 files. Both remain under the 800 LOC limit.

---

## Unresolved Questions

None — feature is self-contained and well-integrated with existing FR-025 risk subsystem architecture.
