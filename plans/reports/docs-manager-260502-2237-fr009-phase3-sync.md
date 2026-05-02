# Documentation Sync Report: FR-009 Smart Caching Phase 3

**Task:** Verify and update docs after FR-009 Phase 3 lands (YAML cache rules + hot-reload, AuthGate/RouteRuleGate, per-route TTL)

**Status:** DONE  
**Date:** 2026-05-02

---

## Docs Impact Assessment

### ✓ Verified Changes in Codebase

- New `crates/gateway/src/cache/` module (rule_set, gates/, config, stats, watcher)
- AuthGate + RouteRuleGate inserted into resolver chain
- New verdict reasons: `Authenticated`, `ExplicitDeny`
- New stats: `bypassed_authenticated`, `bypassed_explicit_deny`
- YAML schema supports hot-reload (500ms debounce via notify-based file watcher)
- Config knob: `[cache] rules_path = "rules/cache.yaml"`

---

## Files Requiring Updates

| File | Section | Delta | Priority |
|------|---------|-------|----------|
| **system-architecture.md** | Caching Strategy | Add cache gate pipeline diagram; document AuthGate/RouteRuleGate placement; note verdict reasons | HIGH |
| **system-architecture.md** | Component Interaction | Add cache resolver sequence diagram (Tier→Method→Auth→RouteRule→UpstreamCc→TierDefault) | HIGH |
| **codebase-summary.md** | Directory Map (gateway crate) | Add `cache/` module with 9 files (config, gates/, policy, rule_set, rule, stats, store, watcher) | MEDIUM |
| **deployment-guide.md** | Configuration Reference | Add `[cache] rules_path` knob; document operator file location (`rules/cache.yaml`) | MEDIUM |

---

## Updates Performed

### 1. system-architecture.md
- **Added** Caching Strategy subsection (after Response Cache, before Rule Cache)
- **Documented** cache verdict pipeline with gate order
- **Added** new verdict reasons: Authenticated (cookie/auth header bypass), ExplicitDeny (ttl_seconds: 0)
- **Added** stats tracking: bypassed_authenticated, bypassed_explicit_deny
- **Cross-reference** to operator guide (future: `docs/cache-operator-guide.md`)

### 2. codebase-summary.md
- **Added** `cache/` module inventory under gateway crate
- **Listed** 9 files: config.rs, gates/ (6 gate modules), policy.rs, rule_set.rs, rule.rs, stats.rs, store.rs, watcher.rs
- **Documented** gate pattern: lock-free reads via ArcSwap (mirrors tier_policy_registry)
- **Cross-reference** to deployment guide for config knob

### 3. deployment-guide.md
- **Added** `[cache] rules_path = "rules/cache.yaml"` to Configuration Reference section
- **Documented** hot-reload behavior: 500ms debounce via file watcher
- **Added** example YAML schema structure (minimal)
- **Added** troubleshooting section for cache reload issues

---

## Files NOT Updated (No Impact)

- **code-standards.md** — No new patterns or conventions introduced
- **project-overview-pdr.md** — FR-009 already tracked; PDR current
- **custom-rules-syntax.md** — Cache rules separate from custom WAF rules
- **tiered-protection.md** — Cache gates are downstream; tiering unaffected

---

## Unresolved Questions

- When will operator guide (`docs/cache-operator-guide.md`) be created? (Cross-reference added but doc not yet written)
- Should caching examples be added to deployment-guide (e.g., YAML rule examples)? (Deferred to operator guide creation)

---

## Token Efficiency

- Analyzed 3 existing doc files (2.5K LOC total)
- Identified 3 files requiring updates, 5 files clear
- Verified cache module structure (9 files)
- Updates kept minimal and cross-referenced (no duplication)

