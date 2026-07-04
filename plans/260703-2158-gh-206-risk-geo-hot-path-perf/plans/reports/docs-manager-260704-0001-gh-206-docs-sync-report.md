# Docs Sync Report: GH-206 / GH-199 Hot-Path Performance Work

**Date:** 2026-07-04  
**Scope:** Assess docs impact from perf work (GH-206, GH-199) in `crates/waf-engine`  
**Changes reviewed:** geo.rs, engine.rs, risk store Redis, velocity window  

---

## Assessment Summary

**Changes analyzed:**
1. Geo ISO-code normalization (load-time + parse-time uppercase)
2. Risk store Redis single-Lua-script RTT + LRU fallback cache
3. Risk scoring skip for fast-path exits (guard-disabled, IP/URL whitelist/blacklist)
4. Velocity window alloc removal

**User-visible changes requiring doc updates:**
- ✓ **Geo ISO-code fix only** — lowercase ISO codes (e.g., `"cn"`) in geo rules now enforce correctly (previously silently inert)

**Internal optimizations (no doc impact):**
- Risk store Redis optimization: single RTT, owner convergence MAX-score logic
- Risk scoring skip on fast-path: performance gain, risk_score=0 remains contract-compliant (0-100 range)
- Velocity window: alloc removal, no behavior change

---

## Documentation Changes

### CHANGELOG.md
- **Updated:** [Unreleased] / Fixed section
- **Added:** Geo rule ISO-code fix entry (GH-206 reference)
- **Rationale:** Operators need awareness that lowercase ISO codes now work; existing rules should be audited
- **Note:** Backward-compatible; uppercase codes continue to work

### Other docs reviewed, no updates needed:
- `docs/product/observability-headers.md` — contract still met (risk_score present, 0-100, valid on all decisions)
- `docs/product/audit-log.md` — risk_score field unchanged (0 is valid value)
- `docs/product/decision-classes.md` — no risk scoring assumptions to invalidate
- `docs/product/waf-control-plane.md` — geo capability description unchanged
- No standalone geo rules guide exists (design docs in place, not operator docs)

---

## Risk Assessment

**No breaking changes detected.**  
Risk_score=0 on fast-path requests is contract-compliant:
- Header present on all responses ✓
- Value in 0–100 range ✓
- Reflects state at decision time ✓ (no scoring executed = no score)

Geo fix is strictly additive (loose matching now works; strict matching unchanged).

---

## Unresolved Questions

None. Changes verified against relevant contract docs and codebase.
