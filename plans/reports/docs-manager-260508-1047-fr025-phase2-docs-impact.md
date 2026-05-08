# FR-025 Phase 2 Documentation Impact Assessment

**Date**: 2026-05-08 10:47  
**Component**: waf-engine risk/seed  
**Assessment**: MAJOR documentation updates required

## Impact Decision
**Status**: MAJOR — 3 docs require updates, 2 are architectural

## Files Requiring Updates

### 1. `docs/system-architecture.md` — CRITICAL
**Why**: Request lifecycle docs FR-025 at Phase 5, but Phase 2 adds pre-phase L0 seed evaluation that runs before phases 1–16.

**Current state**: Mentions risk scoring; lacks seed layer detail.

**Required changes**:
- Insert seed layer before Phase-0 in request lifecycle (line 72)
- Document seed verdict types (Whitelisted, Score{delta, kind}, None)
- Note seed-layer data hot-reload mechanism (ArcSwap)
- Update architecture section to show Tor/ASN/Whitelist tables

**Estimated LOC**: +25 lines in request lifecycle section

### 2. `docs/deployment-guide.md` — CRITICAL
**Why**: Operators must know where to place seed data files and formats.

**Current state**: No mention of seed paths, file formats, or configuration.

**Required changes**:
- Add "Seed Data Files" section under Configuration Reference (after Cache Rules Operator)
- Document three file formats:
  - Tor exits: newline-delimited IPs
  - Whitelist: newline-delimited CIDRs
  - ASN classes: CSV (CIDR,ASN,classification)
- Specify paths: `/etc/prx-waf/` (production) or `configs/seed/` (docker-compose)
- Document `[seed]` TOML section (enabled, *_path, delta values)
- Add troubleshooting: "Seed files not reloading" and "Invalid CIDR format"

**Estimated LOC**: +40 lines

### 3. `docs/project-roadmap.md` — IMPORTANT
**Why**: FR-025 Phase 2 is now complete but not documented in roadmap status.

**Required changes**:
- Add "FR-025 — Cumulative Risk Scoring" section after FR-012 (before Panel-Config)
- Phase 1 status: ✓ Complete
- Phase 2 status: ✓ Complete (L0 Reputation Seed Layer)
- Deliverables: Module location, config file, operator guide reference
- Brief feature summary: whitelist short-circuit, Tor/ASN classification with configurable deltas

**Estimated LOC**: +20 lines

## Files NOT Requiring Updates

- `docs/code-standards.md` — seed module follows existing patterns
- `docs/codebase-summary.md` — already has risk module summary (needs refresh after commit)
- `docs/device-fingerprinting.md` — orthogonal feature

## Data Files Required

Operators must provision (or system auto-creates empty):
- `configs/seed/whitelist.txt` — CIDR per line
- `configs/seed/tor_exits.txt` — IP per line
- `configs/seed/asn_classes.csv` — format: `CIDR,ASN,classification`

## Recommended Priority

1. **First**: Update `system-architecture.md` (foundational)
2. **Second**: Update `deployment-guide.md` (operational necessity)
3. **Third**: Update `project-roadmap.md` (project tracking)

## Token Estimate
- System architecture: 60 tokens (read) + 120 tokens (edit)
- Deployment guide: 80 tokens (read) + 160 tokens (edit)
- Roadmap: 40 tokens (read) + 100 tokens (edit)
- **Total**: ~560 tokens

## Unresolved Questions
- Should seed data files use YAML instead of CSV for ASN classes (for consistency)?
- Should `/etc/prx-waf/` require sudo, or keep in `configs/`?
- Should repomix be re-run to update `codebase-summary.md` before commit?
