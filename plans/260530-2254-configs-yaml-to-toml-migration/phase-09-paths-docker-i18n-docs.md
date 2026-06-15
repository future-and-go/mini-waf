---
phase: 9
title: "Paths / Docker / i18n / docs"
status: pending
effort: "0.5d"
priority: P2
dependencies: [3, 4, 5, 6, 7, 8]
---

# Phase 9: Paths / Docker / i18n / docs

## Overview

Sweep the non-code references: `configs/default.toml`'s `rate_limit.config_path` line, Docker `COPY` no-op verification, admin-panel display labels, i18n locale strings, CLAUDE.md / README / docs prose. Pure search-and-replace governed by one master grep.

## Requirements

- Functional: `configs/default.toml:105` `config_path = "configs/rate-limit.yaml"` → `.toml`.
- Functional: Admin UI tag in `tx-velocity/index.tsx:272` updated.
- Functional: en/vi locale strings reference `.toml`.
- Functional: All `docs/*.md` references updated.
- Functional: CHANGELOG entry describes the cutover with a `waf migrate-configs` instruction.

## Related Code Files

- Modify: `configs/default.toml` (line 105)
- Modify: `web/admin-panel/src/pages/tx-velocity/index.tsx` (line 272 tag)
- Modify: `web/admin-panel/src/i18n/locales/en.json` (lines 619, 621)
- Modify: `web/admin-panel/src/i18n/locales/vi.json` (lines 714, 716)
- Modify: `docs/codebase-summary.md` (3 references at lines 517, 521, 525)
- Modify: `docs/device-fingerprinting.md` (line 174)
- Modify: `docs/project-overview-pdr.md` (line 252)
- Modify: `docs/PRX-WAF-TechnicalGuide-VI.md` (line 493)
- Modify: `CHANGELOG.md` (add cutover entry; line 48 is historical — leave)
- Verify (no change): `Dockerfile`, `Dockerfile.prebuilt`, `docker-compose*.yml` — these `COPY configs/` whole dir; extension change is transparent.

## Implementation Steps

1. **Master grep (record output in phase report):**
   ```bash
   git grep -nE 'configs/(challenge|ddos|device-fp|rate-limit|relay|risk|tier-policies|tx-velocity)\.ya?ml' \
     -- ':!plans/' ':!CHANGELOG.md' ':!docs/historical/**'
   ```
   Result drives the exact edit list (catches anything missed by Phases 3–8).
2. **Apply edits** one file at a time. For each: open → s/.yaml/.toml/ on the matched lines → confirm no other yaml refs remain in same file (some are legitimate — e.g. `rules.yaml` paths in `default.toml:36`).
3. **Verify Docker build** (no edits expected): `docker build -f Dockerfile.prebuilt -t waf-prebuilt-test . && docker run --rm waf-prebuilt-test ls /app/configs/ | grep -E '\.toml$'`. Expect all migrated files listed as `.toml`.
4. **Update `CHANGELOG.md`:** new section under `## [Unreleased]`:
   ```markdown
   ### Breaking
   - All files under `configs/` are now TOML. YAML loaders removed.
     Operators upgrading from previous releases MUST run `waf migrate-configs --dir configs/ --in-place`
     once, then update any references to `configs/*.yaml` in their `default.toml` (`rate_limit.config_path`).
     User-authored rule files under `rules/` remain YAML — no change.
   ```
5. **Sync `docs/system-architecture.md` + `docs/deployment-guide.md`** if they mention specific config files (grep target).
6. **Rebuild admin panel** to embed updated locale strings:
   ```bash
   cd web/admin-panel && npm run build && cd ../..
   cargo build -p waf-api --release  # picks up rust_embed of dist/
   ```
7. **Smoke test admin UI:** boot `cargo run -- -c configs/default.toml run`, hit `http://localhost:16827/ui/`, open Tx-Velocity page, verify tag reads `configs/tx-velocity.toml`.

## Todo List

- [ ] Master grep run; output saved to phase report
- [ ] `configs/default.toml:105` updated
- [ ] `tx-velocity/index.tsx` tag updated
- [ ] en + vi locale JSON updated
- [ ] All `docs/*.md` references updated
- [ ] CHANGELOG entry added with `waf migrate-configs` instruction
- [ ] `docker build` succeeds with new configs dir
- [ ] Admin panel rebuilt; tag verifies in browser
- [ ] No `configs/*.ya?ml` references remain outside `plans/` + `CHANGELOG.md` history

## Success Criteria

- [ ] `git grep -nE 'configs/(challenge|ddos|device-fp|rate-limit|relay|risk|tier-policies|tx-velocity)\.ya?ml'` returns ZERO matches outside `plans/` and historical `CHANGELOG.md` lines
- [ ] Docker image builds + runs
- [ ] Admin UI displays `.toml` references

## Risk Assessment

- **Risk:** Operator deployments break on upgrade because their `default.toml` still references `configs/rate-limit.yaml`. **Mitigation:** CHANGELOG entry calls this out explicitly; `migrate-configs` tool prints a warning if it sees a `default.toml` with a `.yaml` `config_path`.
- **Risk:** Frontend Build embedding may lag; the React bundle is built into Rust binary via `rust_embed` (per `waf-api` CLAUDE.md). **Mitigation:** Step 6 rebuilds explicitly; CI's `cargo build --release` already runs `web/admin-panel` build via `build.rs`.
