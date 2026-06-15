---
title: "§8 WAF Startup & Binary Contract — Interop v2.3 Compliance"
description: "Make the WAF benchmark-compatible per contract v2.3 §8: binary at ./waf, ./waf run startup, ./waf.toml in CWD, health-ready before startup timeout. Renames Cargo bin prx-waf → waf, adds config auto-discovery, generates ./waf.toml at release time."
status: pending
priority: P1
branch: "main"
tags: [interop, contract, benchmark, hackathon, s8-binary-startup-contract]
blockedBy: []
blocks: [260527-1157-waf-interop-v23-critical-compliance]
created: "2026-05-30T15:25:31.019Z"
createdBy: "ck:plan"
source: skill
---

# §8 WAF Startup & Binary Contract — Interop v2.3 Compliance

## Overview

Contract v2.3 §8 mandates a specific startup contract the benchmarker depends on for `startup_failed` vs `ready` classification. We are non-compliant on **every** line (gap report §8, lines 113–124). This plan closes all five:

| Contract line | Current | Target |
|---|---|---|
| Binary at `./waf` | `target/release/prx-waf` | Cargo `[[bin]] name = "waf"` → emits `target/release/waf`; release script copies to `./waf` |
| `./waf run` starts proxy | `prx-waf -c configs/default.toml run` | `./waf run` (no flag) via config auto-discovery |
| `./waf.yaml` or `./waf.toml` in CWD | `configs/default.toml` only | Auto-discovery walks `./waf.toml` → `./configs/default.toml`. TOML-only (YAML out of scope). |
| `./waf_audit.log` after first request | VictoriaLogs HTTP only | **Out of scope** — handled by parent plan `260527-1157` Phase 3 (JSONL writer) |
| Health endpoint ready before startup-timeout | `GET /health` exists on gateway (proxy.rs:607) and admin API (waf-api/server.rs:95) | No code change — verify timing under release build in Phase 4 |

**Source:** `plans/reports/contract-gap-analysis-260527-1133-waf-interop-v23-report.md` §8
**Contract:** `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 504–528
**Supersedes:** `plans/260527-1157-waf-interop-v23-critical-compliance/phase-05-binary-startup-contract-8.md` (parent-plan stub — that file picked wrapper-script approach; this plan picks the higher-blast-radius **rename** approach per explicit user decision)

## Design Decisions (user-confirmed)

1. **Cargo bin rename** (not wrapper, not symlink, not second bin). `[[bin]] name = "prx-waf"` → `"waf"`. Crate name `prx-waf` unchanged (only the output filename changes). Single source of truth for the binary name.
2. **TOML-only** config auto-discovery. No YAML parser, no serde_yaml dependency. Contract allows either format — we pick TOML.
3. **`./waf.toml` generated at release time** by a release script, not symlinked, not committed. Source: `configs/default.toml` + benchmark overrides applied during packaging.

## Architecture Impact

```
Cargo.toml (prx-waf crate)  → [[bin]] name: "prx-waf" → "waf"
crates/prx-waf/src/main.rs  → CLI `default_value` removed; auto-discovery in resolve_config_path()
Dockerfile, Dockerfile.prebuilt, prx-waf.service
.github/workflows/release.yaml      → drop the post-build `install … prx-waf "$STAGE/waf"` rename (binary IS `waf` now)
.github/workflows/deploy-cluster.yml→ s/target/release/prx-waf/target/release/waf/g
.github/workflows/nightly-e2e.yml   → s/prx-waf/waf/g where the binary path is referenced
tests/e2e/* (compose + scripts)     → update binary path references
scripts/release.sh (NEW)            → build → copy ./waf → render ./waf.toml from configs/default.toml + interop overrides
tests/e2e/s8-startup-contract.sh (NEW) → mimic benchmarker startup probe (rooted at CWD)
```

**Crate name vs binary name distinction:** `cargo build -p prx-waf` keeps working (it's the *package* name). What changes is `target/release/prx-waf` → `target/release/waf`. The Cargo workspace member entry stays `crates/prx-waf`. No `Cargo.lock` churn from a workspace-member rename — only one `Cargo.toml` line flips.

## Phases

| Phase | Name | Status | Priority | Effort | Dependencies |
|-------|------|--------|----------|--------|--------------|
| 1 | [Cargo bin rename + reference sweep](./phase-01-cargo-bin-rename-reference-sweep.md) | Pending | P1 | 0.5d | None |
| 2 | [Config auto-discovery in main.rs](./phase-02-config-auto-discovery-in-main-rs.md) | Pending | P1 | 0.5d | Phase 1 |
| 3 | [Release packaging (./waf + ./waf.toml)](./phase-03-release-packaging-waf-waf-toml.md) | Pending | P1 | 0.5d | Phase 1, 2 |
| 4 | [Contract validation E2E](./phase-04-contract-validation-e2e.md) | Pending | P1 | 0.5d | Phase 3 |

**Total estimated effort:** ~2 days

## Dependencies

- **Parent plan `260527-1157-waf-interop-v23-critical-compliance`** owns the `./waf_audit.log` JSONL writer (Phase 3 there). The contract's "Logs: `./waf_audit.log`" line is closed by that work, not this plan. Phase 4 here only verifies the file appears at the expected path once a request is processed.
- **No blocking dependency** on the §2 control plane or §5 observability-header plans; this plan is purely about packaging and startup.

## Non-Goals (out of scope — guard against drift)

- YAML config support (`./waf.yaml`). TOML-only is explicit.
- `./waf_audit.log` file writer (other plan).
- Health endpoint code changes — endpoint exists at `proxy.rs:607` and `waf-api/server.rs:95`; only timing is validated.
- Renaming the `prx-waf` *crate* directory (`crates/prx-waf/`) — only the binary name flips. Crate rename is a much larger refactor with no contract benefit.
- Renaming the `prx-waf` Docker container_name in docker-compose.yml — that's a container label, not a binary path.

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Missed reference to `target/release/prx-waf` in a CI or e2e script → broken pipeline | High | Phase 1 includes exhaustive grep sweep; CI dry-run via workflow_dispatch before merge |
| Dockerfile cache invalidation forces full rebuild | Medium (CI slowdown only) | Acceptable one-time cost; document in commit message |
| `./waf.toml` generated config drifts from `configs/default.toml` | Medium | Phase 3 release script renders deterministically from default.toml + a small overrides table; checked into VCS |
| Renamed binary breaks operator muscle memory (`prx-waf` typed in shells) | Low | CHANGELOG entry; no runtime impact |
| Health endpoint slow under release-mode cold-start exceeds benchmark startup-timeout | Medium | Phase 4 measures cold-start time; if >2 s, profile and tune |
