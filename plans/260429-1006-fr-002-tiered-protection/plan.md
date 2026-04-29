---
title: "FR-002 Tiered Protection — Implementation"
description: "Add 4-tier classification (CRITICAL/HIGH/MEDIUM/CATCH-ALL) with hot-reloadable per-tier policy registry. Strategy + Registry pattern + ArcSwap. Foundation for FR-005/006/009/027."
status: in-progress
priority: P0
effort: 3d
branch: main
tags: [waf, gateway, fr-002, tiered-protection, hot-reload]
created: 2026-04-29
blockedBy: []
blocks: []
---

## Source
Design doc (locked decisions D1–D5, AC mapping, schema): [`../reports/brainstorm-260429-1006-fr-002-tiered-protection-design.md`](../reports/brainstorm-260429-1006-fr-002-tiered-protection-design.md)

Build-order context: [`../reports/brainstorm-260429-0954-fr-001-012-build-order.md`](../reports/brainstorm-260429-0954-fr-001-012-build-order.md)

## Scope
Implement FR-002 acceptance criteria:
- 4 tiers: CRITICAL, HIGH, MEDIUM, CATCH-ALL
- Distinct policy per tier (fail_mode, ddos_threshold, cache_policy, risk_thresholds)
- Request → tier classification (path/host/method/header)
- Hot-reload via ArcSwap (no restart on config change)
- Public API consumed by future FR-005, FR-006, FR-009, FR-027

**Non-goals:** Per-tier enforcement of DDoS/cache/challenge (those are downstream FRs). FR-002 ships the *bus*, not the consumers.

## Phases

| # | Phase | Status | Effort | File |
|---|-------|--------|--------|------|
| 1 | Types + TOML schema | complete | 0.5d | [phase-01-types-schema.md](phase-01-types-schema.md) |
| 2 | Tier classifier | complete | 0.75d | [phase-02-classifier.md](phase-02-classifier.md) |
| 3 | Policy registry + ArcSwap | complete | 0.5d | [phase-03-registry.md](phase-03-registry.md) |
| 4 | Config watcher (hot-reload) | complete | 0.5d | [phase-04-watcher.md](phase-04-watcher.md) |
| 5 | Wire into ctx_builder | complete | 0.25d | [phase-05-wire-in.md](phase-05-wire-in.md) |
| 6 | Tests + bench + docs | pending | 0.5d | [phase-06-tests-docs.md](phase-06-tests-docs.md) |

## Key Dependencies
- **FR-001** (reverse proxy) ✅ merged — `RequestCtx` & `ctx_builder` finalized.
- **arc-swap** crate ✅ in workspace.
- **notify** crate ✅ (reused from rules hot-reload).
- **regex** crate ✅ in workspace.

## Cross-Plan Status
- **Phases 1-5 COMPLETE** (3.75d delivered, 25min ahead of plan).
- **Phase 6 (tests/bench/docs) PENDING** — final gate before FR-005/006/009/027 can start.
- **Blocks:** FR-005/006/009/027 (when Phase 6 ships).

## Success Criteria
- All 4 tiers classifiable from TOML config.
- `cargo test -p waf-common -p gateway` green.
- `cargo clippy --workspace --all-targets -- -D warnings` clean.
- Hot-reload integration test passes (edit file → next request sees new policy, no restart).
- Bench: classifier hot-path < 50µs for 50-rule config.
- Downstream-consumer doc published in `docs/`.

## Docs Impact
- New: `docs/tiered-protection.md` (consumer guide for FR-005/006/009/027).
- Update: `docs/system-architecture.md` (add Tier flow).
- Update: `docs/code-standards.md` only if a new pattern lands (no — Strategy+Registry already documented).
