---
phase: 3
title: Update durable proof
status: completed
priority: P2
effort: 30m
dependencies:
  - 1
  - 2
---

# Phase 3: Update durable proof

## Overview

Record durable proof booleans for the three stories and flip their status to done,
reflecting what Phases 1–2 verified. Per each story's Validation section, proof is
set with numeric booleans via `harness-cli story update`.

## Requirements

- Functional: each story's `--unit/--integration/--e2e/--platform` booleans reflect
  reality (claim only what is actually proven; do not over-claim platform/e2e).
- Non-functional: follow the review-audit-self-decision rule — proof claims are sticky
  and source-noted; don't mark a layer `1` without a test or check behind it.

## Architecture

Proof mapping (conservative — only set `1` where a test/check exists):

| Story | unit | integration | e2e | platform | Backing evidence |
| --- | --- | --- | --- | --- | --- |
| US-1601 | 1 | 0 | 0 | 0 | `resolve_config_path_tests` (CLI run parse + listener-config resolve) |
| US-1602 | 1 | 0 | 0 | 0 | `config_loader` YAML/TOML parity + `resolve_config_path_tests` cwd discovery |
| US-1603 | 1 | 1 | 0 | 0 | `handler_health` (200 when ready) + `audit_file_sink_integration` (lazy `./waf_audit.log` on first event) |

> Integration for US-1601/1602 (full `./waf run` boot bound to configured port) and
> all platform rows depend on a live Postgres + a benchmark harness not available in
> this environment; leave them `0` rather than over-claim. If a later run executes the
> smoke + audit-on-first-request platform check, update then.

## Related Code Files

- None (durable-state mutation only).

## Implementation Steps

1. Confirm exact story IDs the harness expects:
   `scripts/bin/harness-cli query stories` (or `--epic E16`).
2. For each story, run e.g.:
   `scripts/bin/harness-cli story update --id US-1601 --unit 1 --integration 0 --e2e 0 --platform 0`
   (repeat for US-1602, US-1603 per the table above).
3. Update the epic README status column and each story file `## Status` from
   `in_progress` to the proven status (keep honest: code-complete + unit/integration
   proof, platform pending).
4. Re-read all three story files + epic README for consistency (no stale `in_progress`
   where proof now exists; no over-claimed platform rows).

## Success Criteria

- [ ] `harness-cli query stories` shows the three stories with the proof booleans above.
- [ ] Story files + epic README reconciled (status reflects proof, no contradictions).
- [ ] No proof layer set to `1` without a passing test/check behind it.

## Risk Assessment

- Risk: over-claiming platform/e2e proof inflates the harness signal. Mitigation: the
  conservative mapping above; only flip platform to `1` after an actual smoke run.
- Risk: story ID format differs from `US-16xx`. Mitigation: Step 1 confirms IDs before
  any `story update`.
