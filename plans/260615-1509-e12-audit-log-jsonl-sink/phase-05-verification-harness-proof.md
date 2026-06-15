---
phase: 5
title: "Verification + harness proof"
status: completed
priority: P1
effort: "2h"
dependencies: [1, 2, 3, 4]
---

# Phase 5: Verification + harness proof

## Overview

Run the full validation ladder, then record durable proof for E12 in the harness
(story status/proof booleans, decision registration/verify). No code change
beyond fixing anything the gates surface.

## Requirements

- All validation commands run from repo root and pass; proof recorded numerically
  via `harness-cli`.
- Decisions 0009 and 0010 registered in the durable layer (markdown files already
  exist) and tied to the implemented stories.

## Validation Ladder

```
validate:quick   cargo fmt --all -- --check
                 cargo clippy --workspace -- -D warnings
                 cargo build --workspace
                 cargo test -p waf-engine audit
test:integration cargo test -p waf-api interop_control
                 cargo test --workspace
```

> Note: validation.md flags workspace test build may hit ENOSPC (full disk).
> Check `df -h .` first; if low, prune `target/` or run targeted `-p` tests and
> record the disk constraint in the trace rather than claiming a green that did
> not run.

## Implementation Steps

1. `cargo fmt --all -- --check`; fix formatting.
2. `cargo clippy --workspace -- -D warnings`; fix lints (esp. dead-code after VL
   removal).
3. `cargo build --workspace`.
4. `cargo test -p waf-engine audit` (unit + sink).
5. `cargo test -p waf-api interop_control` and the new correlation test
   (integration).
6. `cargo test --workspace` (disk permitting).
7. Record proof per story (US-1201..1205):
   `scripts/bin/harness-cli story update --id US-1201 --status implemented \
     --unit 1 --integration 1 --e2e 0 --platform 0` (repeat per story with its
   actual proof booleans; US-1205 is a removal — unit/integration via green
   workspace build/tests).
8. Register decisions:
   `scripts/bin/harness-cli decision add --id 0009-audit-log-jsonl-file-sink \
     --title "JSONL audit file sink" --doc docs/decisions/0009-audit-log-jsonl-file-sink.md`
   and `0010-decommission-victorialogs` likewise.
9. Update the E12 README story table statuses (in_progress/planned →
   implemented) and append acceptance evidence to
   `US-1201-jsonl-file-writer/validation.md`.
10. Record a trace: `scripts/bin/harness-cli trace --summary "E12 audit JSONL sink
    + VL decommission" --outcome success --story US-1201` (+ note VL-removal and
    any disk constraint).
11. `scripts/bin/harness-cli query matrix` to confirm E12 rows reflect proof.

## Success Criteria

- [ ] fmt clean, clippy clean (`-D warnings`), workspace builds.
- [ ] `waf-engine audit` unit/sink tests green.
- [ ] `waf-api interop_control` + correlation integration tests green.
- [ ] `cargo test --workspace` green (or disk constraint documented with targeted
      green per crate).
- [ ] US-1201..1205 proof booleans recorded; matrix reflects `implemented`.
- [ ] Decisions 0009 + 0010 registered in durable layer.
- [ ] E12 README + validation.md updated with evidence; trace recorded.

## Risk Assessment

- **ENOSPC** blocking the workspace test build — documented in validation.md;
  mitigate by pruning `target/` or running targeted `-p` tests, and record the
  constraint honestly (do not claim an unrun green).
- **Clippy dead-code** after VL removal (orphan imports/fns) — fix in-scope per
  CLAUDE.md "clean up orphans YOUR changes create".
