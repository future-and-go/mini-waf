---
phase: 5
title: "Docs Update"
status: complete
priority: P2
effort: "0.5d"
dependencies: [4]
completedAt: "2026-05-04"
---

# Phase 5: Docs Update

## Overview

Update project docs and write journal entry. Reflect FR-012 in roadmap, codebase summary, request pipeline, and add dedicated guide.

## Requirements

- New: `docs/transaction-velocity.md` — feature guide (config, signals, tuning)
- Update: `docs/request-pipeline.md` — show TxVelocityCheck position in chain
- Update: `docs/codebase-summary.md` — add `checks/tx_velocity/` module
- Update: `docs/project-roadmap.md` — mark FR-012 complete
- Update: `docs/development-roadmap.md` if separate
- Journal: `docs/journals/2026-05-XX-fr-012-transaction-velocity-complete.md`

## Related Code Files

**Create:**
- `docs/transaction-velocity.md`
- `docs/journals/2026-05-XX-fr-012-transaction-velocity-complete.md`

**Modify:**
- `docs/request-pipeline.md`
- `docs/codebase-summary.md`
- `docs/project-roadmap.md`
- `CHANGELOG.md`

## Implementation Steps

1. **`transaction-velocity.md`** — sections: Overview, Architecture diagram (mermaid), Config schema with example, Classifiers explained, Tuning guide, Risk-score interaction, Limitations (cluster, ok-flag)

2. **`request-pipeline.md`** — insert TxVelocityCheck box in pipeline diagram between RateLimit and Scanner

3. **`codebase-summary.md`** — add bullet under `waf-engine`: `checks/tx_velocity/` purpose 1-liner

4. **`project-roadmap.md`** — flip FR-012 status to ✅ complete

5. **`CHANGELOG.md`** — entry: `feat(waf-engine): FR-012 transaction velocity & sequence detection (#XX)`

6. **Journal** via `/ck:journal` — what shipped, key decisions, what we'd do differently

## Todo List

- [x] Write `transaction-velocity.md` (≤800 LOC)
- [x] Update request-pipeline diagram + prose
- [x] Add module to codebase-summary (already present from prior phase)
- [x] Mark FR-012 complete in roadmap
- [x] CHANGELOG entry
- [x] Journal completion entry written

## Success Criteria

- [ ] All listed docs updated
- [ ] No stale references (no `TODO: FR-012`)
- [ ] Journal entry committed
- [ ] PR description references all touched docs

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Doc drift from code | Pin code excerpts to file:line refs (will rot but easy to grep-fix) |
| Mermaid syntax errors | Validate with `/ck:mermaidjs-v11` before commit |
