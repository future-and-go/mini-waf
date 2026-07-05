---
phase: 4
title: "Comment + test-name sweep (strip plan/phase/FR IDs)"
status: pending
effort: "45m"
---

# Phase 4: Comment + test-name sweep (strip plan/phase/FR IDs)

## Overview

Rewrite ~87 comment hits across `crates/waf-engine/src/risk/**` and
`crates/waf-engine/src/checks/ddos/**` that embed plan/phase/FR/§ labels, so comments
describe behavior instead of process artifacts. Enforces
`.claude/rules/review-audit-self-decision.md:32-34`. This phase runs **last** so it also
covers lines the earlier phases leave behind and picks up any rebase drift.

## Context

Scope grep (source of truth for the AC):
```
grep -rn "Phase |phase-|FR-0|§.*plan" \
  crates/waf-engine/src/risk crates/waf-engine/src/checks/ddos
```
87 hits on HEAD. Representative examples to rewrite:

| Location | Current | Rewrite to describe |
|---|---|---|
| `risk/scorer.rs:1,6-8,43-45` | `//! FR-025 Scorer orchestrator.` / `//! Phase 5 adds L2 detectors...` | orchestrator + which layers it runs, no phase/FR |
| `risk/config.rs:1,61,65,69,86,235,252,269` | `(Phase 4)`, `FR-028 ... (Phase 6)`, `(Phase 7)` | what each config section controls |
| `risk/seed/mod.rs:1`, `seed/tables.rs:1`, `seed/whitelist.rs:1`, `seed/tor.rs:1` | `//! FR-025 Phase 2: ...` | what the seed layer/loader does |
| `risk/state.rs:1,23,41,51,89` | `FR-025`, `(FR-006)`, `(FR-011)`, `FR-028` | behavior of each type/field |
| `risk/store/store_trait.rs:1,50` | `FR-025 risk store trait.`, `(FR-028)` | trait purpose / honeypot floor behavior |
| `checks/ddos/action/risk.rs:1,3` | `//! FR-005 phase-05 — Risk bump action...` / `FR-010's` | what the action submits and when |
| `checks/ddos/**/aggregator_impl.rs:27` | `per §3.3 of the plan` | the actual invariant it references |
| `risk/mod.rs:1,5`, `risk/decay.rs:1`, `risk/threshold.rs:1`, `risk/canary.rs:1,6`, `risk/velocity/sequence.rs:8` | assorted `FR-0xx` | behavior |
| test files: `risk/tests/lifecycle.rs:1`, `risk/tests/canary.rs:1`, `risk/tests/anomaly_combos.rs:1` | `//! FR-025 Phase 5: ...` | what the test module covers |

## Implementation Steps

1. Walk every hit from the scope grep. For each, rewrite the comment to state the behavior
   or invariant directly; delete the `Phase N` / `phase-NN` / `FR-0xx` / `§X.Y of the plan`
   token. Keep the sentence useful — do not just delete the label and leave a dangling fragment.
2. Also scan for **test/function names** embedding the same tokens within the two dirs
   (e.g. names containing `phase`, `fr_0`, `plan`). Rename to behavior-descriptive names.
   (HEAD grep shows hits are overwhelmingly doc comments, but confirm none leaked into
   `fn` names.)
3. Preserve genuinely meaningful cross-references: a `§`/section pointer that names a real,
   current doc invariant should be replaced by *stating* that invariant, not by a bare label.
4. Do NOT expand scope beyond `risk/**` + `checks/ddos/**`. Other dirs keep their comments.
5. Match surrounding comment style/density (repo rule: surgical, no adjacent reformatting).

## Files

- Modify (owner): all files under `crates/waf-engine/src/risk/**` and
  `crates/waf-engine/src/checks/ddos/**` that the scope grep flags (~20 files, comment-only
  edits). No logic changes.

## Success Criteria

- [ ] `grep -rn "Phase |phase-|FR-0|§.*plan" crates/waf-engine/src/risk crates/waf-engine/src/checks/ddos`
      returns **zero** hits.
- [ ] `cargo build -p waf-engine` + `cargo test -p waf-engine` green (comments only → no behavior change).
- [ ] `cargo fmt --all --check` clean.

## Risks & Rollback

- Risk: overlap with GH-202 (`checks/ddos/action/risk.rs`, `aggregator_impl.rs`) and GH-196/204
  (`risk/*`). Comment-only edits rebase trivially; run this phase after those land, or let GH-202
  fold in its two ddos comment fixes. No hard block.
- Risk: an `FR-0xx`/`§` reference points at a real spec invariant and a naive strip loses meaning.
  Mitigated by step 3 — restate the invariant rather than deleting blindly.
- Rollback: revert the comment diffs; no runtime impact.
