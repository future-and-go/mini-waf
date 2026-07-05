---
phase: 3
title: "RiskConfig serde verify and acceptance quality gates"
status: pending
effort: "1h"
---

# Phase 3: RiskConfig serde verify and acceptance quality gates

## Overview

Close item 2 (risk_api hand-mapped RiskConfig serde) as **verification-only** —
it is implemented by GH-196 Phase 3, not here — and run the full behavior-
preserving quality gate across Phases 1–2.

## Requirements

- Confirm the three risk_api mappers are gone (GH-196 landed) OR record item 2 as
  deferred-to-GH-196 with a clear pointer; do not re-implement it here.
- No public HTTP contract or config-file shape change across the whole plan.
- All existing tests green; build, clippy, fmt clean.

## Item 2 verification

1. `grep -n "yaml_to_fe\|fe_to_yaml\|default_risk_fe" crates/waf-api/src/risk_api.rs`
   - **Empty** → GH-196 Phase 3 landed; risk_api round-trips `RiskConfig` via
     serde. Item 2 satisfied. Confirm Phase 1's `resolve_path`/`write_yaml`
     migration coexists with GH-196's GET/PUT rewrite (both use the shared helper).
   - **Non-empty** → GH-196 not yet landed. Record item 2 as deferred; it is
     tracked by `260705-0953-gh-196-.../phase-03-risk-config-put-get-serde-round-trip.md`.
     Phase 1's helper migration still applies independently. Do NOT delete the
     mappers here (that is GH-196's owned change and its round-trip tests gate it).
2. If landed: verify a full-config round-trip test exists (PUT a config with
   non-default `challenge` / `session_cookie` / `ingest.signal_weights` / seed
   paths → GET → equal). This is GH-196's test; just confirm presence, don't add.

## Quality gates (whole plan)

- `cargo build --workspace`
- `cargo test -p waf-api` (Phase 1 surface)
- `cargo test -p waf-engine` (Phase 2 surface: risk + ddos)
- `cargo clippy --all-targets --workspace` (or the repo's configured clippy scope)
- `cargo fmt --check`
- Repo harness checks if applicable: `scripts/bin/harness-cli query matrix` /
  any lane quick-checks the intake prescribes for a refactor.

## Behavior-preserving proof

- Diff review: every changed line traces to dedupe (shared helper call, Clock
  param) — no handler logic, error semantics, or file-shape change.
- Grep-clean assertions:
  - `grep -rn "fn resolve_path\|fn rules_path" crates/waf-api/src` → only
    `config_files.rs` (tls.rs has no `resolve_path`).
  - `grep -rn "unix_now_ms" crates/waf-engine/src` → empty.
  - `grep -rn "chrono::Utc" crates/waf-engine/src/risk/store/memory.rs
    crates/waf-engine/src/risk/ingest` → only `#[cfg(test)]` helpers, if any.

## Risks & Rollback

- **Risk (Med):** implementing before GH-196 lands means item 2 stays open.
  Mitigation: this plan is `blockedBy` GH-196; if unblocked early, the deferral
  path above keeps GH-207 self-consistent and Phase 1 still delivers value.
- **Rollback:** phase is verification + CI only; nothing to roll back beyond the
  Phase 1/2 commits.

## Success Criteria

- [ ] Item 2 status recorded: mappers deleted (GH-196 landed) or deferred pointer.
- [ ] `cargo build --workspace`, `cargo test -p waf-api`, `cargo test -p waf-engine`
      all green.
- [ ] `cargo clippy --all-targets` and `cargo fmt --check` clean.
- [ ] Grep-clean assertions pass; no public contract or config-file shape change.
