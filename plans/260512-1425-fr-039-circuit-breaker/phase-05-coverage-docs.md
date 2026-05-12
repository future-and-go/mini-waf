---
phase: 5
title: "Coverage Gate + Docs + Journal"
status: pending
priority: P0
effort: "2h"
dependencies: [3, 4]
---

# Phase 5: Coverage + Docs + Journal

## Overview

Close out FR-039: enforce ≥ 90% line+branch coverage (mandatory per `rules.md` line 6), update project docs (`codebase-summary`, `project-roadmap`), write journal entry, prepare PR. Run final lint/fmt/audit gates.

## Requirements

**Functional:**
- Coverage ≥ 90% on all FR-039-modified files (cargo-llvm-cov, line + branch)
- `cargo fmt --all -- --check` green
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` green
- `cargo audit` green (no new advisories)
- `docs/codebase-summary.md` and `docs/project-roadmap.md` updated
- Journal entry in `docs/journals/2026-05-12-fr-039-circuit-breaker.md`
- `context.md` written at repo root (per `rules.md` line 3; NOT committed)
- Branch `feat/fr-039-circuit-breaker` pushed; PR opened via `gh pr create`

**Non-functional:**
- No secrets in commits (`grep -r 'TOKEN\|PASSWORD\|SECRET'` clean)
- Conventional commits format (`feat(gateway):`, `test(gateway):`, etc.)
- Plan + research + scout reports referenced in PR body

## Architecture

### Coverage strategy

Per existing `gateway/CLAUDE.md`, CI gates at 95% on scoped files (excludes `cache`, `lb`, `tunnel`, `ssl`, `http3`, `proxy`, `proxy_waf_response`, `context`, `router`, `lib`, `request_ctx_builder`, `protocol`). **FR-039 touches `proxy.rs` and `error_page_factory.rs` — `proxy.rs` is currently EXCLUDED from the 95% gate.**

**Decision:** Two-track coverage.
- Track A: FR-039-specific report on FR-039 code only (proxy.rs new lines + error_page changes + types.rs new validator). Target ≥ 90%.
- Track B: workspace-wide regression — existing gate stays at 95%; FR-039 must not regress it.

Coverage command:

```bash
cargo llvm-cov -p gateway -p waf-common \
  --tests \
  --no-fail-fast \
  --html \
  --output-dir target/llvm-cov/fr-039
```

Inspect `target/llvm-cov/fr-039/html/` and confirm new lines green.

### Docs update strategy

**`docs/codebase-summary.md`:**
- Add FR-039 row to feature matrix (if present)
- Add brief paragraph under "Resilience" section

**`docs/project-roadmap.md`:**
- Move FR-039 from "Pending P0" to "Complete P0"
- Add completion date and PR link

**`docs/journals/2026-05-12-fr-039-circuit-breaker.md`** (new file):
- Brief summary
- Key decisions (esp. red-team finding: do NOT reuse `degrade::resolve()` for transport fail)
- Coverage numbers
- Open follow-ups (HTTP/3 audit, per-tier timeouts)

### context.md (per rules.md)

```markdown
# Session Context: FR-039 Circuit Breaker

**Branch:** feat/fr-039-circuit-breaker
**Plan:** plans/260512-1425-fr-039-circuit-breaker/
**Completed:** 2026-05-12

## Summary
Implemented FR-039 (transport-layer upstream timeouts + 503 mapping) via 5-phase plan. Stateless, KISS, reused existing ErrorPageFactory.

## Key files
- crates/waf-common/src/types.rs (6 new fields)
- crates/gateway/src/proxy.rs (3 edits)
- crates/gateway/src/error_page/error_page_factory.rs (Retry-After)
- crates/gateway/tests/circuit_breaker_timeouts.rs (10 tests)
- tests/e2e/circuit-breaker/ (Docker e2e, 5 scenarios)

## Coverage
{numbers from cargo-llvm-cov}

## Followups
- HTTP/3 path audit if not already verified
- Per-tier timeout granularity (Critical=3s)
- Prometheus counter `upstream_timeout_total`
```

**MUST NOT commit context.md** — it's a session artifact per `rules.md`.

## Related Code Files

**Create:**
- `docs/journals/2026-05-12-fr-039-circuit-breaker.md`
- `context.md` (root; gitignored — verify or add to .gitignore)

**Modify:**
- `docs/codebase-summary.md`
- `docs/project-roadmap.md`
- `.gitignore` — add `/context.md` if not already excluded

**Delete:** none

## Implementation Steps

1. Run coverage: `cargo llvm-cov -p gateway -p waf-common --tests --html --output-dir target/llvm-cov/fr-039`.
2. If < 90% on FR-039 code → add missing tests in Phase 3 (loop back).
3. Run `cargo fmt --all -- --check` — fix any drift.
4. Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` — fix all.
5. Run `cargo audit` — note any new advisories (none expected; we add no deps).
6. Update `docs/codebase-summary.md` (find FR feature table; mark FR-039 done).
7. Update `docs/project-roadmap.md` (move FR-039 to complete).
8. Write `docs/journals/2026-05-12-fr-039-circuit-breaker.md` (concise, ≤ 80 lines).
9. Write `context.md` at repo root.
10. Verify `.gitignore` excludes `/context.md`.
11. Stage + commit incrementally (conventional commits):
    - `feat(waf-common): add FR-039 upstream timeout fields to HostConfig`
    - `feat(gateway): apply Pingora upstream timeouts + map transport errors to 503 (FR-039)`
    - `test(gateway): FR-039 timeout & circuit breaker unit tests`
    - `test(e2e): FR-039 circuit breaker Docker e2e (H1/H2/H3)`
    - `docs: mark FR-039 complete in roadmap + codebase summary`
12. Push `feat/fr-039-circuit-breaker` to origin.
13. Open PR via `gh pr create --title "feat(gateway): FR-039 circuit breaker (upstream timeouts + 503)"` with body referencing plan + reports.

## Todo List

- [ ] `cargo llvm-cov` ≥ 90% on FR-039 code
- [ ] `cargo fmt --all -- --check` green
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` green
- [ ] `cargo audit` reviewed
- [ ] `docs/codebase-summary.md` updated
- [ ] `docs/project-roadmap.md` updated
- [ ] `docs/journals/2026-05-12-fr-039-circuit-breaker.md` written
- [ ] `context.md` written (and gitignored)
- [ ] Conventional commits staged
- [ ] Branch pushed
- [ ] PR opened with plan + reports linked
- [ ] CI green on PR

## Success Criteria

- [ ] Coverage ≥ 90% confirmed via cargo-llvm-cov report
- [ ] All CI checks green (fmt, clippy, test, audit, build, coverage)
- [ ] Docs reflect FR-039 completion
- [ ] PR review-ready (no TODOs, no dead code, no `.unwrap()` in prod)
- [ ] Journal entry under 80 lines, references plan + reports

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Coverage gap on error-path branches (rare error types) | Add property tests with `proptest` covering all `ErrorType` variants |
| `cargo clippy --all-features` breaks on unrelated feature gates | Run `--all-features` early in Phase 5; fix or scope-down |
| Existing 95% gate trips on `proxy.rs` due to growth | `proxy.rs` is on the EXCLUDED list per `gateway/CLAUDE.md`; verify still excluded |
| PR conflicts with concurrent FR-006/FR-035 work | Rebase from `main` before push; resolve in branch |
| `cargo audit` flags transitive dep | Update `audit.toml` policy or pin advisory; do NOT bypass blindly |

## Security Considerations

- `context.md` may contain sensitive paths — ensured gitignored.
- Commits scanned for accidental secret inclusion (`gh secret list` mismatch is impossible; we add no secrets).
- PR description references public docs only.

## Branch & Commit Hygiene (per rules.md)

- Branch: `feat/fr-039-circuit-breaker` (matches feature)
- Commits: conventional (feat/test/docs); no `chore` or `docs` for `.claude/` files (per CLAUDE.md)
- `cargo fmt --all` before every push (Pre-Push rule)
- `context.md` written, NEVER committed
