---
phase: 5
title: PR-CI-Hardening
status: in-progress
effort: 1h
priority: P1
depends_on:
  - 4
---

# Phase 5: PR — CI Hardening, Squash, Open PR

## Context Links

- `rules.md` line 9 — PR description in English, senior-developer style; conversational answers in Vietnamese.
- `rules.md` line 3 — `context.md` NOT committed.
- `CLAUDE.md` — `cargo fmt --all` mandatory pre-push; CI enforces `--check`.
- `CLAUDE.md` Seven Iron Rules — re-audit before push.

## Overview

Local gates → branch → squash → push → PR → CI green. No code changes; this phase is the release ritual.

## Key Insights

- Format drift fails the CI Lint job → run `cargo fmt --all` before push.
- Clippy with `-D warnings` is project standard; one warning fails CI.
- All commits squashed to one with conventional-commit message.
- PR description is English (formal); inline answers to user (in chat) Vietnamese.
- `context.md` is local-only and must NOT be staged.

## Requirements

### Functional

- Branch `feat/fr-030-dashboard-backend` exists on origin.
- Exactly 1 commit on top of `origin/main` at PR open time.
- PR opened against `main` via `gh pr create`.
- CI all green: build + tests + coverage + lint + clippy + fmt.

### Non-Functional

- No secret / no `context.md` / no `.env` in diff.
- PR description ≤ 60 lines, senior style, English.

## Architecture

Pure git/CI workflow. No application code changes.

## Related Code Files

**Read only:**
- `Cargo.toml`, `Cargo.lock` — verify no incidental changes.
- `.github/workflows/*.yml` — confirm jobs expected to run (build, test, coverage, lint).

**Modify:** none (this phase touches git state, not source).

## Implementation Steps

### Step 0 — Raise CI coverage floors (F8 enforcement)

After phase 4 confirms tests are green and local llvm-cov shows ≥84 / ≥80, edit `.github/workflows/coverage.yml:41-44`:

```diff
       matrix:
         include:
           - { crate: waf-common,  floor: 88 }
-          - { crate: waf-storage, floor: 82 }
+          - { crate: waf-storage, floor: 84 }
           - { crate: waf-cluster, floor: 82 }
-          - { crate: waf-api,     floor: 78 }
+          - { crate: waf-api,     floor: 80 }
           - { crate: gateway,     floor: 85 }
           - { crate: waf-engine,  floor: 80 }
           - { crate: prx-waf,     floor: 5 }
```

**Why exactly +2:** new-code is bounded; +2pp leaves headroom for normal noise but enforces the SPIRIT of "new code clean." If local llvm-cov shows headroom for +3, raise to +3 instead. Never lower an existing floor in this PR.

Stage this edit as part of the same single commit (step 5).

### Step 1 — Format

```bash
docker run --rm -v $PWD:/work -w /work rust:1.91-slim-bookworm \
  sh -c "cargo fmt --all"
docker run --rm -v $PWD:/work -w /work rust:1.91-slim-bookworm \
  sh -c "cargo fmt --all -- --check"
```

Second command MUST exit 0. If diff exists, re-run first command, stage, commit as part of feature commit (not separate `style:` commit since we squash anyway).

### Step 2 — Clippy

```bash
docker run --rm -v $PWD:/work -w /work rust:1.91-slim-bookworm \
  sh -c "cargo clippy --workspace --all-targets -- -D warnings"
```

Exit 0. Fix any warnings before push. Common offenders for new code:
- Unused `mut` on `total` accumulator.
- `as i64` casts → use `i64::try_from(...).unwrap_or(i64::MAX)`.
- Redundant clone in HashSet usage.

### Step 3 — Audit unwrap/expect

```bash
grep -RnE '\.unwrap\(\)|\.expect\(' crates/waf-storage/src crates/waf-api/src | grep -v '^[^:]*:[^:]*://'
```

Expected output: empty (or only pre-existing matches in unchanged files). Any new hit → replace with `?` + `.context(...)` or `.unwrap_or_default()`.

### Step 4 — Verify `context.md` not staged

```bash
git status --short | grep -E 'context\.md$' && echo "BLOCK: context.md staged" || echo "OK"
```

If staged → `git restore --staged context.md`. Add to `.gitignore` if not already.

### Step 5 — Branch + squash

```bash
git checkout -b feat/fr-030-dashboard-backend
git add migrations/0009_category_function.sql \
        crates/waf-storage/src/models.rs \
        crates/waf-storage/src/repo.rs \
        crates/waf-storage/src/db.rs \
        crates/waf-storage/src/lib.rs \
        crates/waf-storage/tests/common/mod.rs \
        crates/waf-storage/tests/repo_category_function.rs \
        crates/waf-storage/tests/repo_endpoint_heatmap.rs \
        crates/waf-storage/tests/repo_stats_overview_filters.rs \
        crates/waf-api/src/stats.rs \
        crates/waf-api/src/server.rs \
        crates/waf-api/tests/common/mod.rs \
        crates/waf-api/tests/handler_stats_endpoints.rs \
        crates/waf-api/tests/handler_stats_overview_filters.rs \
        crates/waf-api/tests/stats_overview_backward_compat.rs \
        .github/workflows/coverage.yml \
        plans/260515-1714-fr030-dashboard-backend/

git commit -m "$(cat <<'EOF'
feat(stats): FR-030 endpoint heatmap + stats overview filters

- Add GET /api/stats/endpoints returning sparse (path, category, count)
  cells for top-20 attacked endpoints in a configurable time window.
- Add optional host_code/action/hours filters to GET /api/stats/overview;
  default (no params) preserves current response shape for backward
  compatibility with the existing dashboard frontend.
- Extract duplicated rule_id -> category CASE expression to a Postgres
  IMMUTABLE function category_of(rule_id) via migration 0009; the new
  heatmap query is its third consumer, eliminating triplication.
- Storage + handler tests via testcontainers (real Postgres) achieve
  >=90% line coverage on the new code paths.
EOF
)"
```

**Explicit file list** (not `git add -A`) — avoids accidentally staging `context.md`, journal scratch files, or unrelated work.

If incremental commits exist on the branch already, squash:
```bash
git rebase -i origin/main  # squash all into first
```

(Per `rules.md`: NEVER use `-i` rebase in tools — for the human; the `git commit --amend` flow is safe alternative; preferred path is to commit only once from the start.)

### Step 6 — Push

```bash
git push -u origin feat/fr-030-dashboard-backend
```

### Step 7 — Open PR via `gh`

```bash
gh pr create --base main --head feat/fr-030-dashboard-backend \
  --title "feat(stats): FR-030 endpoint heatmap + overview filters" \
  --body "$(cat <<'EOF'
## Summary

Adds backend support for the FR-030 dashboard attack-visualization heatmap and enriches `/api/stats/overview` with optional filtering.

- **New endpoint** `GET /api/stats/endpoints` returns a sparse
  `(path, category, count)` heatmap for the top-20 attacked endpoints
  within a configurable time window (`hours`, default 24, max 720),
  optionally filtered by `host_code` and `action`. Response shape is
  designed for direct rendering by D3/visx/Plotly-style heatmap
  components with no client-side pivoting.
- **Enriched** `GET /api/stats/overview` accepts optional `host_code`,
  `action`, and `hours` query parameters. When called without
  parameters the response shape and values are byte-equivalent to the
  pre-change behavior, preserving the existing dashboard frontend.
- **DRY refactor**: the 28-branch `rule_id -> category` CASE
  expression (previously duplicated twice inside `get_stats_overview`)
  is extracted to a Postgres `IMMUTABLE` function `category_of(rule_id)`
  introduced by migration `0009_category_function.sql`. The new
  heatmap query is its third consumer; future categories require a
  single edit.

## Why

The current dashboard cannot answer the operator question "which
endpoints are under which kinds of attack right now?". Building this
into the frontend without backend support would either require N+1
HTTP fan-out or shipping raw event rows; both are wasteful at the
event volume we already see in production. A single aggregated
endpoint with bounded cardinality (240 cells worst case, ~80-120
typical) is the simplest implementation that satisfies the
requirement.

## Design notes

- **Sparse JSON** chosen over dense matrix: ~65 percent smaller
  payload, no padding, native fit for heatmap libraries.
- **Top-20 paths** chosen over normalization-on-read: zero migration
  risk, zero write-time cost, dynamic ranking surfaces what matters
  now.
- **Postgres function** for category derivation chosen over Rust-side
  computation: keeps all stat queries set-based and avoids streaming
  every row into application memory just to bucket it.
- Existing indexes (`created_at DESC`, `host_code`, `action`) are
  sufficient; no new index migration introduced.

## Backward compatibility

`GET /api/stats/overview` without query parameters returns the same
JSON shape and values as before. A snapshot test asserts every
pre-existing key remains present.

## Tests

- New repo-layer tests cover every `category_of` branch (including
  the longer-prefix ordering cases: `CRS-RESP-*`, `ADV-SSRF-*`,
  `OWASP-942/941/930/931/932/933/913`), heatmap empty/single/multi
  cases, filters by host, action, and hours window, top-20 path
  truncation, NULL `rule_id` exclusion, the `'other'` rollup for
  tail categories, and the invariant `total_events == sum(cells)`.
- New API tests cover the new endpoint (happy path, empty, hours
  clamping, auth) and the overview filter axes including the
  empty-string-as-no-filter normalization.
- A dedicated backward-compat regression file asserts every legacy
  JSON key remains present in the `/api/stats/overview` response and
  that the filter variant shares the same envelope shape as the
  unfiltered call.
- All tests run against real Postgres via testcontainers
  (`crates/waf-storage/tests/common/mod.rs`).
- Per-crate line coverage floors raised: `waf-storage` 82 -> 84,
  `waf-api` 78 -> 80. CI fails the PR if either drops.

## Migration

`migrations/0009_category_function.sql` is additive (creates a single
`LANGUAGE SQL IMMUTABLE` function). Rollback is
`DROP FUNCTION IF EXISTS category_of(TEXT);` followed by reverting
the two refactor sites to inline CASE.

## Risk

- Low. The new endpoint is auth-gated like its siblings, all queries
  are parameterized, cardinality is bounded by `LIMIT 20` /
  `LIMIT 12` in the CTEs, path projections are capped at
  `LEFT(path, 256)`, and the `'other'` rollup ensures no tail data
  is dropped from totals.
EOF
)"
```

### Step 8 — Wait for CI

```bash
gh pr checks --watch
```

All checks must pass:
- build
- test (unit + integration)
- coverage (≥ existing floors; new code ≥90%)
- lint (fmt + clippy)

If any check fails:
1. Read failure log via `gh run view --log-failed`.
2. Fix in a NEW commit on the branch.
3. Once green locally, squash again: `git reset --soft origin/main && git commit -m "..."` then force-push **to the feature branch only** (never `main`).
4. Re-run `gh pr checks --watch`.

### Step 9 — Final audit before merge request

- [ ] PR description senior English style, no emoji, no AI references.
- [ ] Commit message conventional (`feat(stats): ...`).
- [ ] Exactly 1 commit ahead of `main`.
- [ ] `context.md` not in diff.
- [ ] Plan folder included in diff for reviewer reference (acceptable; lives under `plans/`).

## Todo List

- [ ] Raise crate floors in `.github/workflows/coverage.yml` (waf-storage 82→84, waf-api 78→80).
- [ ] Run `cargo fmt --all` + `--check`.
- [ ] Run `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] Audit grep for `.unwrap()/.expect()` regression.
- [ ] Verify `context.md` unstaged.
- [ ] Create branch + single squashed commit (explicit file list).
- [ ] Push + open PR via `gh`.
- [ ] Watch CI via `gh pr checks --watch`.
- [ ] Fix any CI failures + re-squash if needed.
- [ ] Confirm green; notify reviewer.

## Success Criteria

- [ ] PR open against `main`, exactly 1 commit ahead.
- [ ] `.github/workflows/coverage.yml` floors raised (waf-storage 84, waf-api 80) and CI passes them.
- [ ] All CI checks green (build, test, coverage, lint, clippy, fmt).
- [ ] PR description English, senior style.
- [ ] No `.unwrap()` regression introduced.
- [ ] Branch `feat/fr-030-dashboard-backend` pushed to origin.

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Rustfmt drift between local + CI | Med | Low | Run `--check` in Docker before push |
| Clippy lint deltas unstable across versions | Low | Med | Match `rust-toolchain.toml` if present; pin via Docker tag `1.91-slim-bookworm` |
| Coverage tool absent in CI runner | Low | High | Existing workflow installs via `taiki-e/install-action@cargo-llvm-cov` (researcher 1 §Q11) |
| Force-push race during squash | Low | Med | Force-push only to feature branch, never `main`; ensure no other contributors on branch |
| `context.md` leak | Low | High | Explicit file list in `git add`; `.gitignore` entry; grep gate |

## Security Considerations

- No secrets in PR (none added).
- No new privileges or env vars.
- Auth path unchanged.

## Rollback Plan

If merged and prod regression detected:
1. Revert PR: `gh pr revert <number>` or manual revert commit.
2. Apply migration rollback SQL (`DROP FUNCTION IF EXISTS category_of(TEXT);`) — only if reverting the migration itself; the function is harmless if left in place.

## Next Steps

Post-merge: update `docs/development-roadmap.md` and `docs/project-changelog.md` (separate PR per `documentation-management.md`). Frontend heatmap component (out of scope) consumes new endpoint.
