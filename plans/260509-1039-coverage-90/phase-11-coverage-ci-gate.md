# Phase 11 — Coverage CI gate (workflow + per-crate floors)

## Context Links
- Baseline: `plans/260509-1039-coverage-90/plan.md`
- Phases 01-10 must land first.

## Overview
- **Priority:** P2
- **Status:** pending (BLOCKED on Phases 01–10)
- **Target:** Codified per-crate floors in CI; PR fails if any crate drops below floor.
- File ownership glob: `.github/workflows/coverage.yml`, `scripts/coverage-check.sh`

## Key Insights
- `cargo llvm-cov` already used in this workspace (verified in baseline run).
- Per-crate floors must be **at-or-just-below** achieved coverage to leave headroom for non-coverage-related changes.
- Workspace-wide floor is meaningful only if exclusion list is documented; otherwise prx-waf drags it.

## Floors (proposed; tighten after Phases land)

| Crate | Floor | Notes |
|-------|-------|-------|
| waf-common  | 88% | post-Phase 01 actual − 2% headroom |
| waf-storage | 82% | post-Phase 02 actual − 3% (DB tests can vary) |
| waf-cluster | 82% | post-Phase 03 actual − 3% |
| waf-api     | 78% | post-Phase 04 actual − 2% |
| gateway     | 82% | post-Phase 05 actual − 3% (Pingora-coupled flake risk) |
| waf-engine  | 88% | post-Phases 06-09 actual − 2% |
| prx-waf     | 32% | post-Phase 10 actual − 3% (CLI dispatch nature) |
| **workspace (excluding prx-waf/main.rs)** | **85%** | — |

## Requirements
- CI job runs on every PR + main push.
- Per-crate report uploaded as artifact (LCOV + HTML).
- Job fails with clear diff if any crate below floor.
- No coverage drop without explicit floor update PR.

## Architecture
```
.github/workflows/coverage.yml   ← new workflow, parallelised matrix per crate
scripts/coverage-check.sh        ← per-crate floor enforcement (bash, awk-based parser)
```

## Related Code Files
**Create:**
- `.github/workflows/coverage.yml` — runs on PR + main push.
- `scripts/coverage-check.sh` — invoked by workflow; takes crate name + floor; exits non-zero if below.

**Optional:**
- `codecov.yml` if uploading to Codecov; otherwise GitHub artifacts only.

## Implementation Steps
1. Create `scripts/coverage-check.sh`:
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail
   crate="$1"; floor="$2"
   actual=$(cargo llvm-cov -p "$crate" --summary-only --ignore-filename-regex 'vendor/|target/' 2>/dev/null \
     | awk '/^TOTAL/ { print $10 }' | tr -d '%')
   awk -v a="$actual" -v f="$floor" 'BEGIN { exit !(a >= f) }' \
     || { echo "::error::Crate $crate coverage $actual% < floor $floor%"; exit 1; }
   echo "OK: $crate $actual% ≥ $floor%"
   ```
2. Create `.github/workflows/coverage.yml`:
   ```yaml
   name: Coverage
   on: [pull_request, push]
   jobs:
     coverage:
       runs-on: ubuntu-latest
       services:
         postgres:
           image: postgres:16-alpine
           env: { POSTGRES_PASSWORD: prx_waf, POSTGRES_USER: prx_waf, POSTGRES_DB: prx_waf }
           ports: [5432:5432]
           options: >-
             --health-cmd pg_isready --health-interval 5s
             --health-timeout 5s --health-retries 10
       strategy:
         fail-fast: false
         matrix:
           include:
             - { crate: waf-common,  floor: 88 }
             - { crate: waf-storage, floor: 82 }
             - { crate: waf-cluster, floor: 82 }
             - { crate: waf-api,     floor: 78 }
             - { crate: gateway,     floor: 82 }
             - { crate: waf-engine,  floor: 88 }
             - { crate: prx-waf,     floor: 32 }
       steps:
         - uses: actions/checkout@v4
         - uses: dtolnay/rust-toolchain@stable
         - uses: taiki-e/install-action@cargo-llvm-cov
         - run: bash scripts/coverage-check.sh ${{ matrix.crate }} ${{ matrix.floor }}
   ```
3. Verify locally first: `bash scripts/coverage-check.sh waf-common 88`.
4. Once all crate jobs pass, raise floors to actual−1 for tighter gating.
5. Add a workspace-level summary job that aggregates artifacts and posts a comment to PR.
6. Document procedure in `docs/code-standards.md` § "Coverage Gate".

## Todo List
- [ ] `scripts/coverage-check.sh` (≤30 LOC)
- [ ] `.github/workflows/coverage.yml`
- [ ] Local smoke test: each crate passes with the proposed floor
- [ ] PR-comment summary (optional, nice-to-have)
- [ ] `docs/code-standards.md` § Coverage Gate

## Success Criteria
- Workflow green on a "no-op" PR.
- Workflow fails on a PR that deletes a high-coverage test file (validate by intentional regression test).
- Per-crate floors documented in workflow.

## Risk Assessment
- **Medium**: `cargo llvm-cov` requires ~10 min cold build per crate. Cache `~/.cargo/registry` + `target/` between runs.
- **Medium**: Postgres service container in CI may differ from testcontainers locally — keep image version pinned (`postgres:16-alpine`).
- **Low**: bash parsing brittle if `cargo llvm-cov` output format changes — pin version in `taiki-e/install-action`.

## Security Considerations
- CI Postgres credentials must be ephemeral (no secrets persisted).
- Coverage artifacts must NOT include source dumps that reveal secrets — verify uploaded LCOV does not embed file contents.

## Next Steps
- After 1 month of green CI, raise floors to actual−1%.
- After Phase 10 follow-up `main.rs` refactor, raise prx-waf floor accordingly.
