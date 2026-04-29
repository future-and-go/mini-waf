# Phase 04 — Ship: Build, Branch, Commit, Push, PR

**Priority:** P0
**Status:** completed
**Depends on:** phase-03 (all tests green)

## Goal

Run only after the plan is approved and phases 01–03 are complete with green tests. This phase performs the branch + commit + push + PR steps.

## Pre-flight

Before any branch/commit:
- [x] `cargo fmt -p waf-common -p waf-engine -p gateway -- --check` clean (touched crates)
- [x] `cargo clippy -p waf-common -p waf-engine -p gateway --all-targets -- -D warnings` clean
- [x] `cargo test -p waf-engine outbound::` — 19 / 19 green
- [x] `cargo build --release -p prx-waf` succeeds
- [x] `git status` showed only intended files (staged explicitly)
- [x] Diff scope verified manually before commit (no surprise scope creep)

## Branch & Commit Plan

Branch name: `feat/fr-035-header-leak-prevention`

Commit message (conventional, bilingual neutral, no AI references):

```
feat(outbound): FR-035 response header leak prevention

Strip server-info, debug/internal, and error-detail headers from upstream
responses before they reach the client. Detection categories are hard-coded;
each is gated by a config toggle. Optional PII regex scan over header values.
Disabled by default — opt in via [outbound] enabled = true.

- Add OutboundConfig + HeaderFilterConfig to waf-common
- Register waf-engine::outbound module; expose HeaderFilter
- Wire HeaderFilter into Pingora response_filter hook in WafProxy
- Add 10 new unit tests covering case sensitivity, security-header preservation,
  empty input, JWT detection, default-disabled invariants
- Add gateway integration test against stub upstream
- Document phase in system-architecture.md; mark FR-035 done in roadmap

Refs: analysis/requirements.md FR-035; CWE-200, CWE-209; OWASP ASVS V14.4
```

Per `CLAUDE.md` Git rules: NO `chore` / `docs` for `.claude/` changes — irrelevant here, this PR touches code/configs/docs only.

## Steps

1. **Verify clean state:**
   ```bash
   git status
   git diff --stat
   ```
2. **Create branch:**
   ```bash
   git checkout -b feat/fr-035-header-leak-prevention
   ```
3. **Stage explicitly** — never `git add -A` (CLAUDE.md rule). List exact files:
   ```bash
   git add crates/waf-common/src/config.rs
   git add crates/waf-engine/src/lib.rs
   git add crates/waf-engine/src/outbound/mod.rs
   git add crates/waf-engine/src/outbound/header_filter.rs
   git add crates/gateway/src/proxy.rs
   git add crates/gateway/tests/outbound_header_filter_test.rs   # if created
   git add crates/prx-waf/src/...                                  # construction site
   git add configs/default.toml
   git add docs/system-architecture.md
   git add docs/project-roadmap.md
   git add docs/codebase-summary.md
   ```
4. **Confirm staged set** matches expectation:
   ```bash
   git diff --cached --stat
   ```
5. **Commit** with HEREDOC for proper formatting (CLAUDE.md rule):
   ```bash
   git commit -m "$(cat <<'EOF'
   feat(outbound): FR-035 response header leak prevention

   Strip server-info, debug/internal, and error-detail headers from upstream
   responses before they reach the client. Detection categories are hard-coded;
   each is gated by a config toggle. Optional PII regex scan over header values.
   Disabled by default — opt in via [outbound] enabled = true.

   - Add OutboundConfig + HeaderFilterConfig to waf-common
   - Register waf-engine::outbound module; expose HeaderFilter
   - Wire HeaderFilter into Pingora response_filter hook in WafProxy
   - Add 10 new unit tests covering case sensitivity, security-header preservation,
     empty input, JWT detection, default-disabled invariants
   - Add gateway integration test against stub upstream
   - Document phase in system-architecture.md; mark FR-035 done in roadmap

   Refs: analysis/requirements.md FR-035; CWE-200, CWE-209; OWASP ASVS V14.4
   EOF
   )"
   ```
6. **If pre-commit hook fails:** fix root cause, re-stage, create a NEW commit (never `--amend` after hook failure — CLAUDE.md rule).
7. **Push to origin:**
   ```bash
   git push -u origin feat/fr-035-header-leak-prevention
   ```
8. **Open PR via `gh`** (relies on existing `gh auth status`; never log or commit any token):
   ```bash
   gh pr create --base main --title "feat(outbound): FR-035 response header leak prevention" --body "$(cat <<'EOF'
   ## Summary
   - Strip leaky response headers (server fingerprint, debug, internal, error detail) before they reach clients.
   - Detection categories hard-coded in `HeaderFilter`; activation per-category via `configs/default.toml [outbound.headers]`.
   - Disabled by default; zero overhead when off.
   - Hooks into Pingora `response_filter`; no body filtering (FR-033/FR-034 are separate plans).

   ## Implements
   - **FR-035** — `analysis/requirements.md` line 75
   - Closes gap from `plans/reports/pm-260421-1031-requirements-gap-analysis.md`

   ## Standards
   - OWASP ASVS V14.4, CWE-200, CWE-209, RFC 9110 §7.6, NIST SP 800-53 SI-11

   ## Test plan
   - [x] `cargo test -p waf-engine outbound::` green (17 unit tests)
   - [x] `cargo test -p gateway --test outbound_header_filter_test` green
   - [x] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
   - [x] `cargo fmt --all -- --check` clean
   - [x] `cargo build --release` green
   - [x] Manual: `curl -I` against stub upstream confirms `Server`/`X-Debug-*`/`X-Internal-*` stripped when enabled, passed through when disabled

   ## Out of scope
   - FR-033 response body content filtering — separate plan
   - FR-034 sensitive field redaction in JSON bodies — separate plan
   EOF
   )"
   ```
9. **Capture PR URL** and surface it back to the user.

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Branch name collision | `git branch -a | grep fr-035` first; suffix `-v2` if taken |
| `gh` not authenticated | User supplied a PAT in TODO.md (REDACTED — must be rotated post-merge); prefer existing `gh auth status`. Never log or commit the token. |
| Push rejected (out-of-date main) | `git fetch origin && git rebase origin/main` then push |
| PR template required | Inline body with HEREDOC matches CLAUDE.md format |

## Success Criteria

- [x] Branch `feat/fr-035-header-leak-prevention` exists on `origin`
- [x] PR opened against `main` — https://github.com/future-and-go/mini-waf/pull/14
- [x] PR URL surfaced to user
- [x] PR `mergeStateStatus` = CLEAN, `mergeable` = MERGEABLE (verified via `gh pr view 14`)

## Post-merge (informational only — not part of this plan)

- Run `npx gitnexus analyze` to refresh the index
- Tag/changelog update may be batched with subsequent FR plans

---

## Notes

- **Do NOT execute this phase until** the user explicitly approves the plan AND phases 01–03 are complete with green tests.
- The PAT in `TODO.md` should be **rotated by the user** after use; treat it as a one-time token.
