# Phase 06 — ABSORBED INTO PHASE 05 (post-red-team scope cut)

> **RED-TEAM PATCH:** Scope Critic finding #1 + #9 collapse phase-06 into phase-05. Ship checklist is now a sub-section of phase-05; this file is retained as historical reference only. **Do NOT execute phase-06 as a separate phase.** Refer to phase-05 for ship steps.
> - Reference: [`reports/red-team-260428-2332-fr033-adjudication.md`](reports/red-team-260428-2332-fr033-adjudication.md).

## Context Links
- CLAUDE.md "Build & Test" canonical commands
- Repo conventions: conventional commits, no AI references in commit / PR text
- Open PRs to consider: PR 14 (`feat/fr-035-header-leak-prevention`), PR 18 (`feat/fr-034-response-field-redaction`)

## Overview
- **Priority:** P0
- **Status:** pending
- Branch, run full local CI, run conflict probe against PR 14 + PR 18, single-commit policy, open PR with cross-references and conflict-resolution notes.

## Key Insights
- Both PR 14 and PR 18 are still open. We MUST avoid touching their owned files (`config.rs`, `prx-waf/main.rs`, `project-roadmap.md`) to keep merge clean.
- Textual conflicts on `HostConfig` (PR 18) and `proxy.rs` body filter ordering (PR 18) are expected and mechanical; document resolution in PR description so reviewer doesn't have to reverse-engineer.
- Single-commit policy = squash-on-merge friendly + clean revert path.
- PR description must be human-style (no AI-derived language, no "I generated", no "This PR adds the following capabilities..." marketing). Match style of recent merged PRs (`git log --oneline -20`).

## Requirements
**Functional**
- Branch `feat/fr-033-response-body-content-filter` from `main`.
- All Build & Test commands from CLAUDE.md pass locally.
- Conflict probe against both open PRs documented.
- PR opened against `main` with structured body.

**Non-functional**
- No AI references in commit / PR text.
- No `--no-verify` push.
- Single commit (per dev-rules and clean review).

## Architecture
N/A — this phase is process.

## Related Code Files
N/A — operates on git + GitHub state.

## Implementation Steps
1. **Sync main:** `git checkout main && git pull --ff-only`.
2. **Branch:** `git checkout -b feat/fr-033-response-body-content-filter`.
3. **Stage all FR-033 changes** with explicit add (no `git add .`):
   ```
   git add crates/waf-common/src/types.rs
   git add crates/waf-common/src/lib.rs
   git add crates/gateway/src/filters/response_body_decompressor.rs
   git add crates/gateway/src/filters/response_body_content_scanner.rs
   git add crates/gateway/src/filters/mod.rs
   git add crates/gateway/src/context.rs
   git add crates/gateway/src/proxy.rs
   git add crates/gateway/Cargo.toml
   git add crates/gateway/tests/response_body_content_scanner_integration.rs
   git add docs/system-architecture.md
   git add docs/codebase-summary.md
   git add crates/gateway/CLAUDE.md
   ```
4. **Local CI gate** (must all pass):
   ```
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace
   cargo build --release
   ```
   If any fail → fix → restage. Do NOT proceed with failures.
5. **Conflict probe (read-only):**
   ```
   git fetch origin pull/14/head:pr-14-probe
   git fetch origin pull/18/head:pr-18-probe
   git merge-tree $(git merge-base HEAD pr-14-probe) HEAD pr-14-probe > /tmp/probe-pr14.txt
   git merge-tree $(git merge-base HEAD pr-18-probe) HEAD pr-18-probe > /tmp/probe-pr18.txt
   ```
   Read each file; expected non-zero conflict markers ONLY at:
   - PR 14: `crates/gateway/src/proxy.rs` response_filter region (header decisions adjacent — should be co-existable; verify by hand)
   - PR 18: `crates/waf-common/src/types.rs` HostConfig field-append region; `crates/gateway/src/proxy.rs` response_body_filter chain region; `crates/gateway/src/context.rs` BodyXxxState append region
   - Document any unexpected conflict in PR body.
   - Delete probe branches: `git branch -D pr-14-probe pr-18-probe`.
6. **Single commit:**
   ```
   git commit -m "$(cat <<'EOF'
   feat(outbound): FR-033 response body content filtering

   Add built-in detector catalog (stack traces, verbose errors, secrets,
   internal IPs) over identity and decompressed (gzip/deflate/br) upstream
   response bodies. Per-host action choice: mask or block. ReDoS-safe via
   aho_corasick literals + anchored RegexSet; bomb-safe via bounded reader
   plus ratio guard. Coexists with AC-17 operator regex and the FR-034
   JSON-field redactor.

   Closes nothing on its own; satisfies analysis/requirements.md FR-033.
   EOF
   )"
   ```
7. **Push:** `git push -u origin feat/fr-033-response-body-content-filter`.
8. **Open PR via `gh`:**
   ```
   gh pr create --base main --title "feat(outbound): FR-033 response body content filtering" --body "$(cat <<'EOF'
   ## Summary
   - Built-in detector catalog: stack traces (Java/Python/Rust/Go/PHP/Node/.NET), verbose errors (SQL/file paths/framework markers/ORM), secrets (AWS/GCP/Slack/GitHub/Stripe/JWT/private key blocks), internal IPs (RFC-1918/ULA/link-local/loopback)
   - Body decompression for gzip, deflate, br with bomb defense (output cap + ratio guard)
   - Per-host action: Mask (replace match span with token) or Block (replace remaining body with neutral 502 page)
   - ReDoS-safe by construction: aho_corasick for literal multipattern, anchored RegexSet for format-based secrets, direct byte parse for IP CIDR classification
   - Coexists with AC-17 operator regex and PR #18 JSON field redactor; chain order: redact → scan → mask

   ## Reference
   - analysis/requirements.md line 73 (FR-033)
   - Plan: plans/260428-2311-fr-033-response-body-content-filter/

   ## Cross-PR coordination
   - PR #14 (FR-035 header leak prevention): no shared file changes; safe to merge in either order
   - PR #18 (FR-034 JSON field redaction): textual conflicts on
     - crates/waf-common/src/types.rs (HostConfig field append — both PRs append fields; resolve by keeping both blocks)
     - crates/gateway/src/proxy.rs response_body_filter (call ordering — final order: redact (#18) → scan (this PR) → mask (AC-17))
     - crates/gateway/src/context.rs (state struct append — keep both)
     Recommended merge order: #18 first, then this PR (so this PR's response_body_filter insertion lands at the documented position).

   ## Test coverage
   - 9 decompressor unit tests (gzip/deflate/brotli round-trip, unknown encoding, reverse chain, output cap, ratio cap, identity passthrough)
   - 26 scanner unit tests (4 categories × positive/negative, FP suppression for 127.0.0.1 / Stripe sig / AWS pre-signed URL, mask vs block action, chunk-boundary straddle, byte ceiling, invalid extra pattern fail-open, category opt-in)
   - 7 integration tests in tests/response_body_content_scanner_integration.rs (full chain, gzip block, brotli mask, deflate IP allowlist, decompression bomb fail-open, chunk split secret, unknown encoding fail-open)
   - Scoped llvm-cov ≥ 95% on new files

   ## Out of scope (deferred)
   - Per-route policy DSL
   - zstd / lz4 decompression
   - HTML-aware sanitization
   - Multi-language stack-trace ML classifier
   - Encrypted body decryption
   - Header-level scanning (FR-035 / PR #14 owns)
   - True 502 status code on Block action: status is locked at response_filter time but match decision happens at response_body_filter time, so Block currently replaces body only and leaves upstream status code on the wire. Documented limitation; status-locking refactor deferred.

   ## Test plan
   - [x] cargo fmt --all -- --check
   - [x] cargo clippy --workspace --all-targets --all-features -- -D warnings
   - [x] cargo test --workspace
   - [x] cargo build --release
   - [x] llvm-cov ≥ 95% on new files
   - [ ] Reviewer verifies neutral block page renders (no Pingora fingerprint)
   - [ ] Reviewer confirms HostConfig serde defaults preserve existing host configs unchanged
   EOF
   )"
   ```
9. **Verify:** `gh pr view --json state,statusCheckRollup` — ensure CI green or pending; address any failure.

## Todo List
- [ ] `git checkout main && git pull --ff-only`
- [ ] `git checkout -b feat/fr-033-response-body-content-filter`
- [ ] Explicit `git add` of FR-033 files only (no `.`, no `-A`)
- [ ] `cargo fmt --all -- --check` green
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` green
- [ ] `cargo test --workspace` green
- [ ] `cargo build --release` green
- [ ] Scoped `cargo llvm-cov` ≥ 95% on new files
- [ ] PR 14 conflict probe → record findings
- [ ] PR 18 conflict probe → record findings
- [ ] Single-commit conventional message (no AI references)
- [ ] `git push -u origin feat/fr-033-response-body-content-filter`
- [ ] `gh pr create` with structured body (above)
- [ ] `gh pr view` confirm CI status
- [ ] Return PR URL in completion message

## Success Criteria
- PR opened against `main` with all listed sections.
- Local CI gates all pass before push.
- Conflict probe results documented in PR body.
- No `--no-verify` flag used.
- Single commit, conventional message, no AI-derived language.

## Risk Assessment
- **PR 18 lands first changes our insertion site** (Likelihood: High, Impact: Low): rebase brings in the redact call; we re-apply our scan call between redact and mask. Resolution mechanical.
- **PR 14 lands first changes header drop region** (Likelihood: Medium, Impact: Low): both PRs only mutate response headers via `remove_header`, idempotent. Resolution mechanical.
- **CI flake** (Likelihood: Low, Impact: Low): retry once via `gh pr checks --watch`; if persistent → investigate before merging.

## Security Considerations
- No secrets in commit / PR body. Reviewers verify the `examples-only` AWS-key-shaped strings in test fixtures are syntactically invalid (deliberately wrong checksum / AKIA prefix `FAKE`).
- No `.env`, no credential files staged (explicit `git add` defends).
- `--no-verify` BANNED per CLAUDE.md.

## Next Steps
- Post-merge: write follow-up ticket for header-level scanning + true-502 Block-action refactor + zstd support.
