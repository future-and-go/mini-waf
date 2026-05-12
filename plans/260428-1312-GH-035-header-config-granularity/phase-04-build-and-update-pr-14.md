# Phase 04 — Build, Commit, Push, Update PR 14

**Status:** completed
**Owner:** main agent
**Effort:** S

## Goal

Land the change on `feat/fr-035-header-leak-prevention` with clean human-style commits and refresh the PR 14 description so reviewers can see what changed since the last push.

## Pre-flight

- [ ] On branch `feat/fr-035-header-leak-prevention` (already current).
- [ ] `git status` — only files touched by phases 01-03 modified.
- [ ] `cargo fmt --all -- --check` clean.
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- [ ] `cargo build --release` clean.
- [ ] `cargo test -p waf-engine outbound::` green.

## Commits

Two focused commits — keep blast radius readable:

1. `feat(outbound): per-header preserve allowlist for FR-035 filter`
   - Files: `crates/waf-common/src/config.rs` (HeaderFilterConfig fields), `crates/waf-engine/src/outbound/header_filter.rs` (preserve precedence in `should_strip`), `crates/waf-engine/src/outbound/mod.rs` (error type if added in this commit), `crates/gateway/src/proxy.rs` (fallible builder call site), `configs/default.toml` (commented allowlist examples), tests for tests 1–6.
2. `feat(outbound): tunable PII patterns and scan cap for FR-035 filter`
   - Files: `crates/waf-common/src/config.rs` (PiiConfig), `crates/waf-engine/src/outbound/header_filter.rs` (filtered pattern build, runtime cap), `configs/default.toml` (commented `[outbound.headers.pii]` block), tests 7–12.

Use HEREDOC commit messages with no AI / prompt / token references. Conventional-commits style.

## Push

```bash
git push origin feat/fr-035-header-leak-prevention
```

PR 14 auto-updates from the push.

## PR 14 Description Update

Update PR 14 description (do **not** rewrite history) to add a new section listing the granular-config additions. Keep tone matter-of-fact, no AI-author markers, no prompt residue, no credentials.

Sketch:

```markdown
### v3 — Granular operator config (this push)

Address review note: per-family `true/false` toggles were too coarse — operators
need to keep specific built-in headers and tune PII detection.

Adds, all backward-compatible (`#[serde(default)]`):

- `outbound.headers.preserve_headers` / `preserve_prefixes`
  → Allowlist that beats every strip rule (except CRLF & hop-by-hop). Use to
    keep specific built-in headers your application legitimately needs.
- `[outbound.headers.pii]` table:
  - `disable_builtin` — drop named built-in patterns (validated; unknown → error).
  - `extra_patterns` — operator-supplied regexes, compiled at startup.
  - `max_scan_bytes` — previously hard-coded `MAX_PII_SCAN_LEN = 8192`, now tunable.
- `HeaderFilter::new` → `HeaderFilter::try_new(&cfg) -> Result<Self, OutboundConfigError>`.
  Gateway logs and disables the filter on construction error (fail-safe).

Tests: +12 unit tests covering preserve precedence, CRLF / hop-by-hop interaction,
PII disable / extras / cap. Existing 30+ tests unchanged.

Default-config behaviour is bit-for-bit identical to the previous push.
```

Use the GitHub CLI for the edit (the user's PAT is set in their environment; the
agent **must not** persist any token to disk or include it in any commit, plan,
log, or comment):

```bash
# Authenticate via env var only (do not write to ~/.gitconfig or ~/.netrc).
GH_TOKEN="$GH_TOKEN" gh pr edit 14 \
  --repo future-and-go/mini-waf \
  --body-file /tmp/pr14-body.md
```

Where `/tmp/pr14-body.md` is the previous body + the new "v3 — Granular operator
config" section appended. Fetch the current body first with
`gh pr view 14 --repo future-and-go/mini-waf --json body --jq .body > /tmp/pr14-body.md`,
then append the new section.

## Todo

- [ ] All pre-flight checks green
- [ ] Commit 1 — preserve allowlist
- [ ] Commit 2 — PII tuning
- [ ] `git push origin feat/fr-035-header-leak-prevention`
- [ ] Fetch current PR 14 body
- [ ] Append "v3 — Granular operator config" section
- [ ] `gh pr edit 14 --body-file ...`
- [ ] Verify PR 14 page shows new commits + updated body
- [ ] `rm /tmp/pr14-body.md` (no body/secrets left in tmp)

## Success Criteria

- Two commits on `feat/fr-035-header-leak-prevention`, conventional-commit style, no AI markers, no token leakage.
- PR 14 shows updated body and new commits in the timeline.
- CI green on the branch.

## Risk

- Token leakage in commit / PR body / commit metadata. **Mitigation:** never write `GH_TOKEN` to a file; pass via env var only; `git config user.email` / `user.name` already set to the user's real identity (verify before commit with `git config user.email`).
- PR body overwrite losing prior context. **Mitigation:** fetch existing body first, append, never replace.
- Branch divergence with origin. **Mitigation:** `git pull --ff-only origin feat/fr-035-header-leak-prevention` before push; if non-FF, stop and ask the user.

## Notes

- The user's GitHub PAT is provided through their shell session; this plan
  intentionally does not record or echo it.
- Commit messages must read like a human authored them — no "Generated by",
  no "Claude", no prompt fragments, no model names.
