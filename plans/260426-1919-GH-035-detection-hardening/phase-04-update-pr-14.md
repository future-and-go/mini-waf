# Phase 04 — Build, Commit, Push, Update PR 14

**Priority:** P0
**Status:** pending
**Depends on:** phase-03 (all tests green)

## Goal

Run only after the user approves the plan AND phases 01-03 are complete with green tests. Push the enhancement to the existing branch `feat/fr-035-header-leak-prevention`. Because PR 14 already tracks that branch, the push automatically updates the PR — no `gh pr create` needed. Update the PR description to list the new families & CVE attribution.

## Pre-flight

- [ ] `cargo fmt -p waf-common -p waf-engine -p gateway -- --check` clean
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean
- [ ] `cargo test -p waf-engine outbound::` — ≥ 31 / 31 green
- [ ] `cargo build --release -p prx-waf` succeeds
- [ ] `git status` shows only intended files
- [ ] No secrets, prompts, AI references, or tokens anywhere in diff or commit message

## Privacy Guard (mandatory — TODO.md instruction)

The user supplied a GitHub PAT inline in `TODO.md`. We treat that token as **redacted** for all artifacts:

- Commit message: no token, no prompts, no AI references, no planner context
- PR body: same constraint
- File contents: same constraint
- Branch / tag names: same constraint

The token is used at most via `gh` CLI environment if `gh auth status` is unavailable; never echoed, never written to disk in this repo.

After merge, the user should rotate the PAT.

## Branch & Commit

Branch already exists locally and on origin: `feat/fr-035-header-leak-prevention`. Just stack a new commit on top.

Commit message (conventional, neutral, no AI / planning references):

```
feat(outbound): expand FR-035 detection — vendor fingerprints, hardening

Add CVE-attributed detection cases for PHP, ASP.NET, Drupal, Spring,
WordPress, Magento, and CDN fingerprints; each gated by a config toggle.
Harden the filter against CRLF response splitting (CWE-93) and ReDoS via
an 8 KiB cap on PII regex input. Pin RFC 9110 §7.6.1 hop-by-hop headers
to a never-strip allowlist. Extend PII patterns with AWS / Google / Slack
/ GitHub token shapes.

- HeaderFilterConfig: +strip_php_fingerprint, +strip_aspnet_fingerprint,
  +strip_framework_fingerprint, +strip_cdn_internal (off by default)
- header_filter.rs: 5 new const lists, 4 new PII patterns, CRLF guard,
  hop-by-hop allowlist, MAX_PII_SCAN_LEN = 8192
- 12+ new unit tests citing the CVE / incident class they guard against
- configs/default.toml: append new toggles to the [outbound.headers] block

Refs: CVE-2024-4577, CVE-2017-7269, CVE-2014-3704, CVE-2018-7600,
CVE-2022-22965, CVE-2017-1000026; CWE-93, CWE-200, CWE-209;
OWASP ASVS V14.4; RFC 9110 §5.5, §7.6.1.
```

## Steps

1. **Verify branch & up-to-date:**
   ```bash
   git status
   git rev-parse --abbrev-ref HEAD          # must be feat/fr-035-header-leak-prevention
   git fetch origin
   git log --oneline origin/feat/fr-035-header-leak-prevention..HEAD
   ```

2. **Stage explicitly** — never `git add -A`:
   ```bash
   git add crates/waf-common/src/config.rs
   git add crates/waf-engine/src/outbound/header_filter.rs
   git add configs/default.toml
   git add docs/system-architecture.md     # only if doc edits made; phase-01 does not require
   ```
   Do NOT stage anything in `plans/` for this commit (planning artifacts stay untracked or in a separate commit if user wants them in repo). Confirm with user before deciding.

3. **Confirm staged set:**
   ```bash
   git diff --cached --stat
   ```

4. **Commit** via HEREDOC (CLAUDE.md format rule):
   ```bash
   git commit -m "$(cat <<'EOF'
   feat(outbound): expand FR-035 detection — vendor fingerprints, hardening

   Add CVE-attributed detection cases for PHP, ASP.NET, Drupal, Spring,
   WordPress, Magento, and CDN fingerprints; each gated by a config toggle.
   Harden the filter against CRLF response splitting (CWE-93) and ReDoS via
   an 8 KiB cap on PII regex input. Pin RFC 9110 §7.6.1 hop-by-hop headers
   to a never-strip allowlist. Extend PII patterns with AWS / Google / Slack
   / GitHub token shapes.

   - HeaderFilterConfig: +strip_php_fingerprint, +strip_aspnet_fingerprint,
     +strip_framework_fingerprint, +strip_cdn_internal (off by default)
   - header_filter.rs: 5 new const lists, 4 new PII patterns, CRLF guard,
     hop-by-hop allowlist, MAX_PII_SCAN_LEN = 8192
   - 12+ new unit tests citing the CVE / incident class they guard against
   - configs/default.toml: append new toggles to the [outbound.headers] block

   Refs: CVE-2024-4577, CVE-2017-7269, CVE-2014-3704, CVE-2018-7600,
   CVE-2022-22965, CVE-2017-1000026; CWE-93, CWE-200, CWE-209;
   OWASP ASVS V14.4; RFC 9110 §5.5, §7.6.1.
   EOF
   )"
   ```

5. **If pre-commit hook fails:** fix root cause, re-stage, NEW commit (never `--amend`).

6. **Push:**
   ```bash
   git push origin feat/fr-035-header-leak-prevention
   ```
   PR 14 auto-updates with the new commit.

7. **Update PR 14 description** to reflect the new content. Use `gh pr edit 14 --body-file <(...)` or `gh pr comment 14`.

   Recommendation: **append a "Update — Detection Hardening" section** to the existing PR body rather than rewriting it (preserves review history). Body addition:

   ```markdown
   ---
   ## Update — Detection Hardening (commit 2 of branch)

   Adds CVE-attributed detection cases on top of the base FR-035 filter:

   | Family toggle | Default | Sample headers | Reference |
   |---------------|---------|----------------|-----------|
   | `strip_php_fingerprint` | true | X-PHP-Version | CVE-2024-4577 |
   | `strip_aspnet_fingerprint` | true | X-AspNet-Version, X-SourceFiles | CVE-2017-7269 |
   | `strip_framework_fingerprint` | true | X-Drupal-Cache, X-Application-Context, X-Pingback, X-Magento-* | CVE-2014-3704, CVE-2018-7600, CVE-2022-22965 |
   | `strip_cdn_internal` | false | X-Varnish, X-Amz-Cf-Id, X-Akamai-* | CDN topology disclosure |

   Hardening:
   - CRLF in any header value → strip + warn (CWE-93 / CVE-2017-1000026)
   - Hard 8 KiB cap on PII regex input (closes ReDoS surface)
   - RFC 9110 §7.6.1 hop-by-hop headers pinned to never-strip allowlist
   - PII patterns extend to AWS / Google API / Slack / GitHub token shapes

   Tests: +12 unit tests, each cites the CVE / incident class it guards.
   Behaviour with `outbound.enabled = false` is unchanged (no overhead).
   ```

   Command:
   ```bash
   # Read current body, append section, write back
   gh pr view 14 --json body --jq .body > /tmp/pr14-body.md
   cat >> /tmp/pr14-body.md <<'EOF'
   ... (section above)
   EOF
   gh pr edit 14 --body-file /tmp/pr14-body.md
   ```

8. **Verify** PR is still mergeable:
   ```bash
   gh pr view 14 --json mergeStateStatus,mergeable,statusCheckRollup
   ```

9. **Surface PR URL** back to user: <https://github.com/future-and-go/mini-waf/pull/14>

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Push rejected (out-of-date origin) | `git fetch origin && git rebase origin/feat/fr-035-header-leak-prevention` if conflict surfaces |
| `gh` not authenticated | Try existing `gh auth status` first; fall back to `GH_TOKEN` env var (never persist) |
| PR description rewrite loses prior review comments | Append, don't replace |
| CI fails post-push (clippy / fmt drift on a different file) | Pre-flight runs full workspace clippy locally — fix before push, never `--no-verify` |
| Commit message accidentally contains AI-generated phrasing or planning slug | Manual review of HEREDOC before commit; commit shown above is final wording |

## Success Criteria

- [ ] New commit on branch `feat/fr-035-header-leak-prevention`
- [ ] PR 14 picks up the commit (auto-tracking)
- [ ] PR 14 description has the "Detection Hardening" section appended
- [ ] `gh pr view 14` shows `mergeStateStatus = CLEAN`, all checks green
- [ ] No tokens, prompts, or AI references anywhere in diff / commit / PR body

## Post-merge (informational)

- User rotates the PAT supplied in `TODO.md`
- Mark this plan `status: completed` in `plan.md` frontmatter
- Update `docs/project-roadmap.md` FR-035 entry with "v0.2.1 — hardening" line
- Run `npx gitnexus analyze` to refresh symbol index

## Notes

- **Do NOT execute** until phase-03 is green and user explicitly approves the plan.
- Keep commit count low — single commit covering phases 01-03 is the cleanest review story for the existing PR.
