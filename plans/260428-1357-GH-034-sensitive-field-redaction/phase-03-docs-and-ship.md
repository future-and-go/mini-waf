# Phase 03 — Docs Sync + Commits + PR

**Goal:** Land docs, mark roadmap, commit cleanly, push, open PR against `main`. No code changes (other than minor TOML / sample edits).

**Status:** todo
**Depends on:** Phase 01 + Phase 02 both green in the dev container.

## Files Touched

| File | Change |
|------|--------|
| `configs/default.toml` | If sample HostConfig blocks exist, add commented `redact_*` fields to the AC-17 block as documentation example. If no host block exists, **skip this file entirely** — the fields are per-host and TOML doesn't carry a global default for them. |
| `docs/system-architecture.md` | Add subsection under outbound protection covering FR-034 (mirrors AC-17 paragraph) |
| `docs/project-changelog.md` | Top-of-list entry for FR-034 |
| `docs/project-roadmap.md` | Flip FR-034 row from `MISSING` / `PLANNED` → `COMPLETE` and link the PR (placeholder filled after PR creation) |
| `crates/gateway/CLAUDE.md` | Append a one-paragraph "Response body sensitive-field redaction (FR-034)" section parallel to the existing "AC-17" paragraph |

## 1. `configs/default.toml`

Inspect first:

```bash
grep -nA5 'internal_patterns\|mask_token\|body_mask_max_bytes' configs/default.toml
```

If the file has a per-host sample block referencing the AC-17 fields, add the FR-034 fields commented out next to it. **Do not** add a `[outbound.body_redactor]` global stanza — there is no `OutboundConfig` on main; that was a v1 hallucination.

If no per-host TOML sample exists (likely — hosts come from PostgreSQL on main), **skip this file.** Document the fields in `docs/system-architecture.md` instead.

## 2. `docs/system-architecture.md`

Find the existing AC-17 paragraph. Add a sibling subsection:

```markdown
#### FR-034 — Sensitive Field Redaction in Response JSON Bodies

Per-host JSON field redactor. When `HostConfig::redact_*` family toggles are
on, JSON values whose keys match a hard-coded family catalog (PCI, banking,
identity, secrets, PII, PHI) are replaced with `redact_mask_token` (default
`***REDACTED***`). Field-name catalogs live in
`gateway::filters::response_json_field_redactor`; activation is per-host via
`HostConfig` fields. Operators extend the catalog with `redact_extra_fields[]`.

Hook: Pingora `response_body_filter`, dispatched directly from
`WafProxy::response_body_filter`. Buffers chunks until `end_of_stream` (or
`redact_max_bytes` cap, default 256 KiB), then parses with `serde_json`,
walks the `Value` tree, replaces matched values, re-serialises, and emits
the full body. Composes with AC-17: FR-034 runs first; AC-17 then masks
internal-ref patterns over the redacted output.

Skip conditions: non-identity Content-Encoding (compressed body — out of
scope), non-JSON Content-Type, noop redactor (no families on, no extras).
Failure mode: fail-open with `tracing::warn!` on cap overflow / malformed
JSON / serde error. Defaults all OFF — zero behaviour change for hosts that
don't opt in.

References: PCI-DSS Req 3.4, HIPAA §164.514, OWASP API3:2023, CWE-200.
Plan: `plans/260428-1357-GH-034-sensitive-field-redaction/`.
```

## 3. `docs/project-changelog.md`

Top-of-list entry under "Unreleased":

```markdown
- **FR-034 — Sensitive field redaction in JSON response bodies** (per-host).
  Six detection families (PCI, banking, identity, secrets, PII, PHI)
  hard-coded in `gateway::filters::response_json_field_redactor`; per-host
  activation via `HostConfig::redact_*` fields. Composes with AC-17 body
  masker — FR-034 runs first, AC-17 over the redacted bytes. Disabled by
  default per host. 256 KiB body cap; skips compressed and non-JSON
  responses. Pingora `response_body_filter` hook.
```

## 4. `docs/project-roadmap.md`

Find the FR-034 row. Flip status → `COMPLETE`. Add PR link (placeholder during commit, fill after PR creation):

```markdown
| FR-034 | Outbound | Sensitive field redaction | COMPLETE — PR #<NN> |
```

## 5. `crates/gateway/CLAUDE.md`

After the existing AC-17 paragraph (currently around lines 15-31), append:

```markdown
## Response body sensitive-field redaction (FR-034)

`response_body_filter` also runs a JSON field-name redactor (see
`filters/response_json_field_redactor.rs`) per host. Active families and
extras come from `HostConfig::{redact_pci, redact_banking, redact_identity,
redact_secrets, redact_pii, redact_phi, redact_extra_fields, redact_mask_token,
redact_max_bytes, redact_case_insensitive}`.

Composes with AC-17: FR-034 runs first, buffering chunks until EOS (or
`redact_max_bytes`), parsing, redacting, then emitting the full body. AC-17
runs over the FR-034 output. When FR-034 is buffering, `*body` is set to
`None` so AC-17 sees nothing.

Skip conditions match AC-17 (non-identity Content-Encoding) plus a JSON
Content-Type gate (only `application/json` and `application/*+json` —
`text/event-stream` and `application/x-ndjson` rejected). Fail-open on cap
overflow / malformed JSON.
```

## 6. Conventional Commits (3 commits)

Branch is already `feat/fr-034-response-field-redaction` (created earlier in this session, off `origin/main`). Working tree must be clean (no `.kiro/`, `.opencode/`, `.gitnexus/`, `.dockerignore`, `package*.json`, `TODO.md` staged — those are session/IDE artifacts; `.gitignore` should already cover them, but verify).

```bash
git status -s
# Expected staged-only files:
#   crates/waf-common/src/types.rs
#   crates/gateway/src/filters/response_json_field_redactor.rs (new)
#   crates/gateway/src/filters/mod.rs
#   crates/gateway/src/context.rs
#   crates/gateway/src/proxy.rs
#   crates/gateway/Cargo.toml         (if serde_json was added)
#   crates/gateway/tests/response_json_field_redactor_integration.rs (new)
#   docs/system-architecture.md
#   docs/project-changelog.md
#   docs/project-roadmap.md
#   crates/gateway/CLAUDE.md
#   plans/260428-1357-GH-034-sensitive-field-redaction/  (untracked OK to commit, or leave untracked per .gitignore — verify with team)
```

### Commit 1 — config + filter logic

```bash
git add crates/waf-common/src/types.rs \
        crates/gateway/src/filters/response_json_field_redactor.rs \
        crates/gateway/src/filters/mod.rs \
        crates/gateway/Cargo.toml
git commit -m "feat(outbound): add JSON body field redactor (FR-034)

Per-host JSON response-body redactor. Six family toggles
(redact_pci/banking/identity/secrets/pii/phi) plus operator extras and
mask token on HostConfig. Hard-coded field-name catalogs in
gateway::filters::response_json_field_redactor. Recursive serde_json
walker; case-insensitive matching by default. 256 KiB hard cap;
fail-open on parse error or oversize. 21 unit tests."
```

### Commit 2 — gateway wiring + integration tests

```bash
git add crates/gateway/src/context.rs \
        crates/gateway/src/proxy.rs \
        crates/gateway/tests/response_json_field_redactor_integration.rs
git commit -m "feat(gateway): wire JSON redactor into response_body_filter

BodyRedactState added to GatewayCtx; per-host CompiledRedactor cache
mirrors AC-17 body_mask_cache. Decision in response_filter
(identity-encoding + JSON content-type + non-noop). Apply in
response_body_filter BEFORE AC-17 mask — FR-034 buffers until EOS,
emits redacted body, AC-17 then runs over it. 7 integration tests
including AC-17 composition."
```

### Commit 3 — docs

```bash
git add docs/system-architecture.md \
        docs/project-changelog.md \
        docs/project-roadmap.md \
        crates/gateway/CLAUDE.md \
        plans/260428-1357-GH-034-sensitive-field-redaction/
git commit -m "docs(fr-034): system architecture, changelog, roadmap, plan

Document the per-host redactor + AC-17 composition in
docs/system-architecture.md. Changelog entry. Roadmap row flipped
to COMPLETE. CLAUDE.md note for the gateway crate. Planning
artefacts under plans/."
```

**Commit message rules** (per project-level instructions):
- Conventional prefix (`feat:`, `fix:`, `docs:`, etc.) — but NOT `chore:` or `docs:` for changes to `.claude/` (none in this PR).
- No mention of agent / model / "Claude" / "generated" / prompt / PAT / TODO.md content.
- Author voice: developer, present tense.

## 7. Push & Open PR

```bash
git push -u origin feat/fr-034-response-field-redaction
```

PR body authored as a developer would:

```bash
GH_TOKEN="$PRX_WAF_PAT" gh pr create \
  --base main \
  --head feat/fr-034-response-field-redaction \
  --title "feat: FR-034 sensitive field redaction in response JSON bodies" \
  --body "$(cat <<'EOF'
## Summary

Per-host JSON response-body redactor that masks values whose keys are in a
configurable catalog (PCI, banking, identity, secrets, PII, PHI). Mirrors
the existing AC-17 body-mask filter pattern: per-host fields on `HostConfig`,
compiled cache on `WafProxy`, streaming dispatch from `response_body_filter`.
Composes with AC-17 — FR-034 runs first, AC-17 over the redacted output.

## What's in

- `HostConfig` gains 10 fields (6 family toggles + extras + mask token + cap + case flag).
- New filter `gateway::filters::response_json_field_redactor` with hardcoded
  family catalogs, recursive `serde_json::Value` walker, 21 unit tests.
- `BodyRedactState` in `GatewayCtx`. `body_redact_cache` on `WafProxy`.
- `response_filter` decides enable; `response_body_filter` runs FR-034 then
  AC-17.
- 7 integration tests including the AC-17 composition path.
- Defaults all OFF — zero behaviour change for hosts that don't opt in.

## What's out (deferred)

- FR-033 — response *value* scanning for stack traces / API keys.
- Compressed-body redaction (decompress / recompress / force `Accept-Encoding: identity`).
- JSONPath / nested-path field rules.
- Type-preserving mask (current: collapse all matched values to JSON string).
- Partial masking (e.g. \`****-****-****-1234\`).

## Standards

PCI-DSS Req 3.4, HIPAA §164.514, OWASP API3:2023, CWE-200.

## Test plan

- [x] \`cargo fmt --all -- --check\` clean (containerised)
- [x] \`cargo clippy --workspace --all-targets --all-features -- -D warnings\` clean (containerised)
- [x] \`cargo test --workspace\` green (containerised) — 21 unit + 7 integration tests added
- [x] \`cargo build --release\` green (containerised)
- [x] Manual: backend returning JSON with \`card_number\` → client sees \`***REDACTED***\` when \`redact_pci=true\`, raw value when host has \`redact_pci=false\` (default)
- [x] Manual: backend returning gzipped JSON → bytes pass through unchanged (\`tracing::debug!\` once)
- [x] Manual: SSE endpoint (\`text/event-stream\`) → no buffering, no behavioural change
EOF
)"
```

**Token-handling rules:**
- `$PRX_WAF_PAT` must be set in shell env before running. Set it with `read -s PRX_WAF_PAT && export PRX_WAF_PAT` so it doesn't echo to the terminal or land in `~/.zsh_history`. NEVER paste the token directly into the command line.
- After the PR is open, `unset PRX_WAF_PAT`.
- The PR body above contains zero references to agents, prompts, or sensitive content — verify by reading `gh pr view --web` once the PR is created.

## 8. Final Verification

```bash
gh pr view --web   # confirm body renders, nothing leaks
gh pr checks       # CI status
```

Update `plan.md` frontmatter:
- `status: completed`
- `completed: <iso-date>`
- `target_pr: <PR URL>`

Update `docs/project-roadmap.md` FR-034 row with the PR URL (replace `<NN>` placeholder).

## Rollback Plan

- **Revert PR** if CI fails / dogfood regression: `gh pr revert` → single revert commit.
- **Operational disable**: every host has `redact_*=false` by default; ops just leaves the toggle off. No runtime intervention required for hosts that already opted in (revert removes the field; existing TOMLs / DB rows ignore the gone field on re-load).

## Success Criteria

- Three commits on `feat/fr-034-response-field-redaction`.
- Branch pushed.
- PR open against `main` with clean description (verified).
- CI green.
- `plan.md` updated with PR URL and `status: completed`.
- `gitnexus_detect_changes()` confirms changeset matches Phase 01 + 02 expectations.

## Out of Scope (Phase 03)

- Auto-merge.
- Squash policy decisions (left to reviewer).
- Backporting to other branches.
- Performance benchmarking under load (deferred).
