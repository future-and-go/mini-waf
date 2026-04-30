# Phase 08 — Docs & Sample Config

## Context Links
- Design: brainstorm §5 (schema), §11 step 4 ("update tiered-protection.md")
- Existing docs index: `docs/`

## Overview
**Priority:** P1 · **Status:** pending · **Effort:** 0.25 d

Ship operator docs + a checked-in sample YAML so the feature is usable on day one of code-freeze week. Cross-link from `docs/tiered-protection.md` so the FR-002 reader sees the new `tier_whitelist_mode` field.

## Key Insights
- Single new doc: `docs/access-lists.md`. ≤ 800 LoC per project doc cap.
- Update `docs/codebase-summary.md` and `docs/development-roadmap.md` per project rule "After Feature Implementation".
- Sample YAML lives under `rules/access-lists.yaml` — same directory pattern as other rule files.

## Requirements

### Functional
- `docs/access-lists.md` covers: schema, semantics, hot-reload, dry-run, examples (allow / block / per-tier mode), caveats (XFF, port-stripping), troubleshooting (parse errors, locked-out scenario).
- `rules/access-lists.yaml` is a working starter file — empty lists / disabled by default (D4 demonstration).
- Cross-references added to:
  - `docs/tiered-protection.md` — section "Per-tier whitelist mode" linking to `access-lists.md`.
  - `docs/codebase-summary.md` — entry under `crates/waf-engine` for the `access` module.
  - `docs/development-roadmap.md` — mark FR-008 status (pending → in-progress at start of impl, complete at merge).

### Non-functional
- Doc readable by an SRE who has never used this WAF — concrete YAML examples, copy-paste curl reproductions.

## Architecture (doc structure)

```
docs/access-lists.md
├── Overview (D1, D6 — Phase-0 short-circuit)
├── YAML schema (verbatim from brainstorm §5)
├── Decision order (Host → Blacklist → Whitelist)
├── Per-tier whitelist mode (Strategy: full_bypass vs blacklist_only)
├── Hot-reload (file save + SIGHUP)
├── Dry-run mode (would-block log without blocking)
├── Operational caveats
│   ├── XFF / client_ip resolution (until FR-007)
│   ├── Host header port suffix handling
│   └── Caps (50 k WARN, 500 k bail)
├── Troubleshooting
│   ├── "all my prod traffic 403'd" → check host_whitelist deny-by-default
│   ├── "reload didn't take effect" → check WARN logs for parse errors
│   └── "blacklisted IP still hitting backend" → ensure access_lists wired in proxy.rs
└── Audit-log fields (access_decision, access_reason, access_match)
```

## Related Code Files

### Create
- `docs/access-lists.md` (≤ 600 LoC target)
- `rules/access-lists.yaml` (sample — all gates disabled by default)

### Modify
- `docs/tiered-protection.md` — add cross-link section.
- `docs/codebase-summary.md` — append `access` module entry.
- `docs/development-roadmap.md` — update FR-008 row.
- `docs/project-changelog.md` — add entry for FR-008 ship.

## Implementation Steps

1. **Draft `docs/access-lists.md`** following the structure above. For each section, include:
   - **Why** (the decision behind it — pull from brainstorm §2 D-table).
   - **How** (YAML snippet + 1-line explanation).
   - **Common mistake** (lifted from brainstorm §9).
2. **Sample `rules/access-lists.yaml`**:
   ```yaml
   version: 1
   dry_run: false

   # All-empty default — gate is OFF until you populate it.
   ip_whitelist: []
   ip_blacklist: []

   host_whitelist:
     critical:  []
     high:      []
     medium:    []
     catch_all: []

   tier_whitelist_mode:
     critical:  blacklist_only
     high:      blacklist_only
     medium:    full_bypass
     catch_all: full_bypass
   ```
3. **Cross-links** in `docs/tiered-protection.md`:
   ```markdown
   ### Access lists (FR-008)
   Each tier carries a `whitelist_mode` flag that controls how IP-whitelist hits
   are treated. See [`access-lists.md`](./access-lists.md#per-tier-whitelist-mode).
   ```
4. **Update `docs/codebase-summary.md`** with one line under waf-engine:
   ```
   - `access/` — FR-008 IP/host whitelist + blacklist (Phase-0 gate, ArcSwap reload).
   ```
5. **Roadmap & changelog**: add FR-008 milestone row + changelog entry on PR merge (`docs-manager` agent does this — call out in PR description).

## Todo List
- [ ] Write `docs/access-lists.md`
- [ ] Add `rules/access-lists.yaml` empty-but-valid sample
- [ ] Cross-link section in `docs/tiered-protection.md`
- [ ] Append entry in `docs/codebase-summary.md`
- [ ] Update `docs/development-roadmap.md` FR-008 row
- [ ] Add `docs/project-changelog.md` entry on merge
- [ ] Verify all internal links resolve (`grep -nR "access-lists.md" docs/`)

## Success Criteria
- Operator can read `docs/access-lists.md` and configure the feature without reading code.
- All internal markdown links resolve.
- Roadmap reflects current status.

## Common Pitfalls
- **Stale schema in doc vs code**: keep YAML examples in `docs/` and `rules/access-lists.yaml` byte-identical for the schema portion. A future schema change must update both — flag this in the file header.
- **Forgetting changelog**: project rule. `docs-manager` agent invocation must be part of the PR checklist.
- **Doc bloat**: 800-LoC project cap. Trim narrative; keep examples.

## Risk Assessment
- Very low.

## Security Considerations
- Sample YAML must NOT contain real internal IPs or hostnames — use TEST-NET-3 (`203.0.113.0/24`) and `example.com` only.

## Next Steps (post-merge)
- Open follow-up tickets for brainstorm §11.5:
  - FR-042: Tor exit list + reputation refresh
  - FR-007: ASN classification + validated `ctx.client_ip`
  - Risk-score integration (FR-025/026)
