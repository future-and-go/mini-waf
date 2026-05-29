# PR #114 Scope Dissection vs release/stg

Reviewer: reviewer-1
Date: 2026-05-29
PR: https://github.com/future-and-go/mini-waf/pull/114
Base: `main` (af10edb58 → see note below)
Head: `0a25b7aec` (branch `feat/admin-panel-phase1`)
release/stg HEAD: `5bc0616bc`

## Method note

`gh pr view 114 --json commits` reports 30+ commits, but PR #114 includes a
merge commit `270d9d29b` that pulls additional main commits *into* the PR
branch. Splitting at the merge:

- 14 commits = wave-3 source set on `main` not yet on `release/stg`
  (transitive payload — appears in the PR's diff vs main but is owned by
  upstream merge wave).
- 23 commits = **net-new admin-panel work** (the actual PR contribution).
- 1 = merge commit itself.

Aggregate vs main: 82 files, +9432/−1885. The brief's "112 files +17679"
figure counts every intermediate touch including the lint-loop churn
(18 "Fix lint" / "Fix unit test" rebase commits) — the file set
boils down to the 82 above.

## Thematic slices

### S1 — Admin-panel BE API surface (waf-api, NET-NEW)

**Intent.** Add eight HTTP routers backing the Phase-1 admin-panel pages:
risk-scoring, tier-policies, relay-intel, access-lists, challenge-engine,
DDoS protection, device fingerprinting, geo-restriction. Each is a brand
new file; none exist on main or stg today.

**Commits**
- `380c46bce` "Add miss BE API" (the substantive add, +1670/−34)
- `c42e8e64e` "Fix lint and review code" (incremental fixes across same files)
- Plus the long lint-fix tail (`c3fc13def`, `5187b364d`, `a623d130f`,
  `586258a83`, `28263fb3c`, `3066579ba`, `20e5fb8f8`, `2e01dee5b`,
  `5e046be9e`, `c491e9002`, `c420f957e`, `5df1201fd`, `00541e4f7`,
  `d9949c7cd`, `d950592a4`, `3105732b1`, `0a25b7aec`) — 17 commits that
  exist purely to satisfy clippy/rustfmt/test gates after `380c46bce`.

**Files**
- `crates/waf-api/src/risk_api.rs` (NEW)
- `crates/waf-api/src/tier_policies_api.rs` (NEW)
- `crates/waf-api/src/relay_api.rs` (NEW)
- `crates/waf-api/src/access_lists_api.rs` (NEW)
- `crates/waf-api/src/challenge_api.rs` (NEW)
- `crates/waf-api/src/ddos_api.rs` (NEW)
- `crates/waf-api/src/device_fp_api.rs` (NEW)
- `crates/waf-api/src/geo_api.rs` (NEW)
- `crates/waf-api/src/{lib,handlers,server,plugins,tunnels}.rs` (router wiring)
- `crates/waf-api/tests/handler_plugins_tunnels.rs`
- `configs/{ddos,relay,tier-policies}.yaml` (NEW config files)

**Status vs release/stg.** NET-NEW. None of the 8 files exist on stg.
No path collision risk; lint-tail churn is internal to this slice.

**Recommendation.** CHERRY-PICK AS BUNDLE — squash `380c46bce` + the
17-commit lint tail into one or two commits. The lint tail has no
independent value and pollutes history. Reviewer-2 must vet each new
router for auth/authz, input validation, and SQL injection before merge.

---

### S2 — Admin-panel FE pages + i18n (NET-NEW)

**Intent.** Sixteen React/TS page components for the admin panel, plus
EN/VI i18n keys, App.tsx route wiring, and nav-items updates.

**Commits**
- `f11063227` "Add draft version" (+7219/−58) — substantive add
- `816ee36da` "Add draft version" (duplicate, identical stat)
- `270d9d29b` merge commit reconciling the two parallel adds
- A handful of incremental touches from `380c46bce` (i18n keys) and
  `c42e8e64e` family

**Files**
- `web/admin-panel/src/App.tsx`
- `web/admin-panel/src/utils/nav-items.ts`
- `web/admin-panel/src/i18n/locales/{en,vi}.json`
- `web/admin-panel/src/pages/{access-lists,challenge-engine,ddos-protection,device-fingerprinting,geo-restriction,notifications,plugins,relay-intel,response-filtering,risk-scoring,sensitive-patterns,tier-policies,tunnels,rule-analytics}/index.tsx`

**Status vs release/stg.** NET-NEW. release/stg's `web/admin-panel/` does
not contain these pages or their i18n keys.

**Recommendation.** CHERRY-PICK AS BUNDLE — squash both "Add draft
version" commits + merge into one. Reviewer-3 should verify each page
hits the corresponding `S1` BE endpoint with the right RBAC headers.

---

### S3 — Storage model + migration for tunnel protocol

**Intent.** Add `protocol` column (`tcp|udp|ws`, default `tcp`) to
`tunnels` table + matching Rust model fields + `UpdateSensitivePattern`
PATCH struct.

**Commits**
- `380c46bce` (the storage block lives inside the "Add miss BE API" commit)

**Files**
- `migrations/0017_tunnel_protocol.sql` (NEW)
- `crates/waf-storage/src/models.rs` (+30 lines: `protocol` field on
  `TunnelRow`/`CreateTunnel`, `UpdateSensitivePattern<'a>`)
- `crates/waf-storage/src/repo.rs` (+52 lines)
- `crates/waf-storage/tests/repo_plugins_tunnels_crowdsec.rs`

**Status vs release/stg.** NET-NEW. release/stg's latest migration is
`0016_host_http_redirect.sql`; slot `0017` is free.

**Recommendation.** CHERRY-PICK SOLO ahead of S1/S2 (BE/FE depend on the
column being present). Migration is additive + `IF NOT EXISTS` guarded,
so rollback risk is low. Reviewer-2 must confirm the new `protocol`
enum is validated at the API boundary.

---

### S4 — Engine helper: `WafEngine::reload_file_rules`

**Intent.** Add a DB-free reload entrypoint for `ForwardOnly` worker
nodes that have no Postgres connection but still need to pick up file-
based custom rules.

**Commits**
- `5df1201fd` "Fix unit test" (despite the subject, it adds the
  public method on `WafEngine`)

**Files**
- `crates/waf-engine/src/engine.rs` (+22 lines)

**Status vs release/stg.** NET-NEW (`reload_file_rules` is not on stg
nor main).

**Recommendation.** CHERRY-PICK SOLO. Tiny, self-contained. But the
commit subject ("Fix unit test") is a lie — must be re-titled to
`feat(engine): add reload_file_rules for ForwardOnly workers` before
landing on stg. Confirm with reviewer-2 that the method has a caller
(otherwise it's dead code per Iron Rule #2).

---

### S5 — Admin-panel requirement docs

**Intent.** Capture the Phase-1 plan + gap analysis under `plans/`.

**Commits**
- `f11063227` (contributes `admin-panel.md`, 822 lines)
- `94c72ae68` "add requirement" (contributes `admin-panel-gap.md`, 50 lines)

**Files**
- `plans/260526-1626-admin-panel-gap-requirement/admin-panel.md`
- `plans/260526-1626-admin-panel-gap-requirement/admin-panel-gap.md`

**Status vs release/stg.** NET-NEW.

**Recommendation.** CHERRY-PICK SOLO as a single `docs(plans):` commit.
Trivial, no code impact, can land independently.

---

### S6 — DB resilience + batched audit log writer (transitive)

**Intent.** Wave-3 PR #137 source.

**Commits**
- `e7d7bf77f` "feat: add DB connection resilience and batched audit log writer"

**Files** — `crates/waf-engine/src/logging/db_batch_writer.rs` and
related storage hooks.

**Status vs release/stg.** ALREADY-LANDED via
`6e252cd89 feat(storage,engine): port DB resilience + batched audit log writer from main (#137)`.

**Recommendation.** SKIP. But note: `c42e8e64e` (S1 lint commit) touches
`db_batch_writer.rs` for ~23 lines — that delta is **not** in stg's
copy. Reviewer-2 must diff the post-`c42e8e64e` shape vs stg's
`6e252cd89` shape and either roll the lint-fix forward as a tiny
follow-up or fold it into S1's squash.

---

### S7 — CrowdSec circuit breaker + dynamic log level (transitive)

**Intent.** Wave-3 PR #138 source.

**Commits**
- `6f39920a5` "feat: add CrowdSec circuit breaker and dynamic log level control"
- `30f7e17c8` "fix: remove unnecessary registry feature from tracing-subscriber" (paired)

**Files** — `crates/waf-engine/src/crowdsec/circuit_breaker.rs` and
tracing wiring.

**Status vs release/stg.** ALREADY-LANDED via
`b175726ee feat(engine,api): port CrowdSec circuit breaker + dynamic log-level control from main (#138)`.

**Recommendation.** SKIP. Same caveat as S6: `c42e8e64e` adds 4 lines to
`circuit_breaker.rs` — likely a `#[allow]` or trivial style fix.
Reviewer-2 to verify and roll forward if needed.

---

### S8 — Regex pre-compilation guarantee (transitive)

**Commits** — `ce449e2e0` "feat: regex pre-compilation guarantee and integration wiring"

**Status vs release/stg.** DEFERRED per prior reviewer-1 audit (260527).
Conflicts with stg's PR #73 surface (`fix(rules): cap per-request regex
compile size_limit at 1 MB`).

**Recommendation.** DEFER. Out-of-scope for PR #114 integration. Must be
re-planned after stg's regex caps stabilise.

---

### S9 — Cluster end-to-end wire-up (transitive)

**Commits**
- `789aaa244` "feat(waf-cluster): wire cluster mode end-to-end integration"
- `d5d4fe81e` "test(waf-cluster): add cluster sync and lifecycle integration tests"
- `ca562d7ae` "fix(e2e): correct API endpoint paths in cluster e2e test script"
- `4867e3d80` "feat(cluster): update plan statuses to completed and add cluster architecture docs"

**Files** — `crates/waf-cluster/{src,tests}/**`, plus docs touched by S10.

**Status vs release/stg.** DEFERRED per prior audit. Cluster
Criticals #70/#75/#76 require multi-node mock + election state machine.
Stg already shipped PRs #80/#81/#82/#83 (hardening individual cluster
paths) but the *end-to-end wire-up* is the deferred piece.

**Recommendation.** DEFER (OUT-OF-SCOPE for this loop). However,
`c42e8e64e` again incrementally touches `cluster_forward.rs` (8 lines),
`node.rs` (12), `sync/{config,rules}.rs`, `transport/server.rs`. Those
are bundled with S1's lint commit — when S1 is squashed, those cluster-
file hunks must be **stripped** out and either dropped or folded into a
future cluster bundle. Reviewer-2 to confirm they are pure clippy fixes
and don't smuggle behavioural changes into deferred cluster code.

---

### S10 — Cluster + system-architecture docs (transitive)

**Commits** — `6803aeb34` "docs: system-architecture.md, cluster-design.md, cluster-guide.md, cluster-protocol.md" (lives on main, pulled in by the merge)

**Files** — `docs/{system-architecture,cluster-design,cluster-guide,cluster-protocol}.md`

**Status vs release/stg.** ALREADY-LANDED via
`cb5c2e09e docs: port cluster + system-architecture updates from main (#139)`.

**Recommendation.** SKIP.

---

### S11 — OWASP CRS rule data refresh (transitive)

**Commits** — `eeda11bc2` "rules: update" (on main)

**Files** — `rules/owasp-crs/**` (5 `.data` files + ~14 `.yaml` rule
files + `rules/sync-config.yaml`).

**Status vs release/stg.** ALREADY-LANDED via
`2344ea8d1 feat(rules): refresh OWASP CRS rule data + payload catalogue from main (#140)`.

**Recommendation.** SKIP.

---

### S12 — CI fix: surface llvm-cov errors + drop obsolete INET test (transitive)

**Commits** — `812f2ccd6` "fix(ci): surface cargo llvm-cov errors and remove obsolete INET test"

**Files** — `.github/scripts/coverage-check.sh`, `crates/waf-storage/tests/repo_hosts.rs`

**Status vs release/stg.** Per brief, semantically equivalent to stg's
`a35f525c4 ci: extend pull_request triggers to release/stg`.
Inspecting: the two commits are **NOT** the same surface —
`812f2ccd6` modifies `coverage-check.sh` + drops an INET test,
`a35f525c4` extends PR triggers. **Brief assertion appears
inaccurate.** Recommend verifying with team-lead — these touch
different files.

**Recommendation.** ASK TEAM-LEAD to confirm whether stg already has
the `coverage-check.sh` `set -e $()` fix and the INET test removal.
If not, this is a small CHERRY-PICK SOLO candidate.

---

### S13 — Style: clippy lints + scalability plan stub (transitive)

**Commits**
- `ed0f4004d` "style: fix clippy lints for CI compliance"
- `8321114d4` "plan to scalability"

**Status vs release/stg.** Likely ALREADY-LANDED — `ed0f4004d` is a CI-
hygiene cleanup that release/stg's lint-strict policy would have
required for the wave-3 ports to compile. `8321114d4` is a plan-only
file under `plans/`.

**Recommendation.** SKIP (assume already-landed). If reviewer-2 finds a
clippy warning on stg that mirrors `ed0f4004d`, cherry-pick its
specific hunk.

---

### S14 — Misc: waf-api rule-scan filter (transitive)

**Commits** — `c4d852ab0` "feat(waf-api): skip non-rule YAML files and dirs during rule scan"

**Files** — likely `crates/waf-api/src/handlers.rs` or a rules-scan helper.

**Status vs release/stg.** UNCLEAR — not enumerated in the wave-3
cherry-pick list (#137/#138/#139/#140). Lives on main since the
admin-panel base was cut.

**Recommendation.** ASK TEAM-LEAD to confirm whether `c4d852ab0` should
be a separate cherry-pick onto release/stg. Likely a CHERRY-PICK SOLO
candidate that the wave-3 plan missed.

---

## Punch-list

| Slice | Theme | Status vs stg | Recommendation | Effort |
|------:|-------|---------------|----------------|--------|
| S1 | Admin-panel BE routers (8 NEW + wiring) | NET-NEW | CHERRY-PICK AS BUNDLE (squash lint tail) | L — needs security review |
| S2 | Admin-panel FE pages + i18n | NET-NEW | CHERRY-PICK AS BUNDLE | M — RBAC check |
| S3 | Tunnel `protocol` migration + models | NET-NEW | CHERRY-PICK SOLO first | S |
| S4 | `WafEngine::reload_file_rules` | NET-NEW | CHERRY-PICK SOLO (re-title commit) | XS |
| S5 | Admin-panel plan/gap docs | NET-NEW | CHERRY-PICK SOLO (`docs:`) | XS |
| S6 | DB resilience + batched audit writer | ALREADY-LANDED (#137) | SKIP — but roll fwd `c42e8e64e` lint delta | XS follow-up |
| S7 | CrowdSec breaker + dynamic loglevel | ALREADY-LANDED (#138) | SKIP — but roll fwd `c42e8e64e` lint delta | XS follow-up |
| S8 | Regex pre-compilation wiring | CONFLICTS-WITH-STG (PR #73) | DEFER | — |
| S9 | Cluster end-to-end wire-up + tests | OUT-OF-SCOPE | DEFER | — |
| S10 | Cluster + arch docs | ALREADY-LANDED (#139) | SKIP | — |
| S11 | OWASP CRS data refresh | ALREADY-LANDED (#140) | SKIP | — |
| S12 | CI `coverage-check.sh` + drop INET test | UNCLEAR (brief possibly wrong) | ASK lead, likely CHERRY-PICK SOLO | XS |
| S13 | Style clippy + scalability plan | ASSUMED-LANDED | SKIP | — |
| S14 | waf-api rule-scan filter | UNCLEAR | ASK lead, likely CHERRY-PICK SOLO | XS |

**Totals**
- 14 slices identified
- 5 cherry-pick candidates (S1, S2, S3, S4, S5) confirmed NEW
- 2 ambiguous candidates pending team-lead confirmation (S12, S14)
- 4 ALREADY-LANDED (S6, S7, S10, S11) — skip with `c42e8e64e` lint-delta follow-up
- 3 DEFERRED / OUT-OF-SCOPE (S8, S9, plus S13 assumed)

## Cross-slice risks

1. **The `c42e8e64e` "Fix lint and review code" commit is a magnet.** It
   touches files belonging to S1, S6, S7, and S9. When squashing S1, the
   S6/S7/S9 hunks must be peeled off and either dropped (deferred) or
   forward-ported as standalone follow-ups against stg's already-landed
   copies.
2. **17 lint-loop commits.** S1 commit chain has 17 trailing `Fix lint`/
   `Fix unit test` commits. Cherry-picking them serially against stg will
   trigger 17 CI runs and 17 lint reviews. Squash before picking.
3. **Two identical "Add draft version" commits (`f11063227`, `816ee36da`)**
   reconciled by merge `270d9d29b`. After squash, only one survives.
4. **Migration 0017 ordering.** S3 must land before S1's `repo.rs`
   changes compile against the new `protocol` column; otherwise CI fails
   on missing column at test time (sqlx offline compile may also need
   `cargo sqlx prepare` re-run).
5. **Brief assertion mismatch (S12).** `812f2ccd6` vs `a35f525c4`
   appear to touch different surfaces. Flagging for team-lead.

## Recommended landing order

1. S3 (migration + models) — unblocks S1.
2. S5 (docs) — risk-free, lands plan trail.
3. S4 (`reload_file_rules`) — with re-titled commit; verify caller exists.
4. S1 (BE routers, squashed) — pending reviewer-2 security pass.
5. S2 (FE pages, squashed) — pending reviewer-3 RBAC pass.
6. (Conditional) S12 + S14 if team-lead confirms not already in stg.
7. (Forward-port) the `c42e8e64e` deltas to wave-3 files as XS follow-ups.

## Unresolved questions

- S12: Is `coverage-check.sh` `set -e $()` fix + INET test removal
  already on stg? Brief claims equivalence with `a35f525c4` but file
  sets differ.
- S14: Is `c4d852ab0` (waf-api rule-scan filter) intentionally omitted
  from wave-3, or an oversight?
- S4: Does `reload_file_rules` have a caller in PR #114, or is it dead
  code pending a future cluster integration? (Iron Rule #2 implication.)
- For S1/S2 squash: does team prefer one mega-commit per slice, or a
  small ordered series (e.g. `feat(api): add risk + tier-policies
  endpoints`, `feat(api): add access-lists + challenge + ddos
  endpoints`, etc.)?
