# PR #114 Review — Synthesis (260529)

**Source PRs:** reviewer-1 (scope dissection) · reviewer-2 (quality+security) · reviewer-3 (FR+integration plan)
**Target:** release/stg @ `5bc0616bc`
**PR #114:** `feat/admin-panel-phase1` @ `0a25b7aec`, base=`main`, 30+ commits, 112 files, +17 679 / −253

## Headline (consensus across 3 reviewers)

PR #114 source branch is **BEHIND** release/stg by the 14-PR wave (#127–#140). A naive merge/rebase **REVERTS** every wave-3 hardening (XFF fail-secure, admin allowlist fail-closed, JSON walkers, WS JWT, TRAV-007, charset reject, etc.) AND duplicates work already cherry-picked (DbBatchWriter #137, CrowdSec CB #138, docs #139, CRS data #140).

**Verdict:** REJECT PR #114 as a single merge. Cherry-pick only the **NEW admin-panel slices** as 3 sequenced PRs onto release/stg. Each PR `--base release/stg`, squash-merge, conventional commit.

## What's NET-NEW (cherry-pick candidates)

Per reviewer-1 dissection — 14 thematic slices total:

| Slice | Theme | Status | Action |
|---|---|---|---|
| S1 | 8 BE handler modules (`risk/tier_policies/relay/access_lists/challenge/ddos/device_fp/geo_api.rs`) + wiring | NET-NEW | Cherry-pick (split into 3 PRs per reviewer-3) |
| S2 | 12+ FE pages + i18n EN/VI + nav + App.tsx routes | NET-NEW | Cherry-pick (bundle with S1 slices) |
| S3 | `tunnels.protocol` migration 0017 + repo update | NET-NEW | Cherry-pick first (BE depends on column) |
| S4 | `WafEngine::reload_file_rules` for ForwardOnly workers | NET-NEW | Cherry-pick solo (re-title commit) |
| S5 | `admin-panel.md` + `admin-panel-gap.md` plan docs | NET-NEW | Cherry-pick solo (`docs:`) |
| S6 | DB resilience + DbBatchWriter | ALREADY-LANDED #137 | SKIP (forward-port any `c42e8e64e` lint deltas as XS) |
| S7 | CrowdSec CB + dynamic log-level | ALREADY-LANDED #138 | SKIP (same lint-delta caveat) |
| S8 | Regex pre-compilation rewrite | CONFLICTS-WITH-STG (PR #73) | DEFER |
| S9 | Cluster end-to-end wire-up | DEFERRED (multi-node mock) | DEFER |
| S10 | Cluster + arch docs | ALREADY-LANDED #139 | SKIP |
| S11 | OWASP CRS data refresh | ALREADY-LANDED #140 | SKIP |
| S12 | `coverage-check.sh` + drop INET test | UNCLEAR — brief claim of equivalence with `a35f525c4` likely WRONG (different file surfaces) | Verify, likely small cherry-pick |
| S13 | `style: clippy lints for CI compliance` + scalability plan stub | ASSUMED-LANDED | SKIP |
| S14 | `waf-api` rule-scan filter (`c4d852ab0`) | UNCLEAR — not in wave-3 ledger | Verify, likely small cherry-pick |

## Reviewer-3 recommended integration sequence (3 PRs)

### PR-α — `feat(api,ui): tier policies + DDoS + access lists` (P0 mandatory)
- BE: `tier_policies_api.rs`, `ddos_api.rs`, `access_lists_api.rs` + route+lib wiring
- Config: `configs/{tier-policies,ddos}.yaml`
- FE: `pages/{tier-policies,ddos-protection,access-lists}/`
- FR delivered: FR-002, FR-005, FR-008, FR-036, FR-037, FR-038

### PR-β — `feat(api,ui): challenge engine + risk + relay + device-fp + geo` (P1 intelligence, 20 Battle pts)
- BE: 5 `_api.rs` modules
- Config: `configs/relay.yaml`
- FE: 5 pages
- FR delivered: FR-006, FR-007, FR-010, FR-011, FR-025, FR-026, FR-027, FR-041

### PR-γ — `feat(ui,api): response-filtering + sensitive-patterns + plugins + tunnels` (P0 hygiene + admin-panel-gap.md bugs)
- BE: `handlers.rs::patch_sensitive_pattern`, `plugins.rs` response-shape, `tunnels.rs` protocol field, migration 0017
- FE: 4 pages
- FR delivered: FR-022, FR-033, FR-034, FR-035

## CRITICAL blockers reviewer-2 found (must-fix BEFORE merge)

5 would-block-merge findings:

1. **C1 — Stub handlers return `success:true` for no-op operations.** `delete_ban_entry`, `credit_risk_actor`, `clear_risk_actor`, `refresh_relay_intel`, `test_relay` log and return success without touching any store. **Operator deception.** Fix: either wire to live stores OR return `501 Not Implemented` + FE disables buttons.
2. **C2 — Unbounded YAML writes of user-supplied JSON to disk.** PUT handlers (`put_access_lists`, `put_relay_config`, `put_device_fp_config`, `put_challenge_config`) write request body verbatim — no schema validation, no size cap. Disk-fill DoS + config corruption + immediate `engine.reload_rules()` after a malformed write. Fix: typed serde deserialisation + axum `RequestBodyLimit`. `put_tier_policies` already has the right pattern.
3. **C3 — `tunnels.protocol VARCHAR(3) NOT NULL DEFAULT 'tcp'` with no CHECK constraint.** Any caller writes `"xxx"`; routing branches on `tcp|udp|ws` silently fall through. Also `VARCHAR(3)` cuts off `quic`/`http`/`grpc`. Fix: widen + CHECK or enum + reject at API boundary.
4. **I1 — `Duration::from_mins(2)` in `sidecar.rs:39` violates project MSRV pin.** Existing call-sites deliberately use `from_secs(60)` with `#![allow(clippy::duration_suboptimal_units)]`. **CI breaker on stg.** Fix: `Duration::from_secs(120)`.
5. **I5 — `list_tunnels` JSON envelope change** from `{tunnels:[…]}` to `{success,data,total}` breaks existing FE/scripts. Fix: ship in lockstep with FE OR keep both keys for one release.

## Other high-impact findings

- **C4** — `reload_from_registry` ignores its `registry` argument; worker DB-rule sync is a no-op despite the doc-comment promise. Fix or re-title as `chore(engine): scaffold reload_from_registry`.
- **I2** — `sidecar.spawn()` detaches restart loop into `tokio::spawn`, contradicting the "fail-closed on first spawn" doc.
- **I3** — `set_log_level` 10 s cooldown is decorative TOCTOU. Fix: `compare_exchange` on timestamp.
- **I4** — `replay_request` forwards `Authorization` and `Cookie` from cluster peer to local admin API → any mTLS peer can replay forged bearer tokens as "loopback admin". Strip + re-issue service token, OR document trust model explicitly.
- **I7** — `apply_sync_response_sync` calls blocking `fs::read_dir` inside async ctx via `reload_file_rules`. Wrap in `spawn_blocking` or move to `tokio::fs`.
- **I8** — `challenge_preview` interpolates user `title`/`message` into HTML template; iframe sandbox is `allow-scripts` without `allow-same-origin` (mitigated but still defense-in-depth XSS). Fix: HTML-escape server-side.
- **I9** — `Database::connect` spawns unkillable health-check loop. CLI commands (`seed-admin`, `crowdsec`) leak the Arc. Fix: shutdown watch channel.
- **I10** — GETs return `400 BadRequest` on YAML parse error; PUTs same. Pick one convention (GET → fallback+WARN, PUT → reject).
- **M1** — No role-based authz on new mutation endpoints (`viewer` could PUT configs). Add `require_admin` layer.
- **M6** — `db_batch_writer` drops events on channel-full with rate-limited WARN. Under attack burst (highest value), audit data is silently lost. Add `dropped_events_total` counter + decide drop-vs-backpressure trade-off.
- **M7** — 8 of 12 FE pages exceed 250 LOC (risk-scoring 694, tier-policies 688, ddos 561…). Split during port.
- **M8** — Zero new unit tests across 8 BE handler modules. Coverage mandate is ≥90%.

## Cross-cutting risks

- **`c42e8e64e` "Fix lint and review code" commit** smuggles edits into wave-3 files (`circuit_breaker.rs`, `db_batch_writer.rs`, `cluster_forward.rs`, `node.rs`). Hunks must be peeled off the S1 squash and either dropped or rolled forward as XS follow-ups (reviewer-2 to confirm they are pure clippy).
- **17 lint-tail commits** must be squashed into 1–2 commits per slice.
- **Migration 0017 ordering** — must land before S1's `repo.rs` changes compile against the column.
- **`5df1201fd` "Fix unit test"** actually adds a public `WafEngine::reload_file_rules` method — re-title to `feat(engine): …` before landing.
- **`812f2ccd` ≡ `a35f525c4`** equivalence claim in the brief looks WRONG (different file surfaces). Verify.

## Consolidated unresolved questions (5)

The two reviewer reports converge on the same blocker decisions:

1. **PR #105 audit_emitter sequencing.** PR-β's `pages/risk-scoring/` (and any honeypot KPI) depends on `security_events` rows from audit_emitter. PR #105 is DRAFT on `main`. Options: (a) wait for #105 to land on release/stg first, (b) ship PR-β risk-scoring in degraded read-only/empty-state mode, (c) port minimal audit_emitter scaffold to stg first.
2. **Stub-vs-501 for C1 handlers.** Phase-1 Battle posture: wire stubs to real stores before merge, OR return 501 with FE disabling the buttons? Determines whether C1 is merge-blocker.
3. **Trust model for cluster `replay_request` (I4).** Is "any mTLS peer = full admin trust" intentional? If yes, document in `docs/cluster-protocol.md`. If no, strip+re-issue is required for PR-α even though it's a wave-3 carry-over, not a PR #114 NEW slice.
4. **FE 250-LOC ceiling enforcement.** 8 of 12 NEW FE pages exceed 250. (a) Split into `components/` subtrees during port (~2–3 h/PR), or (b) accept ceiling for `pages/` shell JSX only?
5. **#60.X batching.** PR-β covers FR for #60.1/#60.2/#60.3/#60.4/#60.7. PR-γ partially covers #60.5 (honeypot via Sensitive Patterns surface). **#60.6 (IP Reputation editor) is NOT in PR #114 at all** — ship in separate later PR, or scope-creep into PR-γ?

Lower-priority follow-ups (reviewer-2 list — addressable as separate tickets post-merge):
- C4, I2, I8, M1, M6, M8, M9 (security + reliability gaps).
- S12 / S14 verification.
- `c42e8e64e` lint deltas forward-port.
- `notifications` page refactor (defer until value confirmed).

## Recommended next action

Answer Q1–Q5, then begin solo-loop with PR-α (P0 mandatory bundle — no audit_emitter dependency, smallest blast radius).
