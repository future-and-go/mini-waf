# PR #114 — Quality & Security Risks per NEW Slice

Reviewer: reviewer-2
Date: 2026-05-29
PR: https://github.com/future-and-go/mini-waf/pull/114 (`feat/admin-panel-phase1`, head `0a25b7aec`)
Base for review: `release/stg` (`5bc0616bc`)
Scope: NEW slices per reviewer-1 dissection — S1 (8 BE handler modules + wiring), S2 (FE pages + i18n), S3 (tunnels protocol migration + repo), S4 (`reload_file_rules` + `reload_from_registry`). Wave-3 transitives (S6/S7/S10/S11) skipped except where the PR's lint commit `c42e8e64e` mutates them.

## Method
- `git fetch origin pull/114/head:pr-114` + `git diff release/stg...pr-114 -- <path>` per file.
- Read full BE handler files via `git show`.
- Cross-checked auth, validation, file-system path resolution, race conditions, error propagation.
- Verified clippy/Iron-Rule violations against `[[pattern-clippy-strict-rust2024]]` and `[[reference-rustls-23-resolver]]` notes.

## Per-finding format
`[SEVERITY] <finding> -- <path:line> -- <recommendation>`

---

## CRITICAL

### C1 — Stub handlers return `success: true` with no work performed
Five new "mutating" endpoints accept calls and reply 200 without doing anything:
- `delete_ban_entry` (`crates/waf-api/src/ddos_api.rs:128`) — only logs the IP; the in-memory ban store is never touched, so the operator's manual unban is silently a no-op.
- `credit_risk_actor` / `clear_risk_actor` (`crates/waf-api/src/risk_api.rs:177-189`) — echo the id; risk-store untouched.
- `refresh_relay_intel` (`crates/waf-api/src/relay_api.rs:91`) — returns zeros; no refresh runs.
- `test_relay` (`crates/waf-api/src/relay_api.rs:103`) — comment says "stub" but the body returns `verdicts: []` which FE renders as "clean".

Production impact: the admin UI shows confirmation toasts ("Banned IP cleared") for operations that didn't happen. Security operators rely on these for incident response.
**Recommendation:** Either (a) wire to the live stores before merge (preferred), or (b) return `501 Not Implemented` with an explicit `{ status: "not_implemented" }` payload so the FE can disable the buttons and the auditor can see the gap. The current `success:true` shape is actively misleading.

### C2 — Unbounded YAML write of user-supplied JSON to disk
Every PUT handler does `write_yaml(&path, &body)` where `body: Value` is whatever JSON the request supplied — no schema validation, no field filter, no size cap. Examples:
- `put_access_lists` (`crates/waf-api/src/access_lists_api.rs:104`) — entire body written verbatim.
- `put_relay_config` (`crates/waf-api/src/relay_api.rs:82`) — same pattern.
- `put_device_fp_config` (`crates/waf-api/src/device_fp_api.rs:147`) — same.
- `put_challenge_config` (`crates/waf-api/src/challenge_api.rs:115`) — fe→yaml wrapper but no field-level validation.

Impact:
1. **Disk-fill DoS** — authenticated user (any role, see C5) can POST a multi-MB JSON; serialised YAML is written under `rules/`/`configs/`.
2. **Config corruption** — invalid schema is persisted; engine reload on next start fails. `put_access_lists` even *triggers* `engine.reload_rules()` immediately after writing (`:106`), so a malformed body that yaml-serializes fine can break live rule matching until the file is fixed by hand.
3. **Path-traversal not possible here** (path is `state.main_config_file`-relative, no user influence), but the **content** is fully attacker-controlled.

**Recommendation:** Deserialize each PUT body into a typed `serde` struct (the FE TypeScript interfaces are already known); reject anything that fails. Enforce a body size cap via axum `RequestBodyLimit`. For `put_tier_policies` the partial validation at `tier_policies_api.rs:84-101` is the right shape — replicate that pattern everywhere.

### C3 — `tunnels.protocol` accepts any 3-character string; no enum guard
Migration `migrations/0017_tunnel_protocol.sql:2` defines `protocol VARCHAR(3) NOT NULL DEFAULT 'tcp'` — no CHECK constraint. The Rust path `create_tunnel` (`crates/waf-api/src/tunnels.rs:104`) reads `body.protocol` as `Option<String>` and forwards untouched to `Database::create_tunnel` (`crates/waf-storage/src/repo.rs:2013`) which uses it verbatim. Any caller can set `protocol = "xxx"`; the gateway routing logic that branches on `tcp|udp|ws` will silently fall through.

**Recommendation:** Add a CHECK constraint in the migration or a typed enum + match-or-`BadRequest` in `create_tunnel`. Reject unknown protocols at the API boundary. While at it, document that `VARCHAR(3)` excludes future protocols like `quic` (4 chars) — choose `VARCHAR(8)` now to avoid a re-migration later.

### C4 — `reload_from_registry` ignores its registry argument
`crates/waf-engine/src/lib.rs:75-86` — the impl logs the registry size, then calls `self.reload_file_rules()` only, dropping the `registry: &RuleRegistry` parameter. The doc-comment claims "cluster sync keeps them current via `NodeState::rule_registry`" but the engine never reads `NodeState::rule_registry` after init. Worker nodes (`ForwardOnly`) that receive a `RuleSyncResponse` will write to the cluster registry (`crates/waf-cluster/src/sync/rules.rs:191`) but the engine pattern-matchers stay frozen at boot state. The promised "rule replication to workers" path is wired but functionally a no-op for DB-sourced rules.

**Recommendation:** Either implement registry-driven reload (rebuild `CustomRulesEngine` from `registry.rules` slice), or — if S4 is purely scaffolding for a follow-up cluster PR — re-title the commit as `chore(engine): scaffold reload_from_registry` and document that DB-rule sync is non-functional. Currently the code lies about its behaviour.

---

## IMPORTANT

### I1 — `Duration::from_mins` violates project MSRV policy
`crates/prx-waf/src/victoria_logs/sidecar.rs:39`: `const RESTART_BACKOFF_MAX: Duration = Duration::from_mins(2);`
Multiple existing call-sites deliberately use `from_secs(60)` with `#![allow(clippy::duration_suboptimal_units)]` because `from_mins` is MSRV-gated (see `crates/waf-engine/src/checks/rate_limit/store/memory.rs:1`, `crates/waf-api/src/security.rs:1`, `crates/waf-engine/src/crowdsec/sync.rs`). Mixing the two breaks CI on older toolchains and reverses a wave-3 decision.
**Recommendation:** Change to `Duration::from_secs(120)`. Add the existing `#[allow]` line if clippy complains.

### I2 — Sidecar fail-closed promise broken in `spawn()` path
`crates/prx-waf/src/victoria_logs/sidecar.rs:88`: the non-restart `spawn()` calls `spawn_with_restart` inside `tokio::spawn(async move { … })`. The doc-comment on `spawn_with_restart` (line 102) says "First spawn is synchronous (fail-closed)" — but the caller here is detached, so any `Err` returned from the *first* re-attempt is logged and discarded. The WAF will keep running with VictoriaLogs dead, contradicting the stated fail-closed guarantee.
**Recommendation:** Either change `spawn()` callers to use `spawn_with_restart` directly at boot, or document that `spawn()` is best-effort. As written, the two entry points contradict each other.

### I3 — `set_log_level` cooldown is a TOCTOU race
`crates/waf-api/src/handlers.rs:716-740`: read `LAST_LOG_LEVEL_CHANGE_MS`, check cooldown, eventually `setter(&req.filter)`, then `store`. Two concurrent requests can both read the same stale `last`, both pass the gate, both apply filters, last-write-wins. Not high-severity (admin endpoint), but the 10 s cooldown is advertised as a safety; it's actually decorative.
**Recommendation:** `compare_exchange` on the timestamp before calling `setter`, retry-or-reject on conflict.

### I4 — `replay_request` forwards Authorization headers from cluster peer to local admin API
`crates/waf-cluster/src/cluster_forward.rs:178-186` strips only `host` and `content-length` from the forwarded `headers` map; `Authorization`, `Cookie`, custom admin headers are passed through to `127.0.0.1:9527`. Combined with admin-IP allowlist typically including `127.0.0.1`, **any cluster peer with valid mTLS can submit a write request bearing a forged or replayed bearer token and reach the main API as "loopback admin"**. The JWT signature must still verify, so this isn't a free pass, but it does mean:
- A compromised worker becomes a credential-replay vector that bypasses the operator's per-network admin-IP restriction.
- Audit logs on main attribute the action to the loopback IP, losing the originating worker identity.
**Recommendation:** (a) Strip `Authorization` and re-issue a short-lived service token signed by the cluster CA. (b) At minimum, add an `X-Forwarded-By: <node_id>` header at replay time and log it in the audit trail. (c) Document the trust model: "any mTLS-authenticated cluster peer is fully trusted to forge admin requests" is a defensible position but must be explicit.

### I5 — Breaking response-shape change in `list_tunnels`
`crates/waf-api/src/tunnels.rs:46` changes the JSON envelope from `{"tunnels": [...]}` to `{"success": true, "data": [...], "total": N}`. Any consumer on release/stg (existing FE, scripts, monitoring probes) that reads `.tunnels` breaks. The PR does not bump an API version.
**Recommendation:** Land in lockstep with S2 FE changes, sweep release/stg for `tunnels:` consumers (`grep -rn "tunnels:" web/admin-panel/src` against the **stg** tree), or keep both keys in the response for one release.

### I6 — `delete_ban_entry` accepts arbitrary `:ip` path param with no validation
`crates/waf-api/src/ddos_api.rs:128`: `Path(ip): Path<String>` is logged at INFO and echoed back. No `IpAddr::parse` check. A request to `/api/ddos/ban-table/%0AINJECTED-LOG-LINE` ends up in the tracing output (log injection). Combined with C1 (no-op), this is mostly a log-hygiene issue today; when the handler is actually wired it becomes a path-injection vector.
**Recommendation:** `ip.parse::<IpAddr>().map_err(|_| ApiError::BadRequest(...))?` before logging or storing.

### I7 — `apply_sync_response_sync` runs under sync `parking_lot::RwLock` then awaits
`crates/waf-cluster/src/transport/client.rs:317-329`: takes `node_state.rule_registry.write()` (parking_lot), calls `apply_sync_response_sync` inside the guard, then drops the guard via end-of-block — but a few lines later (line 330) the code calls `notify_rules_updated(version).await` which acquires `*self.rules_version.write().await` (tokio) and may also re-enter the engine through a callback. While the parking_lot guard is dropped before the await (good), the engine's `reload_file_rules` performs blocking file I/O (`std::fs::read_dir` via `crate::rules::custom_file_loader::load_dir`) inside an async context. On a worker under rule-sync churn this stalls the tokio runtime.
**Recommendation:** Wrap `load_dir` in `tokio::task::spawn_blocking`, or move `reload_file_rules` to `async fn` and use `tokio::fs`. Match the pattern already in `access_lists_api::read_yaml_opt`.

### I8 — `challenge_preview` interpolates user input into HTML
`crates/waf-api/src/challenge_api.rs:158-175`: `title` and `message` from the JSON body are `format!`-ed straight into the HTML template. The FE iframe (`web/admin-panel/src/pages/challenge-engine/index.tsx:374`) renders this with `sandbox="allow-scripts"` (no `allow-same-origin`), which mitigates the worst case (no session theft) but JS still executes — scripts can phone home, fingerprint the admin's browser, attempt clickjacking against the admin session in adjacent tabs. Defense-in-depth says: escape HTML on the server.
**Recommendation:** HTML-escape `title` and `message` before format!, or render via a templating engine (`askama`, `tera`) with auto-escape. The current code's `&#x1F512;` literal next to user-controlled `{title}` betrays that someone considered escaping for the lock emoji but forgot the user data.

### I9 — `Database::connect` spawns an unkillable health-check loop
`crates/waf-storage/src/db.rs:42`: `tokio::spawn(health_check_loop(health_pool))` — no JoinHandle stored, no shutdown signal, no graceful drop. The loop runs forever, holds an `Arc<PgPool>` clone, prevents the pool from being fully dropped during tests and short-lived CLI commands (`prx-waf seed-admin`, `prx-waf crowdsec …`).
**Recommendation:** Use a `tokio::sync::watch` shutdown channel, or wrap in `tokio::select! { _ = interval.tick() => …, _ = shutdown_rx.changed() => break }`. At a minimum, `tokio::spawn` only when the pool will live for the process lifetime — gate on a `enable_health_check` flag for CLI paths.

### I10 — `get_challenge_config` swallows YAML parse errors as BadRequest
`crates/waf-api/src/challenge_api.rs:35`: `read_yaml` returns `Err(ApiError::BadRequest("parse YAML: …"))` to the *caller*, which is a GET handler. That means corrupted on-disk YAML surfaces to the admin UI as `400 Bad Request` instead of `500 Internal Server Error`. FE error toast will say "invalid request" — misleading. The other modules use `read_yaml_opt` which silently falls back to defaults — also wrong (silent corruption recovery). Pick one strategy.
**Recommendation:** Standardise: GET → fall-back-to-defaults + WARN log on parse failure; PUT → reject and return parse error. Document the convention in `[[reference-stg-config-conventions]]`.

---

## MODERATE

### M1 — No role-based authorization on new PUT/POST endpoints
`crates/waf-api/src/server.rs:248-289`: all new routes sit behind `require_auth` only. `auth.rs:33` defines `role` in Claims and `auth.rs:68` provides `validate_admin_token`, but `middleware::require_auth` (`crates/waf-api/src/middleware.rs:30`) uses `validate_access_token` (no role check). A user with `role: "viewer"` (see `auth.rs:350` test) can PUT `/api/risk/config`, `/api/access-lists`, etc. This is a **pre-existing pattern** (existing PUTs share it), but PR #114 widens the attack surface by ~12 new mutation endpoints.
**Recommendation:** Add a `require_admin` middleware layer for mutation routes (`PUT`/`POST`/`DELETE`/`PATCH`) and stack it on the new endpoints. Track as a follow-up if not in scope for this PR.

### M2 — `next_id` for geo rules is a race
`crates/waf-api/src/geo_api.rs:72`: `next_id = max(existing) + 1` computed after `read_rules`. Two concurrent `create_geo_rule` requests both see the same max, both write rules with the same id, the second `write_rules` clobbers the first (since `read → mutate → write` is not atomic at the FS layer).
**Recommendation:** Use a UUID or atomic counter; or take a process-wide `tokio::Mutex` around the read-modify-write window.

### M3 — `patch_geo_rule` whitelist drops user-meant fields silently
`crates/waf-api/src/geo_api.rs:124`: only `enabled`, `action`, `scope` are applied; sending `country_name` or `iso_code` PATCH is silently dropped. The FE may show "saved" while the change wasn't persisted.
**Recommendation:** Either reject unknown/unsupported PATCH keys with 400, or document the field whitelist.

### M4 — Sidecar restart loop returns `Ok(None)` after exceeding max failures
`crates/prx-waf/src/victoria_logs/sidecar.rs:135-142, 167-174`: after 50 consecutive failures the loop exits with `Ok(None)`. The outer `spawn()` task (line 88) sees this as success — no further notification reaches the operator. The audit pipeline is dead and the WAF keeps proxying traffic.
**Recommendation:** Promote to `error!` + structured metric + (ideally) flip the readiness probe to "degraded" so orchestrator can replace the pod.

### M5 — `lookup_ip` returns deceptive "Unknown" payload
`crates/waf-api/src/geo_api.rs:158-167`: when GeoIP db is not loaded, returns `country_name: "Unknown — GeoIP database not loaded"`. FE has no way to distinguish "unknown country" from "feature disabled" without string-matching the message. Should return 503 / `not_configured` flag.
**Recommendation:** Return `{ "status": "geoip_unavailable" }` so the FE can render a setup banner.

### M6 — `db_batch_writer` silently drops events on channel-full
`crates/waf-engine/src/logging/db_batch_writer.rs:34-37`: `TrySendError::Full` triggers a 30 s rate-limited warning and the event is lost. Under attack burst (which is when audit logs matter most), `attack_logs` rows go missing. The channel capacity is 10 000 from `prx-waf/src/main.rs:1583` — sized for steady state but not for spike + slow DB.
**Recommendation:** Add a `dropped_events_total` counter and surface it on a metrics endpoint. Consider switching to bounded back-pressure (await `send` with a deadline) so the gateway thread visibly slows rather than silently losing audit data — discuss with team-lead which trade-off matches the threat model.

### M7 — Files exceed the 250-LOC modularisation guideline
Per `CLAUDE.md` ("If a code file exceeds 200 lines of code, consider modularizing"):
- `crates/waf-api/src/risk_api.rs` — 188 (OK, edge)
- `crates/waf-api/src/handlers.rs` — already 800+, gains another 100 here.
- `crates/prx-waf/src/victoria_logs/sidecar.rs` — 542 (was 280; doubled).
- FE pages (the 200-LOC guideline applies to JSX-heavy files too): risk-scoring/index.tsx 694, tier-policies/index.tsx 688, ddos-protection/index.tsx 561, access-lists/index.tsx 554, response-filtering/index.tsx 509, geo-restriction/index.tsx 477, device-fingerprinting/index.tsx 437, challenge-engine/index.tsx 416, sensitive-patterns/index.tsx 408.

**Recommendation:** Not a blocker, but at least extract sub-components for the form sections (per existing pattern in `access-lists/index.tsx:90` `IpListCard`). Track as cleanup follow-up.

### M8 — No unit tests for new BE handlers
The PR adds 8 BE handler modules (~1300 LOC) with **zero** new unit tests under `crates/waf-api/tests/`. The only new test infra is `crates/waf-engine/src/crowdsec/circuit_breaker.rs` (transitive) and a handful of `#[cfg(test)]` in `handlers.rs` for the log-level helper. Project mandate is ≥90 % coverage.
**Recommendation:** At minimum, add tests for the YAML round-trip helpers (`yaml_to_fe` / `fe_to_yaml`) and the validation in `put_tier_policies`. The challenge-preview HTML escape (I8) needs a regression test.

### M9 — Clippy strict lints — likely fires under release/stg posture
Per `[[pattern-clippy-cherry-pick-lint-catalogue-wave3]]`. Scanned new BE handler files — most use `format!("…{e}")` (uninlined_format_args OK). Spot risks:
- `crates/waf-api/src/handlers.rs:734` — `LOG_LEVEL_COOLDOWN_MS / 1000` inside `format!` is fine; the `tracing::info!("Log filter updated to: {}", req.filter)` is **not** uninlined → will trip on stg.
- `crates/waf-api/src/access_lists_api.rs:55-69`, `:120-148` — large `json!({})` blocks repeat the same key-extraction pattern; consider extracting helpers but clippy itself probably stays quiet.
- `crates/prx-waf/src/victoria_logs/sidecar.rs:130-131` and similar — `format!("VictoriaLogs exceeded max consecutive failures; giving up")` triggers `clippy::needless_format` and `format!("{:?}")` (`?backoff` is OK).
- New `RuleEntry::from_rule` early-return uses `Option<Self>`; clippy may push for `let Some(c) = … else { return None };` instead of `match`. Confirm during cherry-pick build.

**Recommendation:** Run `cargo clippy --workspace --all-features --tests -- -D warnings` against the cherry-picked tip on release/stg before pushing. Expect 10–30 fires across the new BE files.

### M10 — `LAST_LOG_LEVEL_CHANGE_MS` u64-millis can desync on system clock jumps
`crates/waf-api/src/handlers.rs:723`: uses wall-clock `SystemTime`. Operator NTP correction backwards = cooldown becomes "permanent" until clock catches up; jump forwards = cooldown bypassed.
**Recommendation:** Use `tokio::time::Instant` or `std::time::Instant` (monotonic) instead. Same fix pattern as the sidecar's `run_start = tokio::time::Instant::now()`.

### M11 — `geo-rules.yaml` path mismatch
`crates/waf-api/src/geo_api.rs:20` reads/writes `configs/geo-rules.yaml`, but the access-lists module reads from `rules/access-lists.yaml`. Mixing `configs/` vs `rules/` for similar features is confusing. The doc comment on `geo_api.rs:5` says `rules/geo-rules.yaml` but the code does `configs/geo-rules.yaml`.
**Recommendation:** Pick one location, fix the doc-or-code mismatch. Decide with team-lead whether new rule-data lives under `configs/` or `rules/`.

### M12 — `delete_ban_entry` returns 200 for an IP that never had a ban
`crates/waf-api/src/ddos_api.rs:129`: returns 200 unconditionally. Idempotent DELETE is fine for REST, but combined with C1 (stub) and I6 (no validation) this is an audit gap — operator can't tell whether anything happened.

---

## Clippy catalogue likely-fires (per `[[pattern-clippy-cherry-pick-lint-catalogue-wave3]]`)

Spot-checked the 8 new BE files. Specific predictions for release/stg lint posture:

| Lint | Likely site | Fix |
|------|-------------|-----|
| `uninlined_format_args` | `handlers.rs:734`, several `format!("…{}", e)` calls in YAML helpers | Inline: `format!("…{e}")` |
| `option_if_let_else` | `rules/engine.rs:340-346` (rewritten match) | Probably already OK; verify after cherry-pick |
| `doc_markdown` | Doc comments mentioning `VictoriaLogs`, `CrowdSec`, `AppSec`, `PostgreSQL` without backticks in new modules (`db.rs:1`, `risk_api.rs:1`, `circuit_breaker.rs:1`) | Wrap proper nouns in backticks |
| `significant_drop_tightening` | `transport/client.rs:317` (parking_lot guard around large block) | Scope-narrow the `write()` guard |
| `case_sensitive_file_extension_comparisons` | none observed | — |
| `missing_const_for_fn` | helper fns `default_*_fe` could be const (but they call `json!` macro — likely not const) | leave |
| `drain_collect_for_clear` | none observed | — |
| `type_complexity` | `LogLevelSetter = Arc<dyn Fn(&str) -> anyhow::Result<()> + Send + Sync>` (`state.rs:11`) | Probably already aliased, fine |

Run `cargo clippy --workspace --all-features --tests -- -D warnings` before pushing.

---

## TOP-10 prioritised findings

1. **C1** — stub handlers return success without doing the work (operator deception)
2. **C2** — unbounded YAML writes of user JSON (disk DoS + config corruption)
3. **C3** — `tunnels.protocol` accepts any 3-char string (data integrity)
4. **C4** — `reload_from_registry` is a lie; cluster rule sync is non-functional for DB rules (correctness)
5. **I1** — `Duration::from_mins` violates MSRV policy (CI breaker)
6. **I4** — `replay_request` forwards Authorization headers across cluster boundary (trust-boundary widening)
7. **I2** — sidecar fail-closed promise broken by `tokio::spawn` detach (reliability)
8. **I5** — `list_tunnels` JSON shape change is a breaking API change (compat)
9. **I8** — `challenge_preview` reflects user HTML into iframe (defense-in-depth XSS)
10. **M1** — no role-based authz on new mutation endpoints (authz drift)

## Would-block-merge subset

Block until fixed:
- **C1** (operator deception, easy fix: stub returns `501` + FE disables buttons)
- **C2** (real DoS / corruption risk, needs typed deserialization)
- **C3** (data integrity, one-line CHECK constraint + protocol enum)
- **I1** (CI breaker — won't compile on stg's MSRV-strict pins)
- **I5** (breaks existing tunnels-list consumers on stg)

Acceptable to merge with follow-up tickets (must be filed before merge):
- C4, I2, I4, I8, M1, M6, M8, M9 (security + reliability gaps that need fixing but don't deceive operators or break CI)

## Unresolved questions

1. **Trust model for cluster forwarding (I4):** is "any mTLS peer = full admin trust" intentional? If yes, document in `docs/cluster-protocol.md`. If no, the loopback-bypass is a real authz hole.
2. **Stub vs not-implemented (C1):** does FE plan to ship Phase-1 with these buttons greyed out, or does plumbing-to-real-store land before merge? Affects whether C1 is blocker.
3. **Role-based authz (M1):** is the `viewer` role only used in tests, or are non-admin users created in prod? If only test scaffolding, M1 downgrades to nit.
4. **`reload_from_registry` (C4):** is S4 scaffolding for a follow-up cluster PR, or claimed-functional now? Reviewer-1 already flagged the "dead code" question — this finding is the answer: not strictly dead, but functionally a no-op.
5. **Audit-log loss tolerance (M6):** under attack burst, do we prefer drop-and-warn or backpressure-the-gateway? Threat-model decision, needed before C1 stubs are replaced with real stores.
