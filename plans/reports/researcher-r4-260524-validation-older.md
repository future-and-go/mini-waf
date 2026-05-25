# R4 — Validation + Older Issues (260524)

Branch: main @ 61a75e6b

## Part 1 — Recent validation/enhancement (#71-#74, #95)

### #71 — VALID (High)
WASM plugin upload accepts unbounded multipart body.
- `crates/waf-api/src/plugins.rs:80-81` — `field.bytes().await` reads full payload into memory; line 66 in same fn reads `name` via `field.text().await` with no length cap.
- `crates/waf-api/src/plugins.rs:111` — only validation is `\0asm` magic-bytes check.
- No `DefaultBodyLimit::max(...)` on the route: `grep -rn "DefaultBodyLimit\|body_limit\|max_body" crates/waf-api/src/` returns zero hits. Default axum body limit is 2MB but `Multipart` extractor disables it (DEFAULT_BODY_LIMIT_DISABLED) — so genuinely unbounded.
- Field name + version + description also accepted without cap → row-bloat vector also valid.

### #72 — VALID (High)
`upload_certificate` persists raw PEM with zero validation, then flips status to `"active"`.
- `crates/waf-api/src/handlers.rs:584-596` — handler body is `db.create_certificate(req.clone()).await?; db.update_certificate_status(row.id, "active", None).await?;` — no `rustls_pemfile::certs`/`pkcs8_private_keys` call, no key/cert pair check, no SAN/domain match, no length cap.
- `CreateCertificate` (waf-storage models) takes `Option<String>` for cert/key/chain — no field-level validation.
- Confirmed live-on-main; impacts cert reload (parse error at gateway loader) and DB bloat.

### #73 — VALID (High)
- `crates/waf-engine/src/rules/engine.rs:653` — `(Operator::Regex, ConditionValue::Str(v)) => Regex::new(v).ok().is_some_and(|r| r.is_match(fstr))` — compiles per call, no `size_limit`.
- For contrast, the same file at line 902 uses `RegexBuilder::new(s).size_limit(1 << 20).build()` (the `Matcher::Regex` precompile path); the 653 path bypasses that cache because `eval_one` re-enters with raw `ConditionValue::Str(v)` rather than the precompiled matcher.
- `crates/waf-engine/src/checks/tx_velocity/role_tagger.rs:39` — `Regex::new(&rule.path)`. Note this one compiles at startup (in `compile()`), so memory blow-up is bounded to load-time + per-rule, but the missing `size_limit` claim still holds; severity is lower than the engine.rs hot path.

### #74 — Sub-items verified separately:

1. **WS cap 50 global** — VALID. `crates/waf-api/src/websocket.rs:121` checks `current >= MAX_WS_CONNECTIONS` against a single `state.ws_connections` AtomicU32 with no per-user `DashMap`.
2. **WS JWT in query param** — VALID but mitigated. `websocket.rs:67-91` still accepts `?token=`; warn-log at line 91, comment at line 10 says "deprecated — token may appear in logs". Not removed yet.
3. **Rate limiter uses TCP peer IP, no XFF** — VALID. `crates/waf-api/src/security.rs:234-238` reads `ConnectInfo<SocketAddr>` only; no XFF parse, no `trust_xff_from` config knob.
4. **Heatmap `path_ranks` missing `rule_id IS NOT NULL`** — FIXED. `crates/waf-storage/src/repo.rs:1527-1535` `path_ranks` CTE still has no `rule_id IS NOT NULL`, BUT line 1554-1555 `scoped` CTE adds `AND rule_id IS NOT NULL` and joins via `IN (SELECT path FROM path_ranks)`. Net effect: top-20 paths are still ranked over ALL events incl. `/health`, so the issue's concern (noisy paths crowd out top-N attack paths) **remains valid** — partial fix only.
5. **`stats_overview` live override** — VALID. `crates/waf-api/src/stats.rs:117-126` still has `if total_requests_live > 0 { live } else { db }` with no `q.host_code.is_some() || q.action.is_some()` guard.
6. **`get_stats_timeseries_by_category` inline CASE** — VALID. `crates/waf-storage/src/repo.rs:1342-1390` still uses inline `CASE WHEN rule_id LIKE 'SQLI-%' ...`. Other functions (lines 1170, 1255, 1538-1549) use `category_of(rule_id)` — confirms drift.
7. **Per-route body limit for admin** — VALID (same root as #71).

Verdict #74: **VALID overall** (5/7 sub-items still actionable; sub-item 4 is partially mitigated, not closed).

### #95 — SCOPE_DEFERRED (enhancement, not a bug)
- `git grep "SslManager::new" crates/prx-waf` returns 0 hits in main (verified).
- Architecture decision pending (paths A/B/C/D). PR #89/#90 merged native-TLS-via-TOML approach then PR #96 reverted.
- Active branch `feat/native-tls-vendor-patch-phase-01-issue-95` (current checked-out branch) is Phase 1 work toward Path A vendored `with_cert_resolver`.
- Recommendation: **keep OPEN as roadmap item**. Note PR #89→#96 revert history in any close summary; do not close until Path A/B is shipped.

---

## Part 2 — Older FR/review issues (#60, #57, #47, #43, #20, #13, #11, #9, #8, #7)

### #60 (Admin Panel Missing FR Coverage) — TRACK_OPEN (partial)
**Evidence:** Challenge engine backend exists (`crates/waf-engine/src/challenge/{config.rs,pow.rs}`), `challenge_type` configurable via `settings/index.tsx`, but no dedicated challenge stats page under `web/admin-panel/src/pages/` (no `challenges/` directory). Body covers multiple FR-006/etc. UI gaps — needs per-FR sub-issue audit; not fully closed.

### #57 (Review WAF Rule Priority) — STALE / TRACK_OPEN (doc-only)
**Evidence:** Design doc / spec issue. Rule priority is implemented (rules sorted by `priority`); doc not living in `docs/`. Either link to `docs/request-pipeline-guide.md` and close, or copy to `docs/`.

### #47 (Review Core built) — STALE
**Evidence:** Tabular gap audit from 2026-05-06. Most "Genuinely missing" cells (FR-006 challenge, FR-010 fingerprint, FR-025/026/027 risk) now exist: `crates/waf-engine/src/challenge/`, `crates/waf-engine/src/device_fp/`, `crates/waf-engine/src/risk/`. Snapshot superseded; close as STALE.

### #43 (Security Logs: show rule_name / rule_id) — TRACK_OPEN
**Evidence:** Backend emits `rule_name` + `rule_id` (`crates/waf-engine/src/logging/audit_sender.rs:56,113-116`). Issue is about VictoriaLogs default query mixing `waf_tracing` stream into Security Logs page. UI fix likely still required — no `stream:` filter found in `web/admin-panel/src/pages/logs/` quick scan needed. Keep open until UI default-query change is shipped.

### #20 (Build Order) — STALE
**Evidence:** Roadmap snapshot from 2026-04-29. FR-001..FR-012 implemented (proxy, tier, rule engine, whitelist, relay, fingerprint, rate-limit, cache, behavioral, tx-velocity, ddos, challenge — see `crates/waf-engine/src/{challenge,device_fp,relay,access,checks/{rate_limit,tx_velocity,ddos}}`). Build order completed; close.

### #13 (FR-001: Full Reverse Proxy) — DONE
**Evidence:** Design doc from 2026-04-24. Pingora-based reverse proxy live (`crates/gateway/`, `crates/prx-waf/`). HTTP/1.1+2+WS supported; HTTP/3 partial (per Pingora vendor). Close or convert to docs PR.

### #11 (custom rule) — STALE / DOC
**Evidence:** Code walkthrough doc from 2026-04-23. Custom rules engine exists (`crates/waf-engine/src/rules/engine.rs`); both YAML + DB rules implemented. Move content to `docs/custom-rules-syntax.md` (already exists) and close.

### #9 (Requirement Gap Analysis) — STALE
**Evidence:** Gap analysis from 2026-04-21 listing 9 P0 MISSING FRs. Per current `crates/waf-engine/src/` directory, FR-006 (challenge), FR-010 (device_fp), FR-011 (behavioral via `checks/`), FR-012 (tx_velocity), FR-005 (ddos) all present. Superseded by current implementation; close.

### #8 (WAF Dashboard — Data Model & API Spec) — STALE / DONE
**Evidence:** Spec doc 2026-04-20. Dashboard API endpoints implemented (`crates/waf-api/src/stats.rs`, `panel_api.rs`, `notifications.rs`); migrations 0004-0015 cover data model. Close as superseded by shipped implementation.

### #7 (Dashboard Design Mockup) — STALE / DONE
**Evidence:** Mockup spec 2026-04-20. Admin panel pages exist for all major sections (`web/admin-panel/src/pages/{dashboard,security-events,rule-analytics,custom-rules,ip-rules,url-rules,bot-management,cc-protection,tx-velocity,...}`). Close as superseded.

---

## Summary table

| Issue | Verdict       | Action                                                                 |
|-------|---------------|------------------------------------------------------------------------|
| #71   | VALID         | Cap multipart body (`DefaultBodyLimit::max(16MB)`), stream-check size  |
| #72   | VALID         | Parse PEM via `rustls_pemfile` + key/cert match + SAN check pre-insert |
| #73   | VALID         | Use `RegexBuilder::size_limit(1<<20)` in `engine.rs:653`; cache compiled regex per condition |
| #74.1 | VALID         | Per-user WS cap                                                        |
| #74.2 | VALID         | Remove/deprecate `?token=` query param for WS                          |
| #74.3 | VALID         | Add `trust_xff_from` allowlist for admin rate limit                    |
| #74.4 | VALID (partial-mitigated) | Add `AND rule_id IS NOT NULL` to `path_ranks` CTE         |
| #74.5 | VALID         | Prefer DB totals when query filter active in `stats_overview`          |
| #74.6 | VALID         | Refactor `get_stats_timeseries_by_category` to use `category_of()`     |
| #74.7 | VALID         | Per-route body limits across admin API                                 |
| #95   | SCOPE_DEFERRED| Keep OPEN; track via `feat/native-tls-vendor-patch-phase-01-issue-95`  |
| #60   | TRACK_OPEN    | Per-FR sub-issue audit (challenge stats UI page missing)               |
| #57   | STALE         | Move doc into `docs/`; close issue                                     |
| #47   | STALE         | Close — gap snapshot superseded                                        |
| #43   | TRACK_OPEN    | UI default-query change for VictoriaLogs Security Logs page            |
| #20   | STALE         | Close — build order done                                               |
| #13   | DONE          | Close — FR-001 shipped (HTTP/3 partial)                                |
| #11   | STALE/DOC     | Close — content already in `docs/custom-rules-syntax.md`               |
| #9    | STALE         | Close — P0 FRs implemented                                             |
| #8    | STALE/DONE    | Close — dashboard API + migrations shipped                             |
| #7    | STALE/DONE    | Close — admin panel pages shipped                                      |

## Unresolved questions

- #74.4 heatmap: original report says "noisy paths chiếm slot top-20"; current code restricts `scoped` to `rule_id IS NOT NULL` but `path_ranks` itself still ranks ALL events. Is partial mitigation acceptable, or does the spec require top-20 to be attack-paths-only? — needs product call.
- #95 path decision (A/B/C/D) — currently on Phase 1 of Path A (vendor patch). Confirm with team-lead this is the chosen path before closing/relabeling.
- #43 needs a check on the actual VictoriaLogs default query in admin-panel (didn't grep `logs/index.tsx`) — keep open pending UI verification.
