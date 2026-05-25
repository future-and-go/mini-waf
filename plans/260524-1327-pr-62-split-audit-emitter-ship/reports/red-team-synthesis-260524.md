---
report: red-team-synthesis
plan: pr-62-split-audit-emitter-ship
date: 2026-05-24
reviewers: 3 (Security R1, API contract R2, Failure modes R3)
findings: 24 (CRITICAL 2 / BLOCKER 1 / HIGH 11 / MED 8 / LOW 2)
---

# Red-Team Synthesis — Accept / Defer / User-Decision

## Accept (auto-apply to plan)

### Phase 01 (audit_emitter core)
| ID | Severity | Change |
|---|---|---|
| F-F-3 | CRITICAL | Startup invariant: if `enabled=true` AND zero callers wired → `warn!`; test `enabled_with_no_callers_logs_warning` |
| F-S-2 | HIGH | `channel_capacity` default floor 4096 (was `parallelism*64`); WARN log every `QueueFullDropped` increment |
| F-S-4 | HIGH | 2nd-layer global token bucket per `rule_id` (~100 emits/s/rule across all IPs) — guards IP-rotation bypass |
| F-S-6 | MED | Single `cfg.load_full()` at emit entry; downstream all reads from snapshot; mandate `DashMap::entry().or_insert_with()` |
| F-F-1 | HIGH | Each counter `inc_*` pairs with `tracing::warn!(target="audit_emitter")` or `error!` for panics |
| F-F-6 | MED | Use `load_full()` not `load()` in `emit()` — avoids torn reads |
| F-F-7 | HIGH | Bucket key = `(u128, &'static str)` Copy (IPv4 via `to_ipv6_mapped`); zero-alloc hot path |
| F-F-9 | MED | `FeedStatusRegistry` moved from phase 02 → phase 01 (`crates/waf-engine/src/intel_status.rs`, empty default); phase 02 populates; **phase 04 blockedBy [1] not [2]** |
| F-F-5 | MED | Replace 2s wall-clock panic test với `tokio::test(start_paused=true)` + `time::advance(POST_PANIC_BACKOFF + 1ms)` |
| F-F-12 | MED | Step 0: `cargo tree -p waf-engine` + `-p waf-storage` to verify no dep cycle |
| F-A-3 | HIGH | Regex contract test at emit: `^[A-Z]+-[A-Z]+-\d{3}$`; fail loud in tests, log+drop in prod |

### Phase 02 (relay wiring)
| ID | Severity | Change |
|---|---|---|
| F-S-3 | HIGH | Use `peer_addr` ONLY for `audit_ctx.client_ip`; drop XFF parse until #74.3 lands `trust_xff_from` config; warn-log nếu untrusted XFF present |
| F-S-5 | HIGH | `audit_map` returns structured JSON detail; strip query-string from path; 4KB length cap; test `path_with_html_chars_safely_encoded` |
| F-A-3 | HIGH | Rename `BOT-RELAY-TOR-001` → `BOT-TOR-001` (per user); update `docs/PRX-WAF-TechnicalGuide-{EN,VI}.md` in same PR |
| F-F-10 | LOW | Tech guide update IN same PR (not post-merge follow-up) |

### Phase 03 (tx_velocity wiring)
| ID | Severity | Change |
|---|---|---|
| F-S-5 | HIGH | Spec session-key fingerprint: HMAC-SHA256 (key from JWT secret), truncate 16 hex chars; emit as `detail.session_fp` (not raw); 4KB cap |
| F-F-10 | LOW | Tech guide update IN same PR |

### Phase 04 (admin API)
| ID | Severity | Change |
|---|---|---|
| F-S-1 | CRITICAL | Both endpoints behind admin-auth middleware (match `panel_api.rs` pattern); cluster-aware refresh gate via DB advisory lock (`pg_try_advisory_lock`) OR document single-node-only constraint |
| F-S-7 | MED | Mandatory index migration in same PR: `CREATE INDEX CONCURRENTLY ON security_events(created_at, host_code, action)`; `SET LOCAL statement_timeout = '5s'`; cap `hours` default 168 (was 720) |
| F-A-1 | BLOCKER | **2-step deprecation per user**: this release `GET /api/threat-intel/status` returns 200 + same JSON shape + `Deprecation: true` + `Sunset: <90 days>` + `Link: </api/reputation/status>; rel=successor-version` (RFC 9745 / 8594). 308 deferred to next release. |
| F-A-2 | HIGH | Keep `message: String` field in `/api/reputation/status` response |
| F-A-4 | HIGH | Response shape: `{success, data: {allow, challenge, block, approximation: true, unavailable_bands: ["elevated"]}}` — explicit array, no `elevated: 0` |
| F-A-5 | HIGH | Refresh within rate-limit window: return 200 + `data.refresh_skipped: true` + `data.next_refresh_allowed_at: <iso>` |
| F-A-6 | MED | POST body: empty OR `application/json` + `{}`; `#[serde(deny_unknown_fields)]` on schema |
| F-A-7 | MED | New endpoints include `data.api_version: "v2"` / `data.schema: "reputation.v1"` positive marker |
| F-A-9 | MED | Use path-relative `Location: ./reputation/status` (reverse-proxy prefix safe); integration test under simulated `/admin/` mount |
| F-F-2 | HIGH | Add `GET /api/audit/metrics` (admin-auth) returning JSON snapshot: `{emitted, rate_limited, queue_full_dropped, db_insert_failed, worker_restarted}` |

### Plan-wide
| ID | Severity | Change |
|---|---|---|
| F-A-10 | LOW | BP5 reworded with RFC 9745 `Deprecation` + RFC 8594 `Sunset` 90-day window. Drop non-standard `X-Deprecated` header. |
| F-F-4 | MED | Mock for unit tests + testcontainers Postgres smoke (per phase, CI-required, EXCLUDED from coverage gate) — hybrid per user |
| F-F-8 | HIGH | Phase 01 Step 0: inline CI pre-flight (`cat .github/workflows/ci.yml | grep rust-toolchain`); update CI workflow in same PR if mismatch |

## User decisions (reversed/scope-expanded per audit)

| Finding | User original | Audit ask | Decision | Applied |
|---|---|---|---|---|
| F-A-1 | "308 + X-Deprecated" (BP5) | 2-step deprecation (200 first, 308 later) | **Hybrid 2-step (recommended)** | Yes |
| F-A-3 | implicit (tech guide uses `BOT-RELAY-TOR-001`) | Rename `BOT-TOR-001` 3-segment grammar | **Rename per recommended** | Yes |
| F-F-2 | scope = 3 endpoints | Add `/api/audit/metrics` | **Add to phase 04** | Yes |
| F-F-11 | rules.md item 10 "1 commit per PR" | Keep 4 logical commits >500 LOC | **Keep rules — 1 commit per PR** | No (declined audit) |
| F-F-4 | rules.md item 6 "create mocks" | testcontainers Postgres smoke | **Hybrid (mock + smoke, smoke excluded from coverage gate)** | Yes |
| F-F-8 | scope = 4 PRs | Phase 00 CI pre-flight PR-0 | **Inline trong phase 01 Step 0 (no 5th PR)** | Yes |

## Defer (not in scope this round)

| ID | Reason |
|---|---|
| F-S-8 | "GET only" current scope; revisit when first POST deprecation lands |
| F-F-11 | User declined audit; rules.md item 10 unchanged |

## Net plan deltas

- **Phase 01**: +1 module `intel_status.rs`, +regex contract test, +CI pre-flight, +Postgres smoke, +tracing on counters, key type change, +1 layer of global rate-limit. LOC est revised: 900 → **~1200** (cap raised; still single PR).
- **Phase 02**: -FeedStatusRegistry (moved), +F-S-5 sanitise, +rename `BOT-TOR-001`, +tech guide update. LOC: 600 → **~550**.
- **Phase 03**: +session fingerprint HMAC, +tech guide update. LOC: 700 → **~750**.
- **Phase 04**: +admin-auth wire, +index migration, +`/api/audit/metrics`, +2-step deprecation (200 not 308), +response shape adjustments. LOC: 700 → **~900**.
- **Plan.md**: BP5 reworded, +BP6 rule_id regex, +BP7 observability invariant, dependency graph updated (phase 04 blockedBy [1]).
- **Total LOC est**: ~3400 (was ~2900). Still 43% below PR #62 5078.

## Unresolved questions (carry to next phase)

- `panel_api.rs` auto-wrap admin auth, hay phase-04 explicit middleware? (need code-read confirm)
- Workspace có sẵn governor / rate-limit primitive cho F-S-4? (or write inline)
- Prometheus exposition format hay JSON-only cho `/api/audit/metrics`? (likely JSON theo existing convention; Prometheus separate sub-issue)
- Production `security_events` row count → `CREATE INDEX CONCURRENTLY` đủ hay cần off-peak? (phase 04 verify on staging trước)
- Reverse-proxy mount prefix có dùng prod không? (affects F-A-9 testing scope)
