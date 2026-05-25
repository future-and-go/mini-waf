# Red-Team: Security & DoS (R1)

## Verdict
**NEEDS_REVISION** — 7 exploitable gaps.

## Findings

### F-S-1 — `/api/reputation/refresh` no auth + per-process gate
**Severity:** CRITICAL
**Attack:** Anonymous POST. phase-04 gate GLOBAL per-process, not per-caller — first attacker locks operator 60s; leaks reload timing. N-node cluster = N parallel refresh storms → upstream feed ban.
**Evidence:** phase-04:28-29, 114-118 (no auth extractor), 252.
**Mitigation:** (1) admin-auth middleware (match `panel_api.rs`); (2) cluster gate via DB advisory lock OR document single-node; (3) audit row on refused calls.
**Phase:** 04

### F-S-2 — Channel exhaustion silent-drop = log blinding
**Severity:** HIGH
**Attack:** Burst > `channel_capacity` (default `parallelism*64` ≈ 256-1024) → `QueueFullDropped` silent. Adversary floods to drop legit BOT-RELAY-TOR rows during real attack.
**Evidence:** phase-01:22, 60; phase-04 lacks drop dashboard.
**Mitigation:** (1) WARN log rate-limited on drops; (2) default floor 4096; (3) docs: drops = attack-in-progress, must alarm.
**Phase:** 01, 04

### F-S-3 — XFF spoof = poisoning + bucket bypass
**Severity:** HIGH
**Attack:** phase-02:179 admits no `trust_xff_from` on main; §2.3 still parses XFF. Attacker sets `X-Forwarded-For: <victim>` → (a) frames victim in `security_events`, (b) rotates XFF to defeat `(client_ip, rule_id)` gate → unbounded writes (chains F-S-4).
**Evidence:** phase-02:113-115, 179.
**Mitigation:** Phase 02 use `peer_addr` only until #74.3 lands. Warn-log if XFF untrusted.
**Phase:** 02

### F-S-4 — IP rotation defeats per-IP gate
**Severity:** HIGH
**Attack:** Botnet rotates source → every `(client_ip, rule_id)` distinct → `try_reserve` always wins → unbounded writes. `max_keys=10k` × 6 rules = 60k rows/window. DB writeback saturates.
**Evidence:** phase-01:24, 129; no global cap.
**Mitigation:** 2nd-layer global token bucket per rule_id (~100 emits/s/rule across all IPs).
**Phase:** 01

### F-S-5 — Detail field XSS + PII leak
**Severity:** HIGH
**Attack:** phase-03:24 "anonymised" — no impl spec. phase-02 emits raw path. Request `/<script>alert(1)</script>?token=secret` → stored in `detail` → stored-XSS admin panel + query secrets persist.
**Evidence:** phase-02 §2.3 raw detail; phase-03:24; phase-04 returns detail unchecked.
**Mitigation:** (1) audit_map structured JSON, strip query-string; (2) detail length cap 4KB at emit; (3) test `path_with_html_chars_escaped`; (4) document FE escape required.
**Phase:** 02, 03

### F-S-6 — TOCTOU enabled-check + GC vs try_reserve
**Severity:** MEDIUM
**Attack:** (a) `is_enabled()` → broadcast → reserve; flip mid-emit → broadcast fired disabled-state. (b) Janitor GC mid-reserve: 2 concurrent emits both miss key, both insert. Plan specs rollback-match but not reserve-vs-GC atomicity.
**Evidence:** phase-01:46-50, 131.
**Mitigation:** (1) single ArcSwap load at entry, snapshot downstream; (2) mandate `DashMap::entry().or_insert_with()`; (3) loom/stress test `concurrent_reserve_with_gc`.
**Phase:** 01

### F-S-7 — `risk_distribution_query` unbounded + no auth
**Severity:** MEDIUM
**Attack:** GET `?hours=720` repeated. phase-04:253 makes index CONDITIONAL. Without index, full-table scan; 20 concurrent calls saturate DB CPU. Auth unspecified.
**Evidence:** phase-04:157-164, 253.
**Mitigation:** (1) mandatory index migration same PR; (2) admin-auth middleware; (3) cap hours at 168 default; (4) `statement_timeout 5s`.
**Phase:** 04

### F-S-8 — 308 over-generalised claim
**Severity:** LOW
**Attack:** Not exploitable here (GET-only). phase-04:251 misleads future POST deprecations — old proxies coerce 308→301 dropping body.
**Evidence:** phase-04:173, 251.
**Mitigation:** Narrow risk-row: "GET-only contract; POST deprecations need body-replay test".
**Phase:** 04

## Phases requiring revision

- **01:** drop-alerts (F-S-2), global token bucket (F-S-4), atomic reserve + snapshot enabled (F-S-6).
- **02:** `peer_addr` only — drop XFF (F-S-3); structured detail + cap + sanitise tests (F-S-5).
- **03:** specify fingerprint algo + detail sanitisation (F-S-5).
- **04:** admin auth both endpoints (F-S-1, F-S-7); cluster gate (F-S-1); mandatory index + hours cap 168 + `statement_timeout` (F-S-7); narrow 308 claim (F-S-8).

## Unresolved questions

- `panel_api.rs` auto-wraps new routes with admin auth, or phase-04 needs explicit middleware?
- Existing global-rate primitive (governor?) in workspace for F-S-4?
- Prod `security_events` row count — index migration needs `CONCURRENTLY`?
