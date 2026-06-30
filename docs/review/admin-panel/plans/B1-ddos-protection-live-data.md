# B1 — DDoS Protection: live metrics, ban table, working unban

**G.1 rows:** 7, 8, 9 · **Req IDs:** FR-005 (DDoS protection), FR-004 (rate
limiting) · **Lane:** normal

> Companion: spec §B1. Follows [`ARCHITECTURE.md`](../../../ARCHITECTURE.md)
> (command/query, observability) and [`CONTEXT_RULES.md`](../../../CONTEXT_RULES.md).

---

## 1. Codebase audit (current state)

**Frontend** (`web/admin-panel/src/pages/ddos-protection/index.tsx`):
- `GET /api/ddos/config` + `PUT /api/ddos/config` — **real**.
- `GET /api/ddos/metrics` (5s poll) expects `DdosMetrics` (lines 52-57):
  `{ active_bans, bursts_1h, bans_issued_1h, store_errors }`.
- `GET /api/ddos/ban-table` expects `{ data: BanEntry[] }`; `BanEntry`
  (lines 44-50): `{ ip, banned_until_ms, ban_level, last_rps, reason }`.
- `DELETE /api/ddos/ban-table/{ip}` — Unban button (URI-encoded ip).

**Backend reality** (`crates/waf-api/src/ddos_api.rs`):
- `get_ddos_metrics` (line 75) → hardcoded zeros; ignores state (`_:`).
- `list_ban_table` (line 82) → `{ data: [], total: 0 }`.
- `delete_ban_entry` (line 92) → only `tracing::info!`, no state change.
- Routes already registered (`server.rs:281-283`); **no route change needed**.

**Engine reality:**
- `engine.ddos_ban_table()` → `&Arc<DynamicBanTable>`
  (`engine.rs:389-393`). `DynamicBanTable` = `DashMap<IpAddr, i64>`
  (ip → `expires_ms`) with `insert, contains, purge_expired, len, is_empty,
  clear` (`checks/ddos/action/ban.rs:27-74`). **No iterator/snapshot, no
  `get(ip)`, no `remove(ip)`.**
- **No per-entry `ban_level`/`last_rps`/`reason` are persisted** — the table
  stores expiry only. `ban_level` (offense step) lives in a separate
  `CounterStore` key `ddos:offense:{ip}`; `last_rps`/`reason` are computed only
  at ban time inside `BanAction::execute` and discarded.
- `engine.ddos_metrics()` → `&Arc<DdosMetrics>` (`engine.rs:383-387`). Fields
  (`checks/ddos/metrics.rs:17-34`): `burst_total, burst_per_ip, burst_per_fp,
  burst_per_tier, bans_active, bans_total, store_errors, degrade_events`
  (lifetime `AtomicU64`, **no 1-hour windowing**). Accessors at lines 89-127.
- `reset_runtime_state` (`engine.rs:536-543`) clears the whole ban table.
- **Known drift:** `dec_bans_active()` is never called in production, so
  `bans_active` over-counts after bans expire. `inc_store_error()` is likewise
  never called from prod DDoS code.

## 2. Gap

- Metrics handler ignores the real `DdosMetrics`; field names differ
  (`active_bans` vs `bans_active`, `bursts_1h` vs `burst_total`) and the FE
  expects 1h windows the engine doesn't keep.
- Ban table can't be enumerated (no iterator) and per-entry `ban_level/last_rps/
  reason` aren't stored.
- Unban can't remove a single IP (`remove(ip)` missing).

## 3. Assumptions (explicit)

- A-1: It's acceptable for `active_bans` to be the **live** count
  `ddos_ban_table().len()` (after pruning expired), which is more honest than the
  drifting `bans_active` metric.
- A-2: For `bursts_1h`/`bans_issued_1h`, **either** (a) expose lifetime totals
  and relabel the cards in the FE to "since start", **or** (b) add a small
  rolling-1h ring counter. This plan defaults to **(a)** (minimal, honest) and
  flags (b) as optional.
- A-3: `ban_level/last_rps/reason` are not currently persisted. Default to:
  enrich `DynamicBanTable` to store a small struct so these become real (A-3a),
  **or** return `ban_level=0,last_rps=0,reason="dynamic"` placeholders (A-3b).
  This plan does **A-3a** (small, contained data-model change in-memory) because
  the FE already renders these columns.
- A-4: No external store (Redis) is in play for v1 (config `store.backend` may be
  redis but the live table is in-memory `DashMap`).

## 4. Scope

**In scope:** add `snapshot()`/`iter` + `remove(ip)` (+ optional entry struct)
to `DynamicBanTable`; rewrite the three handlers to read/mutate real state; map
metrics; keep routes unchanged.

**Out of scope:** Redis-backed ban store; cluster-wide ban sync; rolling-window
metrics unless A-2(b) is chosen; changing detection thresholds (that's
`/api/ddos/config`).

## 5. Phased plan (independently testable & reversible)

### Phase 1 — Extend `DynamicBanTable` (engine, pure)
- Add `remove(&self, ip: IpAddr) -> bool` and
  `snapshot(&self, now_ms) -> Vec<BanRow>` (filtering expired). If A-3a:
  change the value type to a small `struct BanState { expires_ms, ban_level,
  last_rps, reason }` and update `insert` call sites in `BanAction::execute`
  to pass the offense step/rps/reason already computed there.
- **Success:** unit tests — insert N, snapshot returns N non-expired rows;
  `remove` deletes one and returns true, false for absent; expired rows excluded.
- **Reversible:** new methods are additive; if A-3a destabilizes, fall back to
  A-3b (value stays `i64`) without touching the API layer.

### Phase 2 — `GET /api/ddos/metrics` from real counters
- Rewrite handler to take `State`, read `engine.ddos_metrics()` +
  `ddos_ban_table().len()`. Map: `active_bans = ban_table.len()`,
  `bursts_1h = burst_total()`, `bans_issued_1h = bans_total()`,
  `store_errors = store_errors()`.
- **Success:** with a seeded ban + a simulated burst, the four numbers are
  non-zero and match engine accessors (integration test asserting equality).
- **Reversible:** revert handler body.

### Phase 3 — `GET /api/ddos/ban-table` enumerates live bans
- Rewrite to return `{ data: snapshot(now), total }` mapped to `BanEntry`
  (`banned_until_ms = expires_ms`).
- **Success:** ban an IP in a test → it appears with correct
  `banned_until_ms`; `active_bans` KPI equals table length.
- **Reversible:** revert handler body.

### Phase 4 — `DELETE /api/ddos/ban-table/{ip}` actually unbans
- Parse `ip` at boundary (`IpAddr::from_str`; 400 on bad input), call
  `ban_table.remove(ip)`; if A-3a/metrics, `dec_bans_active(1)` on success.
  Return `{ success, data: { ip } }`.
- **Success:** after DELETE, the next `GET /api/ddos/ban-table` no longer lists
  the IP and `active_bans` decremented; DELETE of an absent IP returns success
  idempotently (or 404 — pick one; this plan: idempotent 200).
- **Reversible:** revert handler body.

## 6. Edge cases & failure modes

- Malformed IP in DELETE path → 400, no state change.
- IPv6 / zone ids → `IpAddr` parse handles; FE already URI-encodes.
- Race: entry expires between snapshot and DELETE → `remove` returns false →
  idempotent success.
- Empty table → `[]` + zero KPIs (not an error).
- Metric overflow (`AtomicU64`) → not a practical concern; document monotonicity.
- If A-2(a): cards labeled "1h" while showing lifetime totals would mislead —
  **must** update the FE labels in the same change.

## 7. Security

- All endpoints behind `require_auth`. DELETE is a state mutation → record an
  admin audit entry (`action="ddos.unban", resource_id=ip`).
- Do not expose internal counter names or store internals in the response.
- Unban is operator-initiated removal of a protection; log it at `info` with
  `request_id` + admin user.

## 8. Observability

- Canonical per-request JSON log for each handler.
- On unban, emit admin audit (command side owns audit — ARCHITECTURE).
- Consider wiring `dec_bans_active` into the existing purge path so the metric
  stops drifting (small fix; note it even if deferred — surgical-change rule).

## 9. Production-readiness gaps

- In-memory ban table is per-process; multi-node deployments (FR-043/044) won't
  share bans — out of scope here but must be flagged for prod.
- `bans_active` drift (no `dec` on expiry) is a pre-existing bug; this plan
  switches the KPI to `len()` to avoid surfacing it, and recommends fixing the
  decrement separately.
- Rolling-1h metrics (A-2b) are what the FE labels imply; without them the cards
  are lifetime totals.

## 10. Harness intake

- **Lane:** normal (observability + existing behavior; no schema migration —
  the entry struct is in-memory). A-3a touches "existing behavior" (ban insert
  call sites) → add stronger tests.
- **Story:** `docs/stories/epics/` under FR-005 (E14 enforcement or new
  `E18-admin-api-completeness`); from `docs/templates/story.md`.
- **Validation:** unit (`DynamicBanTable`), integration (burst→ban→list→unban),
  KPI equality assertions. Record with `harness-cli story update`.
