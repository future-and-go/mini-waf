# Admin Panel — Frontend ↔ Backend Gap Review

**Date:** 2026-06-25
**Scope:** `web/admin-panel/src/pages/**` reviewed against the live `waf-api` backend.
**Method:** Static cross-reference of every page's API calls against the real route table in `crates/waf-api/src/*.rs`, plus **live verification** against the running Docker instance at `https://localhost:16827` (logged in as `admin`).

> Goal of this report: identify detail screens that **render UI but are not actually backed by a working backend endpoint** — i.e. screens that call routes that don't exist (404), display hardcoded/stubbed data, or are write-only / mislabeled.

---

## How to read severity

| Severity | Meaning |
| --- | --- |
| 🔴 **BROKEN** | The screen (or a major section) calls an endpoint that **does not exist** → 404 at runtime. UI is dead. |
| 🟠 **STUB** | The endpoint exists and returns `200`, but the backend handler returns **hardcoded zeros / empty data**. UI renders but the numbers are always fake. |
| 🟡 **PARTIAL / MISLABELED** | Wired to real routes, but a feature is write-only, mislabeled, or a sub-feature has no backend. |
| 🔵 **COSMETIC** | Intentionally static / client-side data with no backend feed (by design, but presented as if live). |
| ✅ **OK** | Fully wired to existing, working endpoints. |

Live verification was run for every 🔴 / 🟠 item below (HTTP status quoted). Note: the events/stats tables are empty in this instance (no traffic yet), so data-correctness of *working* endpoints was verified at the SQL/struct level, not by row counts.

---

## Executive summary

- **2 screens are outright BROKEN** (call non-existent endpoints → 404): **Logs** (entire page) and **Response Filtering** (Preview widget + entire Per-Host tab).
- **2 screens are STUBS** (endpoint returns hardcoded zeros/empty): **DDoS Protection** (metrics, ban table, unban) and **Challenge Engine** (stats KPIs).
- **1 screen is MISLABELED + write-only**: **CC Protection** makes zero CC/rate-limit calls; it's really an LB-backends + anti-hotlink editor, and the hotlink form never reads back saved state.
- **Several COSMETIC panels** present static/hardcoded data as if it were live: Dashboard "Detection Engines", Enforcement "Plane Map", Settings "Threat-Intel feeds", Geo "Top Blocked (24h)".
- **~28 screens are fully working** and correctly wired.
- A handful of backend endpoints exist but **no frontend screen uses them** (notably `/api/audit-log`, `/api/device-fp/conflicts`, several `/api/cache/*`).

---

## 🔴 BROKEN — calls endpoints that return 404

### 1. Logs (`pages/logs/`) — entire page is dead
The whole page is wired to the decommissioned VictoriaLogs API. All three endpoints were intentionally removed (`docs/decisions/0010-decommission-victorialogs.md`, Accepted; `crates/waf-api/src/logs.rs` deleted).

| Call | Source | Live result |
| --- | --- | --- |
| `GET /api/v1/logs/query` | `victoria-logs-data-provider.ts`, `logs/index.tsx:99` | **HTTP 404** |
| `GET /api/v1/logs/stats` | `logs/index.tsx:42` | **HTTP 404** |
| `GET /api/v1/logs/streams` | `logs/LogsFilters.tsx:88` | **HTTP 404** |

Consequence: the log table, the "Entries (24h)" stat, the filter dropdowns, the LogsQL query bar, the column picker — **none of it can ever load data**. The "VictoriaLogs is disabled" alert only fires on a `400 disabled` body; since the routes 404, even that empty-state renders incorrectly.

**The replacement endpoint `GET /api/audit-log` exists and returns `200 {"entries":[],"total":0}` — but no page consumes it.**

➡️ **Fix path:** either rebuild the Logs page on top of `/api/audit-log` (+ the JSONL file sink), or remove the page and its `victoria-logs-data-provider.ts` entirely.

### 2. Response Filtering (`pages/response-filtering/`) — Preview + Per-Host tab dead
The Global tab (backed by `/api/panel-config`) may work, but two of its three features call routes that do not exist.

| Call | Source | Live result |
| --- | --- | --- |
| `POST /api/response-filtering/preview` | `index.tsx:168` (Preview widget) | **HTTP 404** |
| `GET /api/hosts/{id}/response-filter` | `index.tsx:312` (Per-Host load) | **HTTP 404** |
| `PUT /api/hosts/{id}/response-filter` | `index.tsx:343` (Per-Host save) | **HTTP 404** (no such subresource; only `/api/hosts/{id}` exists) |
| `GET/PUT /api/panel-config` | Global tab | ✅ exists |

Consequence: the **Preview** button always shows `Error:…`, and the **entire Per-Host tab** errors on host-select (load 404) and on Save (404). Also unverified: whether `panel-config` actually persists a `response_filtering` key (the route is generic).

---

## 🟠 STUB — endpoint exists but returns hardcoded data

### 3. DDoS Protection (`pages/ddos-protection/`) — metrics + ban table + unban are stubs
Config save/load is real (`/api/ddos/config` reads/writes `configs/ddos.yaml`). Everything *operational* is hardcoded:

| Call | Live result | Backend source |
| --- | --- | --- |
| `GET /api/ddos/metrics` | `{"active_bans":0,"bans_issued_1h":0,"bursts_1h":0,"store_errors":0}` | hardcoded zeros — `ddos_api.rs:75` |
| `GET /api/ddos/ban-table` | `{"data":[],"total":0}` | explicit **"STUB — v1 placeholder"** — `ddos_api.rs:82` |
| `DELETE /api/ddos/ban-table/{ip}` | `200` but only `tracing::info!("Manual unban")` | no state change — `ddos_api.rs:92` |
| `GET/PUT /api/ddos/config` | real | `ddos_api.rs` ✅ |

Consequence: the 4 KPI cards always show **0**; the ban table is **always empty**; the IP/level filters filter nothing; the **Unban button is a no-op**.

### 4. Challenge Engine (`pages/challenge-engine/`) — stats are stubs
Config save/load and HTML preview are real. The stats dashboard is not.

| Call | Live result | Backend source |
| --- | --- | --- |
| `GET /api/challenge/stats` | `{"issued":0,"passed":0,"failed":0,"replays":0}` | hardcoded zeros — `challenge_api.rs:133` |
| `GET/PUT /api/challenge/config` | real | ✅ |
| `POST /api/challenge/preview` | real HTML | ✅ |

Other gaps on this page:
- Challenge types **`pow` (Proof of Work)** and **`captcha`** are hardcoded `disabled: true` "Coming soon" (`index.tsx:243`) — only `js_challenge` is usable.
- The preview uses a bare `fetch()` (`index.tsx:110`) instead of the shared `httpClient`, so it **sends no bearer token** — if the route is auth-gated it would 401 (falls back to "Preview unavailable").

---

## 🟡 PARTIAL / MISLABELED

### 5. CC Protection (`pages/cc-protection/`) — mislabeled + write-only form
- The page is titled/routed **"CC Protection"** but makes **zero CC / rate-limit / DDoS / challenge calls**. There is no `/api/cc-*` route at all. It actually only does:
  - `GET/POST /api/lb-backends`, `DELETE /api/lb-backends/{id}` (load-balancer backends) ✅
  - `POST /api/hotlink-config` (anti-hotlink) ✅ (route exists)
- The real CC (HTTP-flood) controls live in **Hosts** `defense_json` (`cc`, `cc_rps`, `cc_burst`, `cc_ban_threshold`) and in the DDoS/Challenge endpoints — none of which this page touches.
- **Hotlink form is write-only:** it `POST`s but **never `GET`s** existing config. `GET /api/hotlink-config?host_code=default` exists and returns `200 {"data":null}`, but the FE ignores it and always renders hardcoded defaults (`enabled:true, allow_empty_referer:true`, `index.tsx:159`). Saved server state is never reflected back.

➡️ **Recommendation:** rename the page (e.g. "Load Balancer & Anti-Hotlink"), or actually wire it to the CC/DDoS controls its name implies; and make the hotlink form load existing config.

### 6. TX Velocity (`pages/tx-velocity/`) — works via security-events, but config card is dead
- KPIs and table query `/api/security-events?rule_id_prefix=TX-…`. **Verified: `rule_id_prefix` IS a supported server-side filter** (`SecurityEventQuery`, `crates/waf-storage/src/models.rs:323`), so the data path is genuinely wired. (Empty in this instance only because there's no traffic.)
- The **"Config thresholds" card is a non-functional placeholder** — explicitly read-only (`index.tsx:268`), values are i18n strings, and it tells the user to hand-edit `configs/tx-velocity.yaml`. There is no read or write API for these thresholds.

---

## 🔵 COSMETIC — static/hardcoded data presented as live

| # | Screen | Issue | Location |
| --- | --- | --- | --- |
| 7 | **Dashboard** | "Detection Engines" panel is a **hardcoded static array** with `enabled:true` baked in — every engine always shows green regardless of real config. No API feeds it. | `dashboard/index.tsx:49-64` |
| 8 | **Enforcement → Plane Map** | Entire table fed by a **hardcoded `GOVERNANCE_MAP`**; the "Control Plane" column renders an unconditional green check (`render: () => yes`). No backend call at all. | `enforcement/plane-map.tsx:7,55` |
| 9 | **Settings → Threat Intel** | Feed table is **synthesized client-side** by grouping `/api/rules/registry` rules by `source` (no real feeds API); hardcoded "No live API available" fallback alert. "API Connection Info" card hardcodes `:9527` URLs. | `settings/index.tsx:203-219,864-892` |
| 10 | **Geo Restriction** | Country picker limited to a **hardcoded 31-country map** (`COUNTRY_MAP`) regardless of backend support. "Top Blocked Countries (24h)" is fed by the generic `/api/stats/geo` with **no 24h / no blocked filter** — the label overstates what's returned. | `geo-restriction/index.tsx:54-85,386-410` |

### Client-side approximations (functional, but not backend truth — worth labeling in UI)
These are *not* broken, but they compute in-browser and can diverge from what the engine actually does:
- **Create Rule From Event** preview match count is a browser-side `matchesRule` simulation, not a backend dry-run (`CreateRuleFromEventModal.tsx:117`, labeled "client-side simulation"). No rule-test endpoint exists.
- **Rule Analytics → Top Blocked URIs** groups only the latest 100 `action=block` events client-side (no backend URI-aggregation endpoint) → under-counts.
- **Risk Scoring** distribution chart bins only the current page (limit 50) of actors, not a global histogram.
- **Bot Management / Sensitive Patterns / Custom Rules** "test pattern" boxes run JS regex in-browser (no backend matcher endpoint) → can differ from the Rust engine.

---

## ✅ Fully working screens (verified wired to existing endpoints)

Hosts · Security Events (list + detail) · Rule Analytics · Tier Policies · Access Lists · IP Rules · URL Rules · Rule Manager (`rules-management`) · Custom Rules (full CRUD + toggle) · Rule Sources · Bot Management · Device Fingerprinting · Relay Intel · Risk Scoring · Geo Restriction (CRUD) · Sensitive Patterns · CrowdSec Settings · CrowdSec Decisions · CrowdSec Stats · Cache · Cluster (Overview / Tokens / Sync / Node Detail) · Plugins · Tunnels · Certificates · Notifications · Enforcement (Default Mode / Runtime Ops / Capability Catalog) · Settings (config read/write/reload).

**Caveats resolved during live verification** (previously suspected, now confirmed OK):
- `security-events` filters `rule_id`, `rule_id_prefix`, `rule_name`, `country`, `path` are **all supported** (`SecurityEventQuery`, `waf-storage/src/models.rs:323`). This validates tx-velocity, bot-management, and the honeypot tab (`rule_id=HONEY`).
- `custom-rules` supports `PATCH /{id}` — the in-code `BACKEND-GAP` comment (`custom-rules/index.tsx:67`) is **stale**; PATCH works.

---

## Backend endpoints with NO frontend surface (unused capability)

These routes exist and respond but no screen calls them — either a missing UI or dead backend code:

| Endpoint | Live | Note |
| --- | --- | --- |
| `GET /api/audit-log` | `200` (empty) | The intended Logs replacement — **no page uses it** (see #1). |
| `GET /api/device-fp/conflicts` | `200` | Device-FP page never renders a conflicts table. |
| `DELETE /api/cache/host/{host}`, `DELETE /api/cache/key`, `GET /api/cache/tags` | exist | Cache page doesn't use these three. |
| `GET /api/hotlink-config` | `200` | CC-Protection only POSTs (see #5). |
| `POST /api/sqli-scan/reload`, `GET /api/test` | exist | No UI control. |

---

## Minor / dead-code notes (low priority)

- **Tunnels:** empty low-port guard block — dead code, no warning ever shown (`tunnels/index.tsx:111-113`).
- **Plugins:** empty-state link to `/docs/plugins-getting-started` — not served, likely 404 (`plugins/index.tsx:225`).
- **Rule Sources:** create payload sends **both** `type` and `source_type` because the FE doesn't know which the handler accepts (`index.tsx:128-136`) — the create contract for the source-type field is unverified; worth confirming the handler's expected key.
- **Access Lists:** backend can return `verdict:"pass"` but `verdictColor` only maps allow/bypass/block → renders gray (cosmetic, `index.tsx:71`).
- **Enforcement Capability Catalog:** static `KNOWN_GAP = "ddos_protection.per_tier"` marker and plane badges are literal metadata, not backend-driven (`capability-catalog.tsx:34`).

---

## Recommended priority order

1. **Logs page** (🔴) — biggest gap: a whole nav item is dead. Rebuild on `/api/audit-log` or remove.
2. **Response Filtering** (🔴) — implement `/api/response-filtering/preview` and `/api/hosts/{id}/response-filter`, or hide the Preview widget + Per-Host tab.
3. **DDoS Protection** (🟠) — wire `get_ddos_metrics` / `list_ban_table` / `delete_ban_entry` to the live ban store (currently explicit v1 stubs).
4. **Challenge Engine** (🟠) — back `get_challenge_stats` with real counters; either enable or hide the `pow`/`captcha` "coming soon" options; route preview through `httpClient` for auth.
5. **CC Protection** (🟡) — rename to reflect what it does, and make the hotlink form read existing config.
6. **Cosmetic panels** (🔵) — either feed Dashboard "Detection Engines", Enforcement "Plane Map", Settings "Threat-Intel feeds" from real config, or label them as static/reference. Fix the misleading "(24h)" / "blocked" labels on Geo.

---

*Generated from a static FE↔BE cross-reference plus live verification against the running container. Endpoint inventory: `crates/waf-api/src/server.rs` (+ `security.rs`, `interop_control.rs`, `tls.rs`). FE entry points: `web/admin-panel/src/providers/data-provider.ts` and the per-page sources cited above.*
