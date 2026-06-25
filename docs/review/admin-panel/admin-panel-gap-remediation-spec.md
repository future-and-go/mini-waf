# Admin Panel — Gap Remediation Spec (per-GUI-feature, AI-ready)

**Date:** 2026-06-25
**Companion to:** [`admin-panel-fe-be-gap-review.md`](admin-panel-fe-be-gap-review.md) (the findings report).
**Purpose:** one self-contained work item per broken/incomplete GUI feature, with the **exact API contract the frontend already expects**, **where to implement it in the backend**, and the **requirement ID(s)** to cite — so each item can be handed to an AI/dev to implement without re-discovery.

## Requirement ID systems used here

- **FR-NNN** — functional requirements catalog: [`analysis/requirements.md`](../analysis/requirements.md) §3 (each row is `| FR-NNN | category | title | detail |`).
- **E-NN / US-NNNN** — interop-contract epics & stories under [`docs/stories/epics/`](stories/epics/) (map: [`docs/product/README.md`](product/README.md)).
- **NNNN-decision** — durable decisions under [`docs/decisions/`](decisions/).

> Per [`docs/FEATURE_INTAKE.md`](FEATURE_INTAKE.md), each item lists a suggested **lane** (tiny / normal / high-risk). Items touching the request/response hot path or config persistence are **normal**; none here are auth/data-loss hard-gates except where noted.

Backend route registration for every new endpoint goes in [`crates/waf-api/src/server.rs`](../crates/waf-api/src/server.rs) in the `protected_routes` builder (the `.route(...)` chain starting at line 124). Handlers live in the per-domain `crates/waf-api/src/*.rs` modules.

---

## Legend

| Field | Meaning |
| --- | --- |
| **Req IDs** | FR / Epic / US / decision to reference in the story packet & commit. |
| **FE contract** | Request/response shape the existing frontend code already sends/expects (so the backend must match these field names exactly). |
| **Backend target** | File to add/modify + the `server.rs` route line. |
| **Acceptance** | Verifiable done-criteria. |

---

# A. 🔴 BROKEN — feature calls an endpoint that 404s

## A1. Logs page — rebuild on the audit-log sink (or remove)

| | |
| --- | --- |
| **GUI feature** | Left-nav **Logs** (`/ui/#/logs`) — log table, "Entries (24h)" stat, Event Type / Tier / Rule filters, LogsQL query bar, column picker. |
| **Req IDs** | **FR-029** (Live request feed: request id, ts_ms, risk_score, action, rule), **FR-032** (Structured audit log, SIEM-ingestible). Epic **E12-audit-log** → **US-1201** (jsonl append-only), **US-1202** (required audit fields), **US-1205** (decommission VictoriaLogs). Decisions **0009** (jsonl file sink), **0010** (decommission VictoriaLogs). |
| **Current state** | All three calls 404 (verified): `GET /api/v1/logs/query`, `/api/v1/logs/stats`, `/api/v1/logs/streams`. The VictoriaLogs backend was removed; `victoria-logs-data-provider.ts` still points at it. |
| **What already exists** | `GET /api/audit-log` is implemented — `list_audit_log` at [`crates/waf-api/src/security.rs:267`](../crates/waf-api/src/security.rs#L267), registered at [`server.rs:237`](../crates/waf-api/src/server.rs#L237). It returns `{ entries: [...], total: N }` (live-verified `200 {"entries":[],"total":0}`). The query struct it accepts is `AuditLogQuery` (find in `crates/waf-storage`). |

**Recommended path — FE-only rewire (no new backend):** point the Logs page at `/api/audit-log`.
- **Frontend changes:**
  - Replace the `vlogs` data-provider usage in [`web/admin-panel/src/pages/logs/index.tsx`](../web/admin-panel/src/pages/logs/index.tsx) with a `useCustom`/`useList` against `/api/audit-log` (paginated `page`/`page_size` like other lists).
  - Map columns to the audit-log JSONL fields (per FR-032 / US-1202): `request_id, ts_ms, ip, device_fp, risk_score, rule_id, action` (+ host_code, path, method as available). Confirm the exact field set against `crates/waf-storage` audit model and `docs/product/audit-log.md`.
  - Drop the "Entries (24h)" stat and the dynamic filter-value dropdowns **unless** you add the two small endpoints below; otherwise keep client-side filtering over the fetched page.
  - Delete `victoria-logs-data-provider.ts` and its registration once nothing references it.
- **Optional backend additions (only if the 24h stat + dynamic filter dropdowns are wanted):**
  - `GET /api/audit-log/stats` → `{ count_24h: number }` — handler in `security.rs`, route after line 237.
  - `GET /api/audit-log/streams` → distinct values for `event_type|rule_name|tier` for filter dropdowns.

**Acceptance:** Logs page loads rows from `/api/audit-log`; no request to any `/api/v1/logs/*` path remains (grep the FE bundle); filters operate; no console 404s. **Lane:** normal (FR-032 is an existing contract; touches no auth/data-loss).

---

## A2. Response Filtering — Preview widget + entire Per-Host tab 404

| | |
| --- | --- |
| **GUI feature** | **Response Filtering** (`/ui/#/response-filtering`). Two broken parts: (1) the **Preview** widget on the Global tab; (2) the **whole Per-Host tab**. |
| **Req IDs** | **FR-033** (Response filtering — block stack traces / internal IPs / API keys / verbose errors), **FR-034** (Sensitive field redaction in JSON), **FR-035** (Header leak prevention). |
| **Current state** | `POST /api/response-filtering/preview` → **404**; `GET`/`PUT /api/hosts/{id}/response-filter` → **404** (only `/api/hosts/{id}` exists). The Global config save/load via `/api/panel-config` works. |
| **What already exists** | The actual response-filtering engine is implemented in [`crates/gateway/src/filters/`](../crates/gateway/src/filters/) — `response_json_field_redactor.rs`, `response_header_blocklist_filter.rs`, `response_server_policy_filter.rs`, `response_via_strip_filter.rs`, `response_location_rewriter.rs`. So the runtime behavior exists; only the **admin API surface** is missing. |

### A2a. `POST /api/response-filtering/preview`
- **FE contract** (from [`response-filtering/index.tsx:168`](../web/admin-panel/src/pages/response-filtering/index.tsx#L168)):
  - Request: `{ "body": string, "content_type": string }`
  - Response: `{ "data": { "result": string } }` (FE reads `data.data.result`).
  - Semantics: run the current/global response-filter rules over `body` and return the filtered/redacted text so the admin can preview redaction.
- **Backend target:** new handler in `crates/waf-api/src/security.rs` (co-located with sensitive-patterns/hotlink); reuse the redaction logic from `crates/gateway/src/filters/response_json_field_redactor.rs`. Route: add `.route("/api/response-filtering/preview", post(preview_response_filter))` near the other `security` routes in `server.rs`.

### A2b. `GET`/`PUT /api/hosts/{id}/response-filter`
- **FE contract** (`HostResponseFilter`, [`response-filtering/index.tsx:35`](../web/admin-panel/src/pages/response-filtering/index.tsx#L35)):
  ```jsonc
  {
    "body_scan_enabled": boolean,
    "body_scan_max_body_bytes": number,
    "internal_patterns": string[],     // regex strings, FR-033
    "header_blocklist": string[],      // FR-035
    "strip_server_header": boolean      // FR-035
  }
  ```
  - `GET` returns this object (the per-host filter, defaulting if unset); `PUT` accepts it and persists.
- **Backend target:** extend the host model / `defense_json` in `crates/waf-storage` (hosts table) with a `response_filter` blob, or add a dedicated column. Handlers go in [`crates/waf-api/src/handlers.rs`](../crates/waf-api/src/handlers.rs) next to `update_host`. Routes: `.route("/api/hosts/{id}/response-filter", get(get_host_response_filter).put(put_host_response_filter))` after line 127 in `server.rs`. The gateway filters must then read per-host overrides (wire through the host config the proxy already loads).

**Acceptance:** Preview returns redacted text for a sample body with secrets/stack-trace; selecting a host loads its filter (no 404), editing + Save persists and survives reload; the proxy applies the per-host overrides (integration test in `crates/gateway`). **Lane:** normal→high-risk (FR-033/034/035 touch the response hot path + a data-model change for per-host storage → see FEATURE_INTAKE "Data model" + "Existing behavior" flags; create a story packet, add validation).

---

# B. 🟠 STUB — endpoint returns hardcoded data; UI shows fake numbers

## B1. DDoS Protection — metrics + ban table + unban are placeholders

| | |
| --- | --- |
| **GUI feature** | **DDoS Protection** (`/ui/#/ddos-protection`): 4 KPI cards, live ban table with IP/level filters, per-row **Unban** button. |
| **Req IDs** | **FR-005** (DDoS Protection: burst detection + auto block, per-tier threshold, fail-close/open), supporting **FR-004** (Rate limiting). |
| **Current state** | Config (`GET/PUT /api/ddos/config`) is real. The rest are stubs (verified live + source):<br>• `GET /api/ddos/metrics` → hardcoded zeros, [`ddos_api.rs:75`](../crates/waf-api/src/ddos_api.rs#L75)<br>• `GET /api/ddos/ban-table` → `"STUB — v1 placeholder"`, always `[]`, [`ddos_api.rs:82`](../crates/waf-api/src/ddos_api.rs#L82)<br>• `DELETE /api/ddos/ban-table/{ip}` → only `tracing::info!`, no state change, [`ddos_api.rs:92`](../crates/waf-api/src/ddos_api.rs#L92) |
| **What already exists** | The **live ban store is real**: `DynamicBanTable`, exposed via `engine.ddos_ban_table()` at [`crates/waf-engine/src/engine.rs:391`](../crates/waf-engine/src/engine.rs#L391); per-tier counters in [`crates/waf-engine/src/checks/ddos/metrics.rs`](../crates/waf-engine/src/checks/ddos/metrics.rs). The API just needs to read from `state.engine`. |

- **B1a `GET /api/ddos/metrics`** — return real counters from `crates/waf-engine/src/checks/ddos/metrics.rs`. FE shape (`DdosMetrics`, ddos-protection/index.tsx:52): `{ active_bans, bursts_1h, bans_issued_1h, store_errors }` (all numbers). `active_bans` = `engine.ddos_ban_table()` live count.
- **B1b `GET /api/ddos/ban-table`** — enumerate the live ban table. FE row shape (`BanEntry`, line 44):
  ```jsonc
  { "ip": string, "banned_until_ms": number, "ban_level": number, "last_rps": number, "reason": string }
  ```
  Envelope: `{ "data": BanEntry[], "total": number }`.
- **B1c `DELETE /api/ddos/ban-table/{ip}`** — actually remove the IP from `DynamicBanTable` (it already has a `clear()`/remove path used by reset-state at engine.rs:541). Return `{ success, data: { ip } }`.
- **Backend target:** rewrite the three handlers in [`crates/waf-api/src/ddos_api.rs`](../crates/waf-api/src/ddos_api.rs) to take `State<Arc<AppState>>` (they currently ignore state via `_:`) and read/mutate `state.engine.ddos_ban_table()` + the metrics struct. Routes already registered (`server.rs:281-283`) — no route change.

**Acceptance:** trigger a burst in a test → IP appears in `/api/ddos/ban-table` with correct `banned_until_ms`; `active_bans` KPI matches table length; `DELETE` removes the entry and the next poll shows it gone. **Lane:** normal (existing behavior + observability; no schema change).

## B2. Challenge Engine — stats KPIs are hardcoded; PoW/CAPTCHA disabled

| | |
| --- | --- |
| **GUI feature** | **Challenge Engine** (`/ui/#/challenge-engine`): 4 KPI cards (Issued/Passed/Failed/Replays), challenge-type selector, HTML preview. |
| **Req IDs** | **FR-006** (Challenge Engine: JS Challenge + Proof-of-Work, adaptive Allow/Challenge/Block by cumulative risk). Epic **E17-challenge-lifecycle** → **US-1701** (challenge response format), **US-1702** (challenge solve flow). |
| **Current state** | `GET/PUT /api/challenge/config` and `POST /api/challenge/preview` (HTML) are real. `GET /api/challenge/stats` → hardcoded zeros, [`challenge_api.rs:133`](../crates/waf-api/src/challenge_api.rs#L133). `pow` + `captcha` types are `disabled:true` "Coming soon" ([challenge-engine/index.tsx:243](../web/admin-panel/src/pages/challenge-engine/index.tsx#L243)). Preview uses bare `fetch()` (no bearer token) at index.tsx:110. |

- **B2a `GET /api/challenge/stats`** — back with real counters. FE shape (`ChallengeStats`, line 43): `{ issued, passed, failed, replays }` (numbers). Add counters at the point challenges are issued/solved — see [`crates/gateway/src/proxy_waf_response.rs:321`](../crates/gateway/src/proxy_waf_response.rs#L321) ("Challenge issued") and the solve-flow handler (US-1702). Expose via `AppState`, read in `challenge_api.rs`.
- **B2b PoW / CAPTCHA** — FR-006 explicitly requires **Proof-of-Work**. Either implement the `pow` challenge type (then remove `disabled:true`) or, if out of scope now, leave disabled but track under US-17xx. CAPTCHA is not in FR-006 (FR-006 lists JS + PoW only) — consider removing the CAPTCHA option or marking it clearly non-roadmap.
- **B2c Preview auth** — change `fetch()` at [challenge-engine/index.tsx:110](../web/admin-panel/src/pages/challenge-engine/index.tsx#L110) to the shared `httpClient` so it carries the bearer token (FE-only, tiny).

**Acceptance:** issue a JS challenge in a test → `issued` increments, solving → `passed` increments; preview loads while authenticated. PoW either works or is tracked as a story. **Lane:** normal (B2a/B2c); high-risk if implementing PoW (new enforcement behavior → story packet under E17).

---

# C. 🟡 PARTIAL / MISLABELED

## C1. CC Protection — mislabeled, and hotlink form is write-only

| | |
| --- | --- |
| **GUI feature** | **CC Protection** (`/ui/#/cc-protection`): LB-backends CRUD + anti-hotlink form. |
| **Req IDs** | **FR-004** (Rate limiting — sliding window per IP + per session, token bucket), **FR-005** (DDoS). Anti-hotlink is referer validation (relates to FR-007 / FR-035). |
| **Issue 1 — misnomer** | The page makes **zero** rate-limit/CC/DDoS/challenge calls. Real "CC" (HTTP-flood) controls live in **Hosts** `defense_json` (`cc, cc_rps, cc_burst, cc_ban_threshold`) and in `/api/ddos/*` + `/api/challenge/*`. **Action:** either (a) rename the page (e.g. "Load Balancer & Anti-Hotlink") in the i18n + route label, or (b) add real CC controls (per-host rate-limit editor bound to the existing `defense_json` fields and `/api/ddos/config`). Decision-worthy (scope) → record under FEATURE_INTAKE if you change scope. |
| **Issue 2 — write-only hotlink** | Form `POST`s to `/api/hotlink-config` but never `GET`s it; `GET /api/hotlink-config?host_code=<code>` **exists** (live `200 {"data":null}`). **Action (FE-only, tiny):** add a `useCustom` GET on host-select to load existing config into the form (`HotlinkForm` = `{ host_code, enabled, allow_empty_referer, redirect_url? }`, cc-protection/index.tsx:29). Note the GET requires a `host_code` query param (returns `400 "host_code required"` without it). |

**Acceptance:** opening the hotlink form for a saved host shows its stored values; page title matches its actual function. **Lane:** tiny (hotlink GET wire-up); normal + decision if adding real CC controls.

## C2. TX Velocity — config thresholds have no API

| | |
| --- | --- |
| **GUI feature** | **TX Velocity** (`/ui/#/tx-velocity`): KPIs + events table (these work via `security-events?rule_id_prefix=TX-…`), and a **read-only "Config thresholds" card**. |
| **Req IDs** | **FR-012** (Transaction Velocity & Sequence: Login→OTP→Deposit timing, withdrawal velocity, rapid limit-change). |
| **Current state** | KPIs/table are genuinely wired (`rule_id_prefix` is a supported `SecurityEventQuery` filter — [`crates/waf-storage/src/models.rs:323`](../crates/waf-storage/src/models.rs#L323)). The thresholds card is a hardcoded placeholder; comment says "no REST API for FR-012 config" ([tx-velocity/index.tsx:268](../web/admin-panel/src/pages/tx-velocity/index.tsx#L268)); thresholds live in `configs/tx-velocity.yaml`, edited by hand. |
| **Missing API** | `GET /api/tx-velocity/config` + `PUT /api/tx-velocity/config` (mirror the existing pattern of `/api/ddos/config`, `/api/challenge/config` which read/write a YAML via `resolve_path`). |
| **FE contract** | Define from `configs/tx-velocity.yaml` fields (seq window, withdraw velocity, limit-change thresholds). Return the parsed YAML as JSON; `PUT` validates + writes it back and hot-reloads (the engine already hot-reloads — tx_velocity engine tests exist in `crates/waf-engine/tests/`). |
| **Backend target** | New handler module `crates/waf-api/src/tx_velocity_api.rs` (copy `challenge_api.rs` shape: `resolve_path("configs/tx-velocity.yaml")`, `read_yaml`/`write_yaml`). Routes: `.route("/api/tx-velocity/config", get(...).put(...))` in `server.rs`. Then make the FE card an editable form. |

**Acceptance:** thresholds load from + save to `configs/tx-velocity.yaml` via the API; hot-reload picks them up without restart (FR-031). **Lane:** normal.

---

# D. 🔵 COSMETIC — static/hardcoded data presented as live

These render fine but aren't backed by live data. Fix = either feed from a real endpoint or relabel as "reference/static". Lower priority.

| # | GUI feature | Req ID | What to do | Location |
| --- | --- | --- | --- | --- |
| D1 | **Dashboard → Detection Engines** panel | FR-030 (attack visualization), FR-031 (hot config) | Feed `enabled` state from real config (e.g. derive from `/api/panel-config` + `/api/rules/registry` per engine) instead of the hardcoded `ENGINES` array, or label as "capabilities (static)". | [`dashboard/index.tsx:49-64`](../web/admin-panel/src/pages/dashboard/index.tsx#L49) |
| D2 | **Enforcement → Plane Map** | E14-enforcement-modes, E10 (US-1003 capabilities) | Drive the table (esp. the unconditional green "Control Plane" check) from `/api/enforcement/capabilities` rather than the static `GOVERNANCE_MAP`, or mark the table "reference". | [`enforcement/plane-map.tsx:7,55`](../web/admin-panel/src/pages/enforcement/plane-map.tsx#L55) |
| D3 | **Settings → Threat Intel feeds** | FR-042 (IP Reputation Feed: Tor + bad ASN, periodic refresh), FR-008 (threat intel blacklist) | The table is synthesized from `/api/rules/registry`. Add a real `GET /api/threat-intel/feeds` (or extend `/api/threat-intel/status`) returning feed name/source/last-refresh/count, and remove the "No live API available" fallback. | [`settings/index.tsx:203-219,864-892`](../web/admin-panel/src/pages/settings/index.tsx#L203) |
| D4 | **Geo Restriction** country picker + "(24h) Top Blocked" label | FR-041 (Geographic Restriction) | Replace the hardcoded 31-entry `COUNTRY_MAP` with a full ISO list (or a backend `GET /api/geoip/countries`); fix the "Top Blocked (24h)" label — `/api/stats/geo` sends no 24h/blocked filter, so either add those filters server-side or correct the label. | [`geo-restriction/index.tsx:54-85,386-410`](../web/admin-panel/src/pages/geo-restriction/index.tsx#L54) |

### Client-side approximations (optional backend endpoints to make them accurate)
| Feature | Req ID | Optional new endpoint |
| --- | --- | --- |
| Create-Rule-from-Event **preview match count** (browser sim) | FR-003 (Rule Engine), FR-021/022 | `POST /api/custom-rules/test` (dry-run a rule against recent events) — would replace the client-side `matchesRule`. |
| Rule Analytics **Top Blocked URIs** (100-event client grouping) | FR-030 | `GET /api/stats/endpoints?action=block` server-side aggregation (the `/api/stats/endpoints` route exists — extend it to group by URI). |
| Risk Scoring **distribution chart** (current-page bins) | FR-025, FR-027 | Add a `distribution` field to `GET /api/risk/metrics` (server-side histogram). |
| Bot/Sensitive/Custom-rule **regex test boxes** (JS regex) | FR-003, FR-034 | Optional `POST /api/.../test` for engine-accurate matching. |

---

# E. Backend endpoints that exist but have NO GUI (wire-up opportunities)

| Endpoint (exists, verified) | Req ID | Suggested GUI |
| --- | --- | --- |
| `GET /api/audit-log` | FR-032 | The Logs page (see A1) — primary consumer. |
| `GET /api/device-fp/conflicts` | FR-010 (detect same device switching IPs) | Add a "Conflicts" tab to Device Fingerprinting showing fingerprint↔IP conflicts. |
| `DELETE /api/cache/host/{host}`, `DELETE /api/cache/key`, `GET /api/cache/tags` | FR-009 (Smart Caching) | Add per-host / per-key purge + tag browser to the Cache page. |
| `GET /api/hotlink-config` | FR-007/FR-035 | Load into CC-Protection hotlink form (see C1). |

---

# F. Suggested build order (by requirement weight × user impact)

1. **A1 Logs → `/api/audit-log`** — FR-029/FR-032, mostly FE; removes a fully-dead nav item. *(normal)*
2. **B1 DDoS metrics/ban-table/unban** — FR-005; live store already exists, pure API wiring. *(normal)*
3. **B2a Challenge stats** + **B2c preview auth** — FR-006/E17; small. *(normal)*
4. **A2 Response Filtering preview + per-host** — FR-033/034/035; needs a data-model change → story packet. *(high-risk)*
5. **C2 TX Velocity config API** — FR-012; mirrors existing config endpoints. *(normal)*
6. **C1 CC-Protection** rename + hotlink GET. *(tiny + decision)*
7. **D1–D4 cosmetic** relabel/feed-from-real-data. *(tiny/normal)*

---

*All FE contracts above are transcribed from the current `web/admin-panel/src` sources; all backend pointers verified against `crates/` on 2026-06-25. Before implementing, run the intake step in `docs/FEATURE_INTAKE.md` and create the story packet under the cited epic (or a new `E18-admin-api-completeness` epic if you prefer to group these).*

---

# G. 📋 Summary Overview (to complete the admin-panel)

Quick-reference tables aggregating everything above. Use the **Fix** column to jump to the detailed work item (A1, B1a, …) and the **Req IDs** column for the story packet.

## G.1 API mismatch master table — every broken / stub / missing endpoint

| # | GUI feature (page) | Endpoint | HTTP verb | Status | Symptom in UI | Fix | Req IDs |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Logs | `/api/v1/logs/query` | GET | 🔴 404 (removed) | Log table never loads | A1 | FR-029, FR-032, US-1205, dec-0010 |
| 2 | Logs | `/api/v1/logs/stats` | GET | 🔴 404 (removed) | "Entries (24h)" always "—" | A1 | FR-032 |
| 3 | Logs | `/api/v1/logs/streams` | GET | 🔴 404 (removed) | Filter dropdowns empty | A1 | FR-032 |
| 4 | Response Filtering | `/api/response-filtering/preview` | POST | 🔴 404 (never built) | Preview always errors | A2a | FR-033, FR-034, FR-035 |
| 5 | Response Filtering | `/api/hosts/{id}/response-filter` | GET | 🔴 404 (never built) | Per-Host tab load fails | A2b | FR-033, FR-034, FR-035 |
| 6 | Response Filtering | `/api/hosts/{id}/response-filter` | PUT | 🔴 404 (never built) | Per-Host Save fails | A2b | FR-033, FR-034, FR-035 |
| 7 | DDoS Protection | `/api/ddos/metrics` | GET | 🟠 stub zeros | 4 KPI cards always 0 | B1a | FR-005, FR-004 |
| 8 | DDoS Protection | `/api/ddos/ban-table` | GET | 🟠 stub `[]` | Ban table always empty | B1b | FR-005 |
| 9 | DDoS Protection | `/api/ddos/ban-table/{ip}` | DELETE | 🟠 no-op | Unban button does nothing | B1c | FR-005 |
| 10 | Challenge Engine | `/api/challenge/stats` | GET | 🟠 stub zeros | KPI cards always 0 | B2a | FR-006, US-1701/1702 |
| 11 | Challenge Engine | `/api/challenge/preview` | POST | ⚠️ unauth `fetch()` | 401 if route gated | B2c | FR-006 |
| 12 | CC Protection | `/api/hotlink-config` | GET | ⚠️ exists, unused | Form never shows saved state | C1 | FR-007, FR-035 |
| 13 | CC Protection | *(no CC/rate-limit endpoint called)* | — | ⚠️ mislabeled | Page name ≠ function | C1 | FR-004, FR-005 |
| 14 | TX Velocity | `/api/tx-velocity/config` | GET+PUT | ❌ missing | Threshold card read-only/static | C2 | FR-012 |
| 15 | Dashboard | *(none — hardcoded `ENGINES`)* | — | 🔵 static | Engines always all-green | D1 | FR-030, FR-031 |
| 16 | Enforcement → Plane Map | *(none — static `GOVERNANCE_MAP`)* | — | 🔵 static | Control-plane always ✓ | D2 | E14, E10/US-1003 |
| 17 | Settings → Threat Intel | `/api/threat-intel/feeds` | GET | ❌ missing (synthesized) | Feed table is faked from rules | D3 | FR-042, FR-008 |
| 18 | Geo Restriction | `/api/geoip/countries` | GET | ❌ missing (31 hardcoded) | Country picker incomplete | D4 | FR-041 |
| 19 | Geo Restriction | `/api/stats/geo` (no 24h/blocked filter) | GET | ⚠️ label overstates | "(24h) Top Blocked" misleading | D4 | FR-041 |
| 20 | Create-Rule-from-Event | `/api/custom-rules/test` | POST | ❌ missing (browser sim) | Preview count approximate | D (client-side) | FR-003, FR-021/022 |
| 21 | Rule Analytics | `/api/stats/endpoints` (group-by-URI) | GET | ⚠️ partial (client group) | Top URIs under-counts | D (client-side) | FR-030 |
| 22 | Risk Scoring | `/api/risk/metrics` (no `distribution`) | GET | ⚠️ partial (client bins) | Histogram = current page only | D (client-side) | FR-025, FR-027 |

**Counts:** 🔴 6 broken · 🟠 4 stub · ❌ 4 missing-new · ⚠️ 8 partial/mislabeled/unauth.

## G.2 Backend exists but NO GUI surface (wire-up to complete coverage)

| Endpoint (verified live) | Status | Suggested GUI surface | Req IDs |
| --- | --- | --- | --- |
| `GET /api/audit-log` | ✅ works, unused | Re-point the Logs page here (item A1) | FR-032, FR-029 |
| `GET /api/device-fp/conflicts` | ✅ works, unused | New "Conflicts" tab on Device Fingerprinting | FR-010, FR-011 |
| `DELETE /api/cache/host/{host}` | ✅ works, unused | Per-host purge button on Cache page | FR-009 |
| `DELETE /api/cache/key` | ✅ works, unused | Per-key purge input on Cache page | FR-009 |
| `GET /api/cache/tags` | ✅ works, unused | Tag browser on Cache page | FR-009 |
| `GET /api/hotlink-config` | ✅ works, unused | Load into CC-Protection hotlink form (item C1) | FR-007, FR-035 |

## G.3 Requirement coverage matrix (FR → admin-panel)

Status of each functional requirement **as surfaced in the admin-panel** (engine-level implementation not separately audited; ✅ = GUI fully wired to a working endpoint).

| Req ID | Requirement | Admin-panel page | GUI status |
| --- | --- | --- | --- |
| FR-001 | Full reverse proxy | *(infra — no admin page)* | n/a |
| FR-002 | Tiered protection | Tier Policies | ✅ wired |
| FR-003 | Rule engine | Custom Rules / Rule Manager | ✅ wired |
| FR-004 | Rate limiting | Hosts `defense_json` / CC Protection | ⚠️ partial (CC page mislabeled — C1) |
| FR-005 | DDoS protection | DDoS Protection | 🟠 stub metrics/ban-table (B1) |
| FR-006 | Challenge engine | Challenge Engine | 🟠 stub stats; PoW disabled (B2) |
| FR-007 | Relay & proxy detection | Relay Intel | ✅ wired |
| FR-008 | Whitelist + blacklist | Access Lists / IP Rules / URL Rules | ✅ wired |
| FR-009 | Smart caching | Cache | ✅ wired (3 purge endpoints unused — G.2) |
| FR-010/011 | Device fingerprint / anomaly | Device Fingerprinting | ✅ wired (conflicts tab missing — G.2) |
| FR-012 | Transaction velocity | TX Velocity | ⚠️ config has no API (C2) |
| FR-013…020 | Detection (SQLi/XSS/LFI/SSRF/…) | Rule Manager / Custom Rules | ✅ wired (rule CRUD) |
| FR-021…024 | Rule hot-reload / format / scope / priority | Rule Manager / Rule Sources / Custom Rules | ✅ wired |
| FR-025 | Cumulative risk scoring | Risk Scoring | ✅ wired (distribution approx — G.1#22) |
| FR-026 | Risk dynamics | Risk Scoring (config) | ✅ wired |
| FR-027 | Decision thresholds | Risk Scoring / Tier Policies | ✅ wired |
| FR-028 | Canary / honeypot | Security Events (honeypot tab, `rule_id=HONEY`) | ✅ wired |
| FR-029 | Live request feed | Dashboard (live events) / Logs | ⚠️ Dashboard ✅, **Logs 🔴 broken** (A1) |
| FR-030 | Attack visualization | Dashboard / Rule Analytics | ✅ wired (some client-side approx) |
| FR-031 | Hot config | Settings (reload) | ✅ wired |
| FR-032 | Structured audit log | Logs | 🔴 broken — `/api/audit-log` unused (A1) |
| FR-033/034/035 | Response filtering / redaction / header leak | Response Filtering / Sensitive Patterns | 🔴 preview + per-host broken (A2); Sensitive Patterns ✅ |
| FR-036…039 | Resilience (fail-open/close, circuit breaker) | *(config in DDoS/Tier — no dedicated page)* | n/a (config-file) |
| FR-040 | HTTPS / TLS termination | SSL Certificates | ✅ wired |
| FR-041 | Geographic restriction | Geo Restriction | ✅ wired (country list hardcoded — D4) |
| FR-042 | IP reputation feed | Settings → Threat Intel | 🔵 synthesized, no feeds API (D3) |
| FR-043 | Multi-region deployment | *(none)* | ❌ no GUI |
| FR-044 | Zero-downtime config sync | Cluster → Sync | ✅ wired |
| FR-045 | Auto scaling | *(none)* | ❌ no GUI |
| FR-046 | Behavioral ML scoring | *(none)* | ❌ no GUI |

**Admin-panel completion gaps at a glance:**
- **Must-fix (P0 features degraded):** FR-032 (Logs 🔴), FR-033/034/035 (Response Filtering 🔴), FR-005 (DDoS 🟠), FR-006 (Challenge 🟠), FR-012 (TX config ❌).
- **Polish:** FR-004 (CC label), FR-041 (country list), FR-042 (feeds API), FR-009/FR-010 (unused endpoints → new GUI).
- **Not surfaced at all (P1 bonus):** FR-043, FR-045, FR-046 — no admin-panel page exists.

> **Note on doc paths:** this file now lives at `docs/review/admin-panel/`. The inline `../analysis/…`, `../crates/…`, `../web/…` links in sections A–F were written for the original `docs/` location and now resolve one level too high — adjust to `../../../…` if you rely on click-through. Want me to fix them?
