# PRX-WAF — FR-to-Admin-Panel Gap Analysis & Cursor Prompts

> **Mục đích**: Đối chiếu toàn bộ Backend API (waf-api) với Admin Panel (Vue/React + Refine + AntD) hiện tại, xác định các FR yêu cầu bởi WAF Hackathon 2026 nhưng **chưa có UI tương ứng**, và cung cấp prompt sẵn dùng cho Cursor để generate code thiếu.
>
> **Phạm vi BE**: 70+ endpoint Axum dưới `/api/*` (xem `crates/waf-api/src/server.rs`)
> **Phạm vi FE**: 28 page resource đăng ký ở `web/admin-panel/src/App.tsx`

---

## 1. Tổng quan ánh xạ FR → BE API → Admin Panel

Ký hiệu: ✅ đã có UI đầy đủ · 🟡 có UI một phần / chỉ read-only · ❌ thiếu hoàn toàn

| FR | Nội dung | BE API có sẵn | Admin Panel hiện tại | Trạng thái |
|---|---|---|---|---|
| FR-001 | Full reverse proxy | `/api/hosts` CRUD | `pages/hosts` | ✅ |
| **FR-002** | **Tiered protection (4 tier policy)** | `[tiered_protection]` trong `default.toml` + hot-reload | Không có editor — chỉ chỉnh file TOML | ❌ |
| FR-003 | Rule engine (custom rules) | `/api/custom-rules` CRUD + tree editor | `pages/custom-rules` | ✅ |
| FR-004 | Rate limiting (per-IP + per-session) | `/api/panel-config` `rate_limits.*` | `pages/settings` (giới hạn ở `default_rps`, `burst`, `session_expiry_secs`) | 🟡 thiếu per-tier override |
| **FR-005** | **DDoS protection (per-tier threshold + ban table)** | `[ddos]` TOML + tier policies, ban table inferred trong RiskAggregator | Không có UI; số liệu ẩn trong rule-analytics | ❌ |
| **FR-006** | **Challenge engine (JS / PoW / CAPTCHA, difficulty tier)** | `configs/challenge.yaml` (challenge type, difficulty, token, branding) | `pages/settings` chỉ chọn `challenge_type`; không có difficulty / TTL / branding editor | 🟡 |
| **FR-007** | **Relay & proxy detection (ASN, Tor, XFF validation)** | `configs/relay.yaml` (ASN feed, datacenter set, Tor feed, providers) | Không có UI; chỉ có `threat-intel/status` widget ở settings | ❌ |
| **FR-008** | **Access lists (IP/Host whitelist + blacklist, per-tier)** | `rules/access-lists.yaml` hot-reload | Một phần qua `/api/allow-ips`, `/api/block-ips` (host-scoped chứ không phải tier-scoped) | 🟡 thiếu tier-scoped UI + host-whitelist editor |
| FR-009 | Smart caching (per-tier bypass + TTL per route) | `/api/cache/*` + `rules/cache.yaml` | `pages/cache` (stats, purge tag/route) | ✅ stats; 🟡 thiếu YAML rules editor |
| **FR-010** | **Device fingerprinting (JA3/JA4, H2, UA entropy)** | `configs/device-fp.yaml` (capture, store, providers) | Không có UI | ❌ |
| **FR-011** | **Behavioral anomaly detection** | `device-fp.yaml::behavior` (burst, regularity, zero-depth, missing-referer) | Không có UI | ❌ |
| FR-012 | Transaction velocity & sequence | `configs/tx-velocity.yaml` (signal-only) + `/api/security-events?rule_id_prefix=TX-` | `pages/tx-velocity` (KPI + read-only thresholds) | 🟡 read-only |
| FR-013–020 | OWASP detection (SQLi/XSS/Path/SSRF/Header/BF/Scanner/Body) | `/api/rules/registry` (mỗi rule có toggle) | `pages/rules-management` toggle rules | ✅ |
| FR-021 | Hot-reload rules | `POST /api/reload`, `POST /api/rules/reload` | Button "Reload Rules" trong `pages/settings` | ✅ |
| FR-022 | Rule format YAML/TOML | `/api/rules/import` (POST) | Không có UI cho import | 🟡 |
| FR-023 | Rule scoping (global, tier, route, IP, session, device-fp) | `custom_rules.host_code` (scope = host) | `custom-rules` chỉ scope theo host | 🟡 thiếu tier/route/session/device-fp scope |
| FR-024 | Rule priority | `custom_rules.priority` | Trong form `custom-rules` | ✅ |
| **FR-025** | **Cumulative risk scoring (per IP+fp+session)** | `configs/risk.yaml` (ttl, decay, seed, store) + WS push score | `pages/settings` chỉ có ngưỡng allow/challenge/block (panel-config) | 🟡 thiếu decay/seed/store editor + risk explorer |
| FR-026 | Risk score dynamics | Bound trong risk.yaml | Không hiển thị live | ❌ |
| FR-027 | Decision thresholds | `panel_config.risk_*` | `pages/settings` riskBandPreview | ✅ |
| FR-028 | Canary / honeypot | `panel_config.honeypot_paths` + `risk.yaml::canary` | `pages/settings` honeypotPaths chips; KPI honeypot card ở dashboard | ✅ |
| FR-029 | Live request feed | `/ws/events`, `/ws/logs` + `/api/security-events` | `pages/dashboard` (live tail 50) + `pages/security-events` | ✅ |
| FR-030 | Attack visualization | `/api/stats/*` | `pages/rule-analytics` + dashboard | ✅ |
| FR-031 | Hot config no restart | `/api/panel-config` PUT + `/api/reload` | `pages/settings` | ✅ |
| FR-032 | Structured JSON audit log | `/api/v1/logs/query` (VictoriaLogs) + `/api/audit-log` | `pages/logs` (admin-only) | ✅ |
| **FR-033** | **Response filtering (stack trace, internal IP, API key)** | `panel_config.response_filtering.block_stack_traces` + scanner trong gateway | `pages/settings` chỉ có toggle `block_stack_traces` — không UI cho categories / per-host body_scan_* | 🟡 |
| **FR-034** | **Sensitive field redaction (JSON)** | `panel_config.response_filtering.json_redact_fields` + per-host `internal_patterns` | `pages/settings` chips danh sách field; nhưng per-host `internal_patterns`/mask editor không có | 🟡 |
| **FR-035** | **Header leak prevention (X-Debug, X-Internal-*)** | Per-host `header_blocklist`, `strip_server_header` | Không có UI dedicated (chỉ Hosts edit có vài trường) | 🟡 |
| FR-036–038 | Fail-close/fail-open per tier | `TierPolicy.fail_mode` | Không có UI (gắn với FR-002) | ❌ (chung với FR-002) |
| FR-039 | Circuit breaker upstream | Tự động trong gateway; không config | N/A | ✅ |
| FR-040 | HTTPS/TLS termination | `/api/certificates` CRUD | `pages/certificates` | ✅ |
| **FR-041** | **Geographic restriction (GeoIP allow/deny)** | `rules/geoip/country-blocklist.yaml` + `geo_*` ConditionField | `pages/custom-rules` có thể tạo rule geo; không page riêng | 🟡 |
| **FR-042** | **IP reputation feed (Tor + bad ASN)** | `/api/threat-intel/status` (read-only) | Widget trong `pages/settings`; không có editor cho feed file paths | 🟡 |
| FR-043 | Multi-region deployment | Không trong scope BE hiện tại | N/A | ❌ out-of-scope |
| FR-044 | Zero-downtime config sync | Cluster mesh đã có | `pages/cluster/sync` | ✅ |
| FR-045 | Auto-scaling | Cluster đã có | `pages/cluster/*` | ✅ |
| FR-046 | Behavioral ML scoring | Không trong BE hiện tại | N/A | ❌ out-of-scope |

### Tổng kết các nhóm FR cần page mới

| Nhóm | FR liên quan | Trạng thái UI |
|---|---|---|
| Tiered Protection editor | FR-002, FR-036/037/038 | ❌ Cần new page |
| Access Lists editor | FR-008 (YAML) | ❌ Cần new page |
| DDoS protection panel | FR-005 | ❌ Cần new page |
| Challenge engine editor | FR-006 | ❌ Cần new page |
| Relay/Proxy intel editor | FR-007 | ❌ Cần new page |
| Device fingerprinting | FR-010 | ❌ Cần new page |
| Behavioral anomaly | FR-011 | ❌ Cần new page (hoặc tab trong device-fp) |
| Risk scoring (decay/seed) | FR-025, FR-026 | ❌ Cần new page (mở rộng settings) |
| Live risk explorer | FR-025, FR-026 | ❌ Cần new page |
| TX Velocity config writer | FR-012 | 🟡 hiện chỉ đọc — cần edit |
| Response filtering nâng cao | FR-033, FR-034, FR-035 | 🟡 cần mở rộng settings + per-host editor |
| GeoIP rule list page | FR-041 | 🟡 cần page riêng |
| IP Reputation feed editor | FR-042 | 🟡 mở rộng settings |
| Rule sources / import wizard | FR-022 | 🟡 thiếu import wizard YAML upload |

---

## 2. Inventory chi tiết: BE endpoint vs FE page

### 2.1 BE endpoints đã được map sang FE

```
/api/hosts                          → pages/hosts
/api/allow-ips, /api/block-ips      → pages/ip-rules
/api/allow-urls, /api/block-urls    → pages/url-rules
/api/security-events                → pages/security-events
/api/attack-logs                    → pages/security-events (filter)
/api/custom-rules                   → pages/custom-rules
/api/certificates                   → pages/certificates
/api/lb-backends                    → pages/cc-protection
/api/hotlink-config                 → pages/cc-protection
/api/notifications                  → pages/notifications
/api/panel-config                   → pages/settings
/api/status                         → pages/settings + dashboard
/api/reload                         → pages/settings (button)
/api/sqli-scan/reload               → pages/settings (button)
/api/stats/overview                 → pages/dashboard, pages/rule-analytics
/api/stats/timeseries               → pages/dashboard, pages/rule-analytics
/api/stats/timeseries-by-category   → pages/rule-analytics
/api/stats/geo                      → pages/dashboard (top countries)
/api/stats/endpoints                → pages/dashboard (heatmap)
/api/threat-intel/status            → pages/settings
/api/rules/registry                 → pages/rules-management, dashboard, rule-analytics
/api/rules/reload                   → pages/rules-management
/api/rule-sources                   → pages/rule-sources
/api/bot-patterns                   → pages/bot-management
/api/cache/*                        → pages/cache
/api/cluster/*                      → pages/cluster/*
/api/crowdsec/*                     → pages/crowdsec-*
/api/audit-log                      → pages/logs (admin-only)
/api/v1/logs/*                      → pages/logs (VictoriaLogs proxy)
/api/plugins                        → KHÔNG có page (chưa wire UI)
/api/tunnels                        → KHÔNG có page (chưa wire UI)
/api/sensitive-patterns             → KHÔNG có page độc lập (chỉ qua custom-rules)
/ws/events, /ws/logs                → pages/dashboard, pages/logs
/ws/tunnel                          → KHÔNG có page
```

### 2.2 BE endpoint không có FE tương ứng

| Endpoint | FR | Đề xuất |
|---|---|---|
| `/api/plugins` CRUD + enable/disable | FR-046 (extensibility) | **Cần page** `Plugins Manager` |
| `/api/tunnels` CRUD + `/ws/tunnel` | Tunnel (extension) | **Cần page** `Tunnels` |
| `/api/sensitive-patterns` CRUD | FR-034 outbound redaction | **Cần page** `Sensitive Patterns` (dạng table per host) |
| `/api/notifications/{id}/test`, `/api/notifications/log` | FR-031 dashboard | Có handler nhưng UI chỉ test button — cần "Notification Log" tab |

### 2.3 FR thiếu UI hoàn toàn (chưa có cả BE endpoint quản trị) → cần thêm BE+FE

| FR | Config file | Cần BE endpoint mới | Cần FE page mới |
|---|---|---|---|
| FR-002 | `default.toml [tiered_protection]` hoặc tách `configs/tiered.yaml` | `GET/PUT /api/tier-policies` | `pages/tier-policies` |
| FR-005 | `default.toml [ddos]` | `GET/PUT /api/ddos-config`, `GET /api/ddos/ban-table` | `pages/ddos-protection` |
| FR-006 | `configs/challenge.yaml` | `GET/PUT /api/challenge-config` | `pages/challenge-engine` |
| FR-007 | `configs/relay.yaml` | `GET/PUT /api/relay-config`, `GET /api/relay/intel-status` | `pages/relay-intel` |
| FR-008 (YAML view) | `rules/access-lists.yaml` | `GET/PUT /api/access-lists` | `pages/access-lists` (per-tier table editor) |
| FR-010 | `configs/device-fp.yaml` | `GET/PUT /api/device-fp-config`, `GET /api/device-fp/recent-fps` | `pages/device-fingerprinting` |
| FR-011 | `device-fp.yaml::behavior` | Cùng `/api/device-fp-config` (sub-section) | Tab "Behavior" trong page FR-010 |
| FR-012 | `configs/tx-velocity.yaml` | `GET/PUT /api/tx-velocity-config` | Mở rộng `pages/tx-velocity` (mode editor) |
| FR-025 | `configs/risk.yaml` | `GET/PUT /api/risk-config`, `GET /api/risk/recent-actors` | `pages/risk-scoring` |
| FR-041 | `rules/geoip/country-blocklist.yaml` | `GET/PUT /api/geoip-rules`, đã có CRUD qua custom-rules | `pages/geo-restriction` |
| FR-042 | Feed file paths trong `risk.yaml::seed` | `POST /api/threat-intel/refresh`, GET đã có | Mở rộng panel trong settings |

---

## 3. Roadmap đề xuất (theo độ ưu tiên cho hackathon)

Tổng điểm 120 đ — cấu trúc panel cần "show off" được các FR tính điểm cao nhất.

### Sprint A (high-value, demo trực tiếp trong Attack Battle) — 1 tuần
1. **`pages/tier-policies`** (FR-002) — tạo BE + FE
2. **`pages/ddos-protection`** (FR-005) — ban-table viewer + threshold editor
3. **`pages/risk-scoring`** (FR-025) — live risk actors + decay/seed config
4. **`pages/challenge-engine`** (FR-006) — chọn JS/PoW + difficulty tiers + branding
5. **`pages/access-lists`** (FR-008) — YAML editor có validate

### Sprint B (defense in depth) — 1 tuần
6. **`pages/device-fingerprinting`** (FR-010 + FR-011) — 2-tab: Capture & Behavior
7. **`pages/relay-intel`** (FR-007) — providers ASN/Tor/datacenter + XFF rules
8. **`pages/tx-velocity`** (FR-012 edit mode) — thresholds editor
9. **`pages/geo-restriction`** (FR-041) — country block/challenge list
10. **`pages/response-filtering`** (FR-033/FR-034/FR-035) — gom các tab response

### Sprint C (operational) — vài ngày
11. **`pages/plugins`** (extensibility) — WASM upload/enable/disable
12. **`pages/tunnels`** (extension) — WS tunnel management
13. **`pages/sensitive-patterns`** (FR-034 per-host)
14. **Notification Log tab** trong `pages/notifications`

---

## 4. Prompt cho Cursor — sẵn copy-paste

> **Quy ước chung khi prompt**:
> - Stack FE: Vite + React 18 + TypeScript + Refine + AntD v5 + i18next + react-query
> - Code path: `web/admin-panel/src/pages/<page-name>/index.tsx`
> - Phải đăng ký route trong `web/admin-panel/src/App.tsx` và `nav-items.ts`
> - Phải thêm i18n keys vào `web/admin-panel/src/i18n/locales/{en,vi}.json`
> - Dùng `useCustom` / `useCustomMutation` từ Refine cho endpoint custom; `useTable`/`useList` cho RESTful resources
> - Mọi mutation hot-reload phải nhắc người dùng SIGHUP / file watch
> - Mọi page có editor YAML/TOML: dùng `@monaco-editor/react` nếu đã có, hoặc `<Input.TextArea>` với syntax check phía server
> - Snippet phải tuân theo tone code của `pages/settings/index.tsx` (SectionCard + SwitchRow + Form layout)

### Prompt 1 — FR-002 Tier Policies editor

````
**Task**: Build a new admin-panel page to manage **Tiered Protection Policy (FR-002)** for PRX-WAF.

**Backend prerequisite (create if missing in `crates/waf-api`)**:
1. `GET  /api/tier-policies` → returns `{ default_tier, classifier_rules[], policies: { critical, high, medium, catch_all } }` mirroring `waf-common::TierConfig`. Source: `configs/tier-policies.yaml` (create if absent — split out from `default.toml [tiered_protection]`).
2. `PUT  /api/tier-policies` → validates via `TierConfig::validate()` then atomically writes the YAML file. On success trigger hot-reload (the existing `notify` watcher will pick it up).
3. `POST /api/tier-policies/dry-run` → accepts the same body + a sample request `{ method, host, path, headers }` and returns the classified tier + applied policy snapshot (for the UI "Test classifier" widget).

**Frontend deliverable**: `web/admin-panel/src/pages/tier-policies/index.tsx`

Sections (use SectionCard pattern from `pages/settings`):
1. **Header**: title "Tiered Protection (FR-002)", subtitle "Per-tier policies & request classifier", reload+save buttons.
2. **Per-tier policy grid** (4 cards Critical / High / Medium / Catch-All), each showing:
   - `fail_mode`: Radio `close` / `open`
   - `ddos_threshold_rps`: InputNumber
   - `cache_policy`: Select `no_cache | short_ttl | aggressive | default` + conditional `ttl_seconds`
   - `risk_thresholds`: 3 sliders allow / challenge / block with validation `allow < challenge < block`
3. **Classifier rules table** (priority, tier, host match, path match, method bitset, headers). Use AntD Table with inline edit Drawer.
   - Path match types: `exact | prefix | regex` (must mirror `PathMatch`).
   - Host match types: `exact | suffix | regex`.
   - Methods: multi-select `GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|CONNECT|TRACE`.
4. **Test classifier widget** (right column): Input fields method/host/path/headers, "Run" button posts to `/api/tier-policies/dry-run` and displays the resulting tier + the policy that would apply, with a color-coded badge.
5. **Validation banner** (red Alert at top) when `risk_thresholds` violate `allow < challenge < block`.

Wiring:
- Register `tier-policies` resource in `App.tsx` (list: `/tier-policies`) and add nav item under section "nav.protection" with icon `ApartmentOutlined`.
- Add i18n keys under `tierPolicies.*` (en + vi). Vietnamese strings: keep technical terms in English.
- Page must auto-save dirty state warning (mirror `pages/settings` `isDirty` ref pattern).

**Don't**:
- Don't write to PostgreSQL — tier policies live in YAML config only.
- Don't allow deleting all four tiers; UI must enforce all four present.
- Don't expose internal field `default_tier` selector below "Catch-All" tier — fix to `CatchAll`.

**Acceptance**: Saving a valid config returns 200, page shows "Saved at HH:MM:SS"; saving an invalid config returns 4xx with `error.field` and the page highlights the offending field. After save, the proxy's tier classification (verifiable via dry-run) reflects the new policy within ~250 ms (file watch debounce).
````

### Prompt 2 — FR-005 DDoS Protection panel

````
**Task**: Create `pages/ddos-protection` for FR-005 (DDoS detection + ban table).

**Backend prerequisite (in `crates/waf-api`)**:
1. `GET  /api/ddos/config` → reads `[ddos]` section from main TOML or `configs/ddos.yaml`. Returns `{ enabled, per_ip: { threshold_rps, window_secs }, per_fingerprint: { threshold_rps, window_secs }, per_tier: { critical, high, medium, catch_all }, ban_durations_secs: [60, 300, 3600], store: { backend: "memory"|"redis", redis: {...} } }`.
2. `PUT  /api/ddos/config` → validates + writes + hot-reloads (mirror `panel-config` save flow).
3. `GET  /api/ddos/ban-table?limit=100&offset=0` → returns currently-banned entries from `DynamicBanTable`: `{ items: [{ ip, banned_until_ms, ban_level, last_rps, reason }], total }`.
4. `DELETE /api/ddos/ban-table/{ip}` → unban manually.
5. `GET  /api/ddos/metrics` → snapshot of internal counters: `ddos_hard_burst_total`, `ddos_bans_issued_total`, `ddos_ban_table_size`, `ddos_store_errors_total`, per-tier breakdown.

**Frontend deliverable**: `web/admin-panel/src/pages/ddos-protection/index.tsx`

Layout (top-down):
1. **KPI row**: 4 KpiCard — Active bans · Bursts (1h) · Bans issued (1h) · Store errors (1h). Auto-refresh 5s.
2. **Configuration card** (Form):
   - Switch `enabled`.
   - Two-column: Per-IP threshold (rps + window) | Per-fingerprint threshold (rps + window).
   - Per-tier overrides (4-row table: tier, threshold_rps, action on burst).
   - Ban escalation ladder: 3 InputNumbers (default 60 / 300 / 3600).
   - Store backend Select `memory | redis`, conditional Redis URL InputText.
3. **Ban table** (right or below): AntD Table with columns `IP | Ban level | Banned until (countdown) | Last RPS | Reason | Action(unban)`. Server-side pagination via `useTable` resource `ddos-ban-table`. Add filter `search by IP` and `ban_level` chips.
4. **Per-tier burst chart**: Recharts line chart (uses `/api/ddos/metrics` per-tier breakdown). Stacked area: critical/high/medium/catch_all.
5. **Live event sub-stream**: subscribe to `/ws/events?filter=ddos` (extend the existing WS), show 20 most recent `DDOS-BAN | DDOS-RISK | DDOS-DEGRADE` events in a compact tail like `pages/dashboard`.

Wiring:
- Add resource `ddos-protection` in `App.tsx`. Add nav item with icon `ThunderboltOutlined` under section "nav.protection".
- Add i18n keys under `ddos.*`.
- Reuse `KpiCard`, `EngineBadge` components.

**Don't**:
- Don't allow disabling `enabled` while there are >100 active bans without confirmation Popconfirm.
- Don't let UI bypass the validator that requires `threshold_rps >= 10`.

**Acceptance**: Unban from UI removes IP from `DynamicBanTable` within 200 ms; banned IP regains access on next request. Saving config returns 200 and metrics card reflects new threshold within 5 s.
````

### Prompt 3 — FR-006 Challenge Engine editor

````
**Task**: Create `pages/challenge-engine` to edit `configs/challenge.yaml` (FR-006).

**Backend prerequisite**:
1. `GET  /api/challenge/config` → reads `configs/challenge.yaml` (`crates/waf-engine::challenge::config::ChallengeConfig`). Returns the full struct.
2. `PUT  /api/challenge/config` → atomic-write + hot-reload.
3. `POST /api/challenge/preview` → renders the challenge HTML page server-side using current branding+type, returns the HTML string so UI can show a preview iframe.
4. `GET  /api/challenge/stats` → counts of challenges issued/passed/failed/replayed in last hour from the audit log.

**Frontend deliverable**: `web/admin-panel/src/pages/challenge-engine/index.tsx`

Sections:
1. **Header KPIs**: Issued · Passed · Failed · Replays — KpiCard row.
2. **Mode selector**: Radio (`enabled`) + Select `challenge_type`: `js_challenge` (only currently supported, but show `pow` / `captcha` as disabled with tooltip "Coming soon").
3. **Difficulty tiers table** (FR-006 PoW): editable AntD Table — columns `min_risk | max_risk | difficulty (leading zero bits)`. Validate ranges don't overlap and cover 0..=100.
4. **Token settings card**: `ttl_secs`, `cookie_name`, `cookie_max_age`, `same_site` (Strict/Lax/None), Switch `http_only`. Show a warning callout when `http_only=true` because JS can't read it.
5. **Branding card**: `title` Input, `message` TextArea. Live preview iframe loads `/api/challenge/preview` srcdoc.
6. **Nonce store card**: `capacity`, `gc_interval_secs`, `hmac_secret_path` (read-only display + Copy button + button "Rotate secret" that POSTs to `/api/challenge/rotate-secret`).

Wiring:
- Add nav item under "nav.protection" with icon `SafetyCertificateOutlined` (already used) — use `ExperimentOutlined` instead.
- i18n keys under `challenge.*`.
- Reuse `SectionCard`, `SwitchRow` from settings page.

**Don't**:
- Don't display the HMAC secret value; only show file path and last-modified time.
- Don't allow `ttl_secs > 86400` or `< 30`; enforce in InputNumber bounds.
- Don't ship the captcha option until the BE supports it.

**Acceptance**: After saving, hitting a route with risk score in the challenge band issues an HTML page reflecting the new title/message; replay detection increments the "Replays" KPI within 10 s.
````

### Prompt 4 — FR-007 Relay & Proxy Intel page

````
**Task**: Create `pages/relay-intel` to manage `configs/relay.yaml` (FR-007).

**Backend prerequisite**:
1. `GET  /api/relay/config` → returns the `relay` block: `{ enabled, providers: { asn_classifier: {...}, tor_exit: {...}, datacenter: {...}, proxy_chain: {...}, xff_validator: {...} }, intel: { asn_feed: {url, refresh_secs}, tor_feed: {url, refresh_secs}, datacenter_set: {url|path}, http_proxy: {...} }, trusted_proxies: ["10.0.0.0/8"], risk_weights: {...} }`.
2. `PUT  /api/relay/config` → validate + atomic write + hot-reload.
3. `POST /api/relay/intel/refresh` → force-refresh all intel feeds (Tor, ASN). Returns counts: `{ tor_loaded, asn_loaded, datacenter_loaded, took_ms }`.
4. `GET  /api/relay/intel/status` → similar to existing `/api/threat-intel/status` but with per-feed `last_refresh_ts`, `entry_count`, `last_error`.
5. `POST /api/relay/test` → input `{ client_ip, xff_chain[], user_agent }` → returns provider verdicts + summed risk delta.

**Frontend deliverable**: `web/admin-panel/src/pages/relay-intel/index.tsx`

Tabs (AntD `Tabs`):
1. **Intel feeds**: 3 cards Tor / ASN / Datacenter. Each shows entry count, last refresh timestamp, last error (red Alert), button "Refresh now". Editable: `url`, `path`, `refresh_secs`.
2. **Providers**: 5 SectionCards, one per provider (`asn_classifier`, `tor_exit`, `datacenter`, `proxy_chain`, `xff_validator`). Each:
   - Switch enabled.
   - Risk weight slider (0..50).
   - Provider-specific knobs (e.g. for xff_validator: `max_chain_depth`, `reject_private_in_chain` switch).
3. **Trusted proxies**: Tag input (CIDR validation) — same UX as `trustedBypass` chips in `pages/settings`.
4. **Test request**: form `client_ip`, `xff_chain` (Tag input), `user_agent` → shows providers' verdicts in a table + total risk delta.

Wiring:
- Add nav item under "nav.intel" (new section) with icon `BranchesOutlined`.
- i18n keys `relay.*`.

**Don't**:
- Don't refresh intel feeds automatically from the UI — operator must click Refresh.
- Don't expose internal cache size knobs.

**Acceptance**: Refresh now button reports e.g. `tor_loaded: 1500` and the count is reflected in the card within 2 s. Test request widget reflects provider risk deltas matching the documented signal weights.
````

### Prompt 5 — FR-008 Access Lists page

````
**Task**: Create `pages/access-lists` to manage `rules/access-lists.yaml` (FR-008) — per-tier IP & Host whitelist/blacklist.

**Backend prerequisite**:
1. `GET  /api/access-lists` → returns parsed `AccessConfig` (version, dry_run, ip_whitelist, ip_blacklist, host_whitelist:{critical,high,medium,catch_all}, tier_whitelist_mode:{...}).
2. `PUT  /api/access-lists` → validate (parse YAML, reject >50k entries with WARN, hard reject >500k) + atomic write. The existing `AccessReloader` picks up the change.
3. `GET  /api/access-lists/test?ip=X.X.X.X&host=Y&tier=Z` → returns the decision for that input: `{ decision: "allow"|"block"|"pass", reason, match }`.

**Frontend deliverable**: `web/admin-panel/src/pages/access-lists/index.tsx`

Sections:
1. **Header**: title "Access Lists (FR-008)", subtitle "Phase-0 IP/Host allow & block lists per tier", reload+save+dry-run-toggle.
2. **Global toggles**:
   - `dry_run` Switch (with tooltip "Log only, don't block")
   - `version` (display-only, locked to 1).
3. **IP Whitelist** card: Tag input area (paste-multiline supported, IPv4/IPv6/CIDR validation client-side). Show count + soft warning when > 50k.
4. **IP Blacklist** card: same UX as IP Whitelist.
5. **Per-tier Host Whitelist** (4 cards Critical/High/Medium/Catch-All):
   - Tag input of FQDNs (lowercase, no port).
   - Tier whitelist mode: Segmented `full_bypass | blacklist_only` with tooltip explaining each.
6. **Decision tester** (sticky right column or bottom card): Form with `client_ip`, `host`, `tier` → button "Test" calls `/api/access-lists/test`, renders verdict + reason badge.

Wiring:
- Resource `access-lists`, route `/access-lists`, nav item under "nav.protection" with icon `LockOutlined`.
- i18n keys `accessLists.*`.

**Don't**:
- Don't accept a tier as the new default tier (it's fixed schema).
- Don't let the user enable `full_bypass` for `critical` without showing a strong red warning Popconfirm — the schema default is `blacklist_only` for safety.
- Don't auto-deduplicate — if user pastes duplicates, show duplicate-count badge but keep the list.

**Acceptance**: Saving a list of 5000 IPs takes < 300 ms; the next request from a blacklisted IP is denied (verifiable via the Test card). dry_run=true causes blocked IPs to be logged but allowed through (gateway audit shows `access_decision: block` + actual response 200).
````

### Prompt 6 — FR-010/FR-011 Device Fingerprinting & Behavioral Anomaly

````
**Task**: Create `pages/device-fingerprinting` page for FR-010 (capture) + FR-011 (behavior).

**Backend prerequisite**:
1. `GET  /api/device-fp/config` → returns the full `configs/device-fp.yaml` parsed (capture, store, providers list, behavior block).
2. `PUT  /api/device-fp/config` → validate + atomic write + hot-reload.
3. `GET  /api/device-fp/recent?limit=50` → recent `FpKey` records: `{ fp, ja3, ja4, h2_hash, ua, distinct_ips_24h, distinct_uas_24h, first_seen, last_seen, ip_hopping_signal_count }`.
4. `GET  /api/device-fp/conflicts?limit=50` → recent identities flagged with fp_conflict or ip_hopping.

**Frontend deliverable**: `web/admin-panel/src/pages/device-fingerprinting/index.tsx`

Two top-level AntD Tabs: **Capture & Providers** (FR-010), **Behavior** (FR-011).

#### Tab 1 — Capture & Providers
1. Switch `enabled`.
2. Capture card: `tls.enabled` + algorithms multi-select [ja3, ja4]; `h2.enabled` + hash select `akamai`.
3. Store card: backend Select `memory|redis`; conditional redis URL; `ttl_secs`.
4. Providers table (5 rows: ip_hopping, fp_conflict, ua_entropy, ua_blocklist, h2_anomaly):
   - signal_weight (Slider 0..50)
   - provider-specific knobs (e.g. ip_hopping: `window_secs`, `max_distinct_ips`; ua_entropy: `min_entropy_x100`; ua_blocklist: Tag input for regex patterns).
5. **Recent fingerprints** table at bottom: server-side paginated, columns `fp (truncated) | JA3/JA4 | UA (truncated) | distinct IPs 24h | first/last seen | actions (View, Add to deny)`.

#### Tab 2 — Behavior (FR-011)
1. `window_size`, `actor_ttl_secs` InputNumber.
2. **Burst interval** card: Switch enabled, threshold_ms (default 50), min_consecutive (5), risk_delta slider.
3. **Regularity** card: Switch enabled, min_samples, cv_threshold (0..1), min_mean_ms, risk_delta.
4. **Zero-depth** card: Switch enabled, min_samples, critical_hits_required, risk_delta, exempt_entry_paths Tag input.
5. **Missing-referer** card: Switch enabled, risk_delta, exempt_paths Tag input, exempt_prefixes Tag input.

Wiring:
- Resource `device-fingerprinting`, route `/device-fingerprinting`. Nav item under "nav.intel" with icon `FingerprintOutlined` (or `ScanOutlined`).
- i18n keys `deviceFp.*` + `deviceFp.behavior.*`.

**Don't**:
- Don't display raw TLS handshake bytes from the recent table — only JA3/JA4 hash.
- Don't allow `cv_threshold > 1.0` or `< 0.01`.
- Don't auto-purge recent table on save.

**Acceptance**: Toggling a provider's enabled flag immediately changes `signal_weight` contribution within 250 ms; the Recent table reflects new fingerprints within the WS refresh interval (10s).
````

### Prompt 7 — FR-012 TX Velocity editable mode

````
**Task**: Extend the existing read-only `pages/tx-velocity` to support editing thresholds (FR-012).

**Backend prerequisite**:
1. `GET  /api/tx-velocity/config` → returns parsed `configs/tx-velocity.yaml`.
2. `PUT  /api/tx-velocity/config` → validate + atomic write + hot-reload (`ArcSwap<TxVelocityConfig>` watcher).

**Frontend changes**: `web/admin-panel/src/pages/tx-velocity/index.tsx`

Add a new **Configuration card** (AntD Form):
1. Switch `enabled`.
2. `session_cookie` Input.
3. `signal_cooldown_ms`, `session_ttl_secs`, `janitor_period_secs` InputNumbers.
4. **Endpoint roles** editable Table with columns `role` (Select: login|otp|deposit|withdrawal|limit_change) and `path` (regex Input). Drag to reorder; first match wins.
5. **Classifiers** sub-cards:
   - Sequence: `min_human_ms`.
   - Withdrawal velocity: `max_count`, `window_ms`.
   - Limit-change velocity: `max_count`, `window_ms`.
   - Allow operator to disable a classifier by toggling its Switch — sets the block to absent on save.
6. Save button (mirror `pages/settings` dirty-state pattern).

Keep the existing KPI row, distribution chart, recent events table.

Wiring:
- Reuse current nav item.
- Add i18n keys `txVelocity.config.*`.

**Don't**:
- Don't remove the read-only "Detection Thresholds" Descriptions block — keep it but populate from the new live config so the two views stay synced.
- Don't allow regex pattern that exceeds 200 chars (DoS prevention).

**Acceptance**: A burst of 6 withdrawals from the same session within `window_ms` triggers a `TX-WITHDRAW-*` signal visible in the KPI counter and Recent events within 5 s after save.
````

### Prompt 8 — FR-025 Risk Scoring page

````
**Task**: Create `pages/risk-scoring` for FR-025 cumulative risk scoring engine.

**Backend prerequisite**:
1. `GET  /api/risk/config` → parsed `configs/risk.yaml`.
2. `PUT  /api/risk/config` → atomic write + hot-reload.
3. `GET  /api/risk/actors?limit=50&min_score=0` → top current actors: `{ key: {ip, fp, session}, score, last_seen_ms, contributors_count }`.
4. `GET  /api/risk/actors/{id}` → detail with contributor list: `[{kind, delta, ts_ms, source}]`.
5. `POST /api/risk/actors/{id}/credit` → manual credit (negative delta) for moderator override; body `{ delta: i16, reason }`.
6. `POST /api/risk/actors/{id}/clear` → reset score to 0.

**Frontend deliverable**: `web/admin-panel/src/pages/risk-scoring/index.tsx`

Layout:
1. **Header KPI row**: actor count, average score, p95 score, scored / blocked / challenged in last hour.
2. **Config card** (collapsible top section) — full `risk.yaml` editor split into sub-SectionCards:
   - Toggle `enabled` + `ttl_secs` + `gc_interval_secs` + `session_cookie` + `header_name` + Switch `emit_header`.
   - Store backend (memory/redis with redis sub-form).
   - Decay: `min_clean_streak`, `decay_rate`, `max_decay`.
   - Seed L0: paths to Tor/ASN/whitelist files + Tor/datacenter/bad_asn deltas.
   - Canary (FR-028 reuse): Tag input `paths`, `ban_ttl_secs`. Switch enabled.
   - Challenge credit: token TTL, lru_size, header_name, valid/invalid/replay/expired deltas.
3. **Live actors table** below: server-side paginated useTable on `/api/risk/actors`. Columns: `key (ip / fp / session truncated, copy on hover) | score (colored bar) | contributors_count | last_seen | actions`. Row click opens Drawer:
   - Header: full key, current score, decision band based on FR-027 thresholds (pull from `/api/panel-config`).
   - Contributors timeline: chronological list with `kind`, `delta`, `ts`, `source`. Highlight `Seed::Tor`, `Canary`, `Challenge::Invalid` in distinct colors.
   - Action buttons: "Add credit" (Modal -50/-25/-10), "Clear score", "Add IP to blocklist".
4. **Distribution chart**: Histogram of current actor scores binned 0-10, 10-20, ..., 90-100.

Wiring:
- Resource `risk-scoring`, route `/risk-scoring`. Nav item under "nav.intel" with icon `SecurityScanOutlined`.
- i18n keys `risk.*` + `risk.contributors.*`.

**Don't**:
- Don't expose raw HMAC secret of challenge config — show only file path.
- Don't allow `decay_rate > 50` (would defeat scoring).
- Don't show the full session cookie value in the actor key — show last 8 chars only.

**Acceptance**: Manual credit of -25 reflects in the actor's score within 200 ms (single-node) and persists across reload. Toggling `canary.enabled=false` stops max-score pins on canary paths within ~250 ms (file watch debounce).
````

### Prompt 9 — FR-033/FR-034/FR-035 Response Filtering

````
**Task**: Create `pages/response-filtering` consolidating FR-033/FR-034/FR-035.

**Backend prerequisite**:
1. Extend existing `/api/panel-config` PUT body to accept new sub-fields under `response_filtering`:
   - `categories: { stack_trace, verbose_error, secrets, internal_ip }` (each `{ enabled: bool, redact: bool, block_on_match: bool }`).
   - `max_body_bytes` (currently per-host; expose global default).
2. New endpoint `GET /api/hosts/{id}/response-filter` and `PUT /api/hosts/{id}/response-filter` to set per-host `internal_patterns`, `header_blocklist`, `body_scan_enabled`, `body_scan_max_body_bytes`, `strip_server_header`. (Most fields already exist on `HostConfig` — needs handler surfacing.)
3. New `POST /api/response-filtering/preview` body `{ sample_response_body, content_type }` returns the body after scanning so operator can preview what would be redacted.

**Frontend deliverable**: `web/admin-panel/src/pages/response-filtering/index.tsx`

Tabs:
1. **Global** (FR-033/FR-034):
   - Category cards (Stack Trace · Verbose Error · Secrets · Internal IP): each with Switch enabled + Radio `redact|block_on_match`.
   - JSON redact field list: chips (already exists in settings — pull from same endpoint).
   - `max_body_bytes` global default InputNumber.
   - Preview widget: TextArea sample body + Select content_type + Run button.
2. **Per-host** (FR-035 + per-host overrides): Host selector dropdown → loads `/api/hosts/{id}/response-filter`. Form:
   - Switch `body_scan_enabled`.
   - `body_scan_max_body_bytes` InputNumber.
   - `internal_patterns` Tag input (regex per line; validate each).
   - `header_blocklist` Tag input (header names).
   - Switch `strip_server_header`.

Wiring:
- Resource `response-filtering`, route `/response-filtering`. Nav item under "nav.outbound" (new section) with icon `EyeInvisibleOutlined`.
- i18n keys `responseFilter.*`.
- Remove the now-redundant "Response filtering" SectionCard from `pages/settings` (or replace with a link "Open Response Filtering page").

**Don't**:
- Don't allow `internal_patterns` regex that doesn't compile — validate client-side via `new RegExp(p)` try/catch before adding the chip.
- Don't allow `header_blocklist` to contain `Authorization` (would break legitimate flows) — block client-side with a warning.

**Acceptance**: Adding a regex `password=[^&]+` to internal_patterns of a host immediately causes that pattern to be replaced with `[redacted]` in upstream responses on the next request (~250 ms reload).
````

### Prompt 10 — FR-041 GeoIP Restriction page

````
**Task**: Create `pages/geo-restriction` to manage country/ISP allow/block rules (FR-041) without forcing operators to author raw YAML.

**Backend prerequisite**:
1. `GET  /api/geoip/rules` → returns the list parsed from `rules/geoip/country-blocklist.yaml` and any custom_rules with `field: geo_iso|geo_country|geo_isp`.
2. `POST /api/geoip/rules` (and `PUT/DELETE`) — wraps existing `/api/custom-rules` create with `field: geo_*`.
3. `GET  /api/geoip/lookup?ip=X.X.X.X` → returns `{ iso, country, province, city, isp }` from the GeoIP database. (Already partially exists in `geo_info` on security events.)

**Frontend deliverable**: `web/admin-panel/src/pages/geo-restriction/index.tsx`

Sections:
1. **Header**: title + nav: dropdown filter Action (block/challenge/log/allow).
2. **Country table** (AntD Table). Columns: country flag + ISO code · country name · action (Select inline) · scope (Tag: global / host) · enabled (Switch) · created_at. Rows are the parsed list; clicking "Add country" opens a Drawer that calls a list of all ISO codes (use a static client-side list of ISO 3166-1 alpha-2).
3. **ISP rules** card: Tag input of ISP regex patterns + action selector, scope selector.
4. **Lookup widget** (right column): IP input → "Lookup" button hits `/api/geoip/lookup` → shows country flag, ISO, country, ISP. Provides "Block this country" shortcut button.
5. **Stats card** below: top blocked countries last 24h (reuse `/api/stats/geo`).

Wiring:
- Resource `geo-restriction`, route `/geo-restriction`. Nav item under "nav.intel" with icon `GlobalOutlined`.
- i18n keys `geo.*`.

**Don't**:
- Don't write directly to the YAML file in this v1 — funnel through custom-rules so the existing rule registry stays consistent.
- Don't allow blocking the country of the operator's current IP without Popconfirm warning (call `/api/geoip/lookup?ip=<own>` for self-IP detection).

**Acceptance**: Adding a country block produces a new entry in `pages/rules-management` with `GEO-COUNTRY-*` prefix; the next request from a matching country is blocked within 1 s.
````

### Prompt 11 — WASM Plugins Manager

````
**Task**: Create `pages/plugins` to manage WASM plugins (BE endpoints already exist).

**Frontend deliverable**: `web/admin-panel/src/pages/plugins/index.tsx`

Wires existing endpoints:
- `GET  /api/plugins` (list)
- `POST /api/plugins` (multipart upload: name, version, description, author, file)
- `DELETE /api/plugins/{id}`
- `POST /api/plugins/{id}/enable`
- `POST /api/plugins/{id}/disable`

Layout:
1. **Header**: title "WASM Plugins" + "Upload plugin" button → AntD Modal with form fields and `<input type="file" accept=".wasm">`. Client-side validate magic bytes `\0asm` before submit; show "Invalid WASM" error otherwise.
2. **Plugins table**: columns `Name | Version | Author | Description | Enabled (Switch — POST enable/disable) | Size (bytes formatted) | Created | Actions (Delete with Popconfirm)`.
3. Empty state with link to `/docs/plugins-getting-started`.
4. Per-row Drawer on click → shows full plugin info + load status (if backend rejected compile, show error).

Wiring:
- Resource `plugins`, route `/plugins`. Nav item under "nav.extensions" (new section) with icon `ApiOutlined`.
- i18n keys `plugins.*`.
- Use multipart form via raw axios in the dataProvider's `custom` action (Refine's `useCreate` doesn't natively handle multipart).

**Don't**:
- Don't allow uploading > 10 MB (validate client-side).
- Don't expose `wasm_binary` in the table — strip on display.
- Don't auto-enable a freshly uploaded plugin if the upload validation backend returned a compile warning.

**Acceptance**: Uploading a valid `.wasm` file shows up in the list with size; toggling enabled runs the plugin's `on_request` on the next proxied request (verifiable in security events).
````

### Prompt 12 — Tunnels page

````
**Task**: Create `pages/tunnels` for tunnel management (BE endpoints already exist).

**Frontend deliverable**: `web/admin-panel/src/pages/tunnels/index.tsx`

Wires existing endpoints:
- `GET  /api/tunnels`
- `POST /api/tunnels` (body: `{ name, local_port, target_host, target_port, protocol: tcp|udp|ws }`)
- `DELETE /api/tunnels/{id}`
- `GET  /ws/tunnel?tunnel_id=X` → real-time bytes-in/out + connection count

Layout:
1. **Header**: title + "Create tunnel" button → Modal form.
2. **Tunnel table**: columns `Name | Local port | Target | Protocol | Active connections | Bytes in/out (last 1m) | Status | Actions`.
3. Per-row click → Drawer with live WS stats (line chart bytes/sec).

Wiring:
- Resource `tunnels`, route `/tunnels`. Nav item under "nav.extensions" with icon `ShareAltOutlined`.
- i18n keys `tunnels.*`.

**Don't**:
- Don't allow local_port in the privileged range (< 1024) without Popconfirm.
- Don't show the WS stream until the tunnel is in "active" state.

**Acceptance**: Created tunnel shows status active within 500 ms; deleting closes the listener and removes the entry.
````

### Prompt 13 — Sensitive Patterns page

````
**Task**: Create `pages/sensitive-patterns` to manage FR-034 outbound redaction patterns (BE endpoints already exist as `/api/sensitive-patterns`).

**Frontend deliverable**: `web/admin-panel/src/pages/sensitive-patterns/index.tsx`

Wires existing endpoints:
- `GET  /api/sensitive-patterns`
- `POST /api/sensitive-patterns` (body: `{ host_code, pattern, pattern_type: word|regex, check_request, check_response, action, remarks, enabled }`)
- `DELETE /api/sensitive-patterns/{id}`
- `PATCH /api/sensitive-patterns/{id}` (toggle enabled) — add this handler if missing.

Layout:
1. **Header**: title "Sensitive Patterns (FR-034)" + Host filter Select + "Add pattern" button.
2. **Table**: columns `Host | Pattern (truncated, with regex/word badge) | Direction (req/resp tags) | Action | Enabled (Switch) | Remarks | Actions (Edit, Delete)`.
3. Drawer for Create/Edit form:
   - Host Select (loaded from `/api/hosts`).
   - Pattern Input + radio `word | regex`.
   - Live test field: paste sample text → highlight matches.
   - Switch `check_request`, Switch `check_response`.
   - Action Select `block | redact | log`.
   - Remarks TextArea.
4. **Bulk import** button: opens Modal with TextArea — one pattern per line, parsed into preview table before submit.

Wiring:
- Resource `sensitive-patterns`, route `/sensitive-patterns`. Nav item under "nav.outbound" with icon `EyeInvisibleOutlined`.
- i18n keys `sensitive.*`.

**Don't**:
- Don't allow a regex pattern that doesn't compile — validate via `new RegExp(p)` first.
- Don't allow patterns shorter than 3 chars (FP risk).
- Don't auto-enable check_response without warning since it scans every byte.

**Acceptance**: Adding pattern "card_number" with `check_response=true, action=redact` causes the next response containing `card_number: 1234` to be rewritten to `card_number: [redacted]`.
````

### Prompt 14 — Notification Log tab

````
**Task**: Extend `pages/notifications` to show notification log (handler `/api/notifications/log` already exists).

**Frontend changes**: `web/admin-panel/src/pages/notifications/index.tsx`

Add an AntD Tabs wrapper at the top:
1. **Tab 1: Configs** — existing table.
2. **Tab 2: Log** — new. Calls `useCustom({ url: "/api/notifications/log", ...})`. Table columns: `Timestamp | Config name | Channel | Event type | Status (sent/failed) | Latency ms | Error (truncated)`. Filters: channel, event_type, status. Server-side pagination.
3. Auto-refresh 30 s (Switch).
4. CSV export of the visible page.

Wiring:
- Add i18n keys `notifications.log.*`.

**Don't**:
- Don't display the full webhook URL or Telegram bot token in the Error column — server should redact before sending.

**Acceptance**: Test-sending a notification shows up as a new entry in the Log tab within 5 s with Status=sent and Latency populated.
````

### Prompt 15 — Rule import wizard (FR-022)

````
**Task**: Extend `pages/rules-management` with a Rule Import wizard that wraps `POST /api/rules/import`.

**Frontend changes**: `web/admin-panel/src/pages/rules-management/index.tsx`

Add a button "Import rules" at top → opens a Modal wizard (3 steps via AntD Steps):

1. **Step 1 — Source**: Radio `Upload YAML/TOML file | Paste content | Fetch from URL`. Conditional inputs.
2. **Step 2 — Preview**: client-side parse (use `yaml` package already vendored — if not, ask backend with `POST /api/rules/import?dry_run=true`). Show table of parsed rules with category badge + count summary. Allow per-rule deselect.
3. **Step 3 — Confirm**: shows diff (added / updated / skipped IDs already in registry), Switch `replace_on_conflict`, "Import" button. After import, show success toast with counts.

Wiring:
- i18n keys `rules.import.*`.
- After import, refetch `/api/rules/registry`.

**Don't**:
- Don't allow files > 5 MB.
- Don't allow URL fetch without `https://`.
- Don't auto-enable rules with `category: experimental` — default disabled in the preview.

**Acceptance**: Importing a YAML with 10 rules including 2 conflicts and `replace_on_conflict=false` shows 8 added + 2 skipped in the registry within 2 s.
````

### Prompt 16 — Threat-intel feed editor (FR-042)

````
**Task**: Extend `pages/settings` "Threat intel" section into a full FR-042 editor.

**Backend prerequisite**:
1. Already exists: `GET /api/threat-intel/status`.
2. Add: `POST /api/threat-intel/refresh` → forces refresh of all feed sources defined in `risk.yaml::seed`. Returns counts and durations per feed.
3. Add: `PUT /api/threat-intel/feeds` → updates the feed file paths in `risk.yaml::seed.tor_exits_path` / `asn_classes_path` / `whitelist_path`.

**Frontend changes**: `web/admin-panel/src/pages/settings/index.tsx`

Replace the existing read-only `ReputationStatus` widget with a dedicated SectionCard:

1. **Per-feed cards** (Tor / ASN / Whitelist): each shows entry count, last refresh, last error. Editable: feed file path (Input with file-exists validation via backend), refresh interval. "Refresh now" button.
2. **Risk deltas**: 3 InputNumbers tor_delta / datacenter_delta / bad_asn_delta (mirror `risk.yaml::seed`).
3. **Add to whitelist** quick widget: IP/CIDR Input → "Add" appends to the whitelist file (POST `/api/threat-intel/feeds/whitelist/add`).
4. Move advanced editing to the new `pages/risk-scoring` page (link from here).

Wiring:
- Reuse i18n keys, add new under `settings.threatIntel.*`.

**Don't**:
- Don't show the contents of the Tor exit list inline (too large) — only count + last 5 entries.
- Don't block on file-path validation if the path doesn't exist yet — show a yellow warning instead.

**Acceptance**: Adding `1.2.3.4/32` to the whitelist file causes the next request from that IP to bypass all rules (verifiable in security events: `access_decision: allow`).
````

---

## 5. Cross-cutting refactors gợi ý

Khi đã add nhiều page mới, cần refactor để giữ codebase clean:

### Refactor A — Tách nav sections

`web/admin-panel/src/utils/nav-items.ts` hiện chỉ có 5 section. Đề xuất reorganize:

```ts
sections: [
  "nav.overview",      // dashboard, hosts, security-events, logs
  "nav.protection",    // tier-policies, access-lists, ddos-protection, challenge-engine
  "nav.detection",     // rules-management, custom-rules, rule-sources, bot-management, rule-analytics
  "nav.intel",         // device-fingerprinting, relay-intel, risk-scoring, geo-restriction
  "nav.outbound",      // response-filtering, sensitive-patterns
  "nav.fraud",         // tx-velocity
  "nav.cluster",       // cluster, cluster/tokens, cluster/sync
  "nav.crowdsec",      // crowdsec-settings, crowdsec-decisions, crowdsec-stats
  "nav.extensions",    // plugins, tunnels
  "nav.cache",         // cache
  "nav.system",        // settings, certificates, ip-rules, url-rules, notifications, cc-protection
]
```

### Refactor B — Generic YAML editor hook

Hầu hết các page mới (tier-policies, access-lists, challenge, risk, device-fp, relay, tx-velocity) đều load/save YAML config kèm validation + hot-reload notice. Tạo `useYamlConfig<T>({ url, schema, debounceMs })` để:
- Auto-refetch + detect external change (so sánh `revision` hash, hiển thị "File changed externally" banner)
- Dirty-state tracking
- Optimistic save with rollback
- Validation hook tích hợp ajv schema

### Refactor C — Standard "Test widget" pattern

Tier-policies, access-lists, relay-intel, geo-restriction đều có một "Test request" widget bên phải/đáy. Trừu tượng hóa thành `<TestRequestWidget endpoint="/api/foo/test" fields={[...]} renderResult={fn} />`.

---

## 6. Bảng tóm tắt: FR có UI / chưa có UI

```
Đã có UI đầy đủ:        FR-001 003 009 (stats) 013-020 021 024 027 028 029 030 031 032 039 040 044 045
Có UI một phần:         FR-004 006 008 009 (YAML) 012 022 023 025 033 034 035 041 042
Chưa có UI:             FR-002 005 007 010 011 026 036 037 038
Out-of-scope/N/A:       FR-043 046

Tổng FR P0+P1:          46
Đã có UI hoàn chỉnh:    20
Có UI một phần:         14
Thiếu UI hoàn toàn:     10  ← targets cần generate
Out-of-scope:            2
```

---

## 7. Mức ưu tiên prompt nên chạy trước (theo điểm hackathon)

> Tổng 120 điểm; Security Effectiveness 40 + Intelligence 20 chiếm 60 điểm.

| Ưu tiên | Prompt | Lý do (FR + điểm) | Effort |
|---|---|---|---|
| P0 | Prompt 1 — Tier Policies | FR-002 nền tảng cho mọi tier behavior; Intelligence (20đ) phụ thuộc | M |
| P0 | Prompt 8 — Risk Scoring | FR-025 + FR-026 + canary view; demo Intelligence (20đ) | L |
| P0 | Prompt 2 — DDoS Protection | FR-005 + Graceful degradation; Performance (20đ) + Intelligence | M |
| P0 | Prompt 6 — Device Fingerprinting | FR-010 + FR-011; trong Security Effectiveness (40đ) | L |
| P1 | Prompt 5 — Access Lists | FR-008 là phase-0 quan trọng | S |
| P1 | Prompt 3 — Challenge Engine | FR-006 demo Adaptive Allow/Challenge/Block | M |
| P1 | Prompt 4 — Relay Intel | FR-007 đi cùng "Relay & Proxy Attack" battle scenario | M |
| P2 | Prompt 7 — TX Velocity edit | FR-012 đã có read-only — nâng cấp dễ | S |
| P2 | Prompt 9 — Response Filtering | FR-033/34/35 là Outbound Protection (BẮT BUỘC) | M |
| P2 | Prompt 10 — Geo Restriction | FR-041 P1 bonus | S |
| P3 | Prompt 11 — Plugins | Extensibility (10đ) | S |
| P3 | Prompt 12 — Tunnels | Operability nice-to-have | S |
| P3 | Prompt 13 — Sensitive Patterns | Bổ trợ FR-034 | S |
| P3 | Prompt 14 — Notification Log | UX completeness | XS |
| P3 | Prompt 15 — Rule Import wizard | FR-022 P0 nhưng có CLI thay thế | S |
| P3 | Prompt 16 — Threat-intel feed editor | FR-042 P1 bonus | S |

**Effort scale**: XS<1h, S=2-4h, M=4-8h, L=1-2 days. Đa số prompt độ Sprint A nên chạy song song trên multiple cursor tabs.

---

## 8. Notes triển khai

1. **Auth & RBAC**: tất cả new endpoints phải dưới `protected_routes` (JWT). Nếu là destructive (PUT/DELETE/POST), nên gate qua `admin-only` middleware như `/api/v1/logs/*` đã làm.
2. **Hot reload contract**: mọi PUT phải atomic write file (write tmp + rename), không để gateway đọc nửa chừng.
3. **Pagination**: server-side cho tất cả tables > 100 rows (actor list, ban table, sensitive patterns). Mirror contract `page` / `page_size` / `{data, total}`.
4. **WebSocket**: nếu thêm `/ws/risk` hoặc `/ws/ddos`, đảm bảo qua `admin_ip_check_middleware` + `rate_limit_middleware` như WS hiện tại.
5. **Audit**: mọi PUT/POST sửa config nên log entry vào `audit_log` table với `actor=jwt.sub`, `action="config_update"`, `target=<endpoint>`, body diff (redacted secrets).
6. **i18n**: file `en.json` đã rộng — cân nhắc split sang per-page JSON file nếu vượt 1000 lines (Refine i18n provider hỗ trợ namespace).

---

**Cập nhật**: tài liệu này dựa trên snapshot codebase đến `crates/waf-api/src/server.rs` và `web/admin-panel/src/App.tsx` mới nhất trong project knowledge. Khi BE thay đổi (đặc biệt nếu thêm endpoint mới ngoài bảng §2.1), cần re-cross-check trước khi prompt Cursor.
