# Cursor Prompt — PRX-WAF Admin Panel: Rule Analytics Dashboard + Security Event Detail

> **Scope:** thêm 2 trang mới vào `web/admin-panel` (React 18 + Refine 5 + AntD 5 + Vite 8):
>  1. `/rule-analytics` — dashboard tham khảo Azure WAF (ảnh đính kèm) hiển thị phân bố attack theo Rule Group / Action / Top Blocked URIs / Top Rules / Timeline / Rules Details.
>  2. `/security-events/:id` — trang chi tiết 1 log security event với mọi trường, header, geo, raw detail.
> **Tham chiếu UI:** Azure Application Gateway WAF dashboard — donut charts 2 cột, grid 11 ô top URIs, timeline stacked bars 24h, table top rules + table chi tiết.
> **Output yêu cầu:** TypeScript strict, không placeholder, không dependency mới.

---

## 0. Bắt buộc đọc trước

Trước khi viết code, scan các file dưới đây qua repo (chúng đã tồn tại — KHÔNG tự bịa shape):

1. `crates/waf-api/src/stats.rs` — endpoints `/api/stats/overview`, `/api/stats/timeseries?hours=24`, `/api/stats/geo`.
2. `crates/waf-api/src/server.rs` — endpoint `/api/security-events` (GET list với query params), `/api/rules/registry`.
3. `crates/waf-storage/src/models.rs` — `SecurityEvent`, `AttackLog`, `RecentEvent`, `TopEntry`, `TimeSeriesPoint`, `SecurityEventQuery`.
4. `crates/waf-storage/src/repo.rs::list_security_events` + `get_stats_overview` + `get_stats_timeseries` — phân biệt query params + shape.
5. `web/admin-panel/src/types/api.ts` — `StatsOverview`, `TopEntry`, `RecentEvent`, `TrafficPoint`, `SecurityEvent`.
6. `web/admin-panel/src/components/{kpi-card,top-list,category-bars,traffic-chart,engine-badge}.tsx` — reuse, không tạo lại.
7. `web/admin-panel/src/components/category-bars.tsx` — `categoryColors` + `actionColors` palette (dùng nguyên).
8. `web/admin-panel/src/pages/dashboard/index.tsx` — pattern để copy (Row/Col 12-12-6-6, refetchInterval).
9. `web/admin-panel/src/providers/data-provider.ts` — biết envelope unwrap.

Schema thực tế của `SecurityEvent` (DB row, không sửa được):

```
id          uuid
host_code   text
client_ip   text         (lưu plain text, KHÔNG phải INET)
method      text
path        text
rule_id     text | null
rule_name   text
action      text         (block | log | allow | challenge | log_only | redirect)
detail      text | null
geo_info    jsonb | null  (keys: country, province, city, isp, iso_code)
created_at  timestamptz
```

> `request_headers`, `query`, `phase` **không** có trên `security_events` — chỉ có trên `attack_logs`. Trang detail dưới đây hiển thị cả 2 nguồn khi cần.

---

## 1. Trang `/rule-analytics` — Rule Analytics Dashboard

**File mới:** `web/admin-panel/src/pages/rule-analytics/index.tsx`

### 1.1. Layout (theo ảnh tham khảo)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  [Title] [time range picker]   [host filter]   [Refresh] [Export CSV]        │
├─────────────────────────────────┬────────────────────────────────────────────┤
│  Total WAF Requests by          │  WAF Actions                               │
│  Rule Group (donut, clickable)  │  (donut, clickable filter)                 │
│  [center: total count]          │  [center: total events]                    │
│  Legend bên phải với count      │  Legend bên phải với count                 │
├─────────────────────────────────┴────────────────────────────────────────────┤
│  Top Blocked Request URIs (grid 6 cols × N rows of colored tiles)            │
│  Mỗi ô: path tóm tắt + count                                                 │
├──────────────────────────────────┬───────────────────────────────────────────┤
│  Rules Details Table             │  Stacked bar timeline 24h                 │
│  Rule Id / Rule / Count          │  X = hour, Y = count, stacked by category │
│  Sortable, click row to filter   │  Đáy biểu đồ: 5 sparkline cells           │
└──────────────────────────────────┴───────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────────────────┐
│  Rules Details (full log table)                                              │
│  Time / Rule Id / Action / Rule / Ruleset / Rule Group / Description / Host  │
│  Server-side pagination, server filter, click row → drawer detail            │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 1.2. Data sources

| Section | Endpoint | Refresh |
|---|---|---|
| Donut "Total WAF Requests by Rule Group" | `/api/stats/overview` → `category_breakdown` | 10s |
| Donut "WAF Actions" | `/api/stats/overview` → `action_breakdown` | 10s |
| Top Blocked Request URIs (grid) | `/api/security-events?action=block&page=1&page_size=100` + group-by `path` client-side | 30s |
| Rules Details summary | `/api/stats/overview` → `top_rules` | 10s |
| Timeline stacked bars | `/api/stats/timeseries?hours=24` + một query phụ để lấy per-category — xem note dưới | 60s |
| Rules Details full table | `/api/security-events` (server pagination) | 10s (auto-refresh toggle) |

> **Timeline per-category:** `/api/stats/timeseries` hiện chỉ trả `{ts, total, blocked}`. Stacked timeline theo category cần dữ liệu mới — backend chưa có. **KHÔNG bịa endpoint.** Cách xử lý:
> 1. Bước 1: render Line chart 2 series `total` + `blocked` (giống TrafficChart) — đủ cho release đầu.
> 2. Đánh dấu trong code `// BACKEND-GAP: stacked-by-category timeline → cần /api/stats/timeseries-by-category` và mở TODO trong i18n key `dashboard.gapStackedTimeline` (hiển thị nhỏ phía dưới chart).

### 1.3. Charts — dùng đúng `@ant-design/plots` 2.6.8 đã có

| Chart | Component | Notes |
|---|---|---|
| Donut Rule Group | `Pie` với `innerRadius: 0.7` | Color map từ `categoryColors`. `statistic.title` ẩn, `statistic.content` show total. `onReady`: click slice → set filter `category` cho table phía dưới. |
| Donut Actions | `Pie` với `innerRadius: 0.7` | Color map từ `actionColors`. Click slice → set filter `action`. |
| Timeline | `Line` (smooth=false) | 2 series total/blocked như TrafficChart. KHÔNG dùng Column stack (vì 1.3 đã nói chưa có data per-category). |
| Top URIs tiles | Pure HTML/CSS grid 6 cols, không cần chart lib. Background gradient theo top count percentile. |
| Top Rules list | reuse `<TopList>` component có sẵn (giống Dashboard). |

### 1.4. Filters & state

State với `useState`:
```ts
interface AnalyticsFilters {
  hostCode?: string;
  timeRange: { hours: 1 | 6 | 24 | 168 };  // 1h / 6h / 24h / 7d
  category?: string;       // set bởi click donut Rule Group
  action?: string;         // set bởi click donut Actions
  ruleId?: string;         // set bởi click Top Rules row
  searchPath?: string;     // input filter Top URIs
}
```

Khi bất kỳ filter thay đổi → invalidate `security-events` query, KHÔNG invalidate stats (stats là global cho time range, không follow filter khác).

**Reset filter button** ở header (icon `ClearOutlined`) chỉ enabled khi `category || action || ruleId` truthy.

### 1.5. Top Blocked URIs grid (theo ảnh — 6 cols × 4-5 rows)

```ts
// Build từ security-events page_size=100, action=block:
const tiles = useMemo(() => {
  const byPath = new Map<string, number>();
  for (const ev of events) byPath.set(ev.path, (byPath.get(ev.path) ?? 0) + 1);
  return [...byPath.entries()]
    .map(([path, count]) => ({ path, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 30); // 6 cols × 5 rows
}, [events]);
```

Render:
- Grid `display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 8px;`.
- Mỗi tile là một `<button>` (a11y) với:
  - `path` truncate (tooltip hiện full).
  - Số count lớn bên dưới (e.g. `1.2k` qua `fmtNum`).
  - Background color = `categoryColors[deriveCategory(path)]` hoặc fallback gradient blue→purple theo rank percentile.
- Click tile → set `searchPath = tile.path` → filter table phía dưới.

### 1.6. Rules Details table (full)

- `useTable<SecurityEvent>` với `resource: "security-events"`, `pagination: { pageSize: 25, mode: "server" }`.
- Columns: `created_at`, `rule_id`, `action`, `rule_name`, `path`, `client_ip`, `host_code`, `country` (derive from `geo_info`).
  - `created_at`: `fmtDateTime` 12-hour format with seconds (`9/18/2025, 9:39:53 PM` style từ ảnh).
  - `action`: Tag color theo `actionColors`.
  - `rule_id`: mono font, click → filter ruleId state.
  - `path`: ellipsis, click row → mở Drawer detail (reuse phần "1.7 Drawer rule detail").
- Row click → navigate `/security-events/{id}` (route mới ở section 2).
- Auto-refresh toggle (Switch) tương tự `SecurityEventsPage`.

### 1.7. Mini drawer "Quick view" (optional ở dashboard, navigate cho full)

Trên click row trong Rules Details table:
- Mặc định mở Drawer width 480 với basic fields: `rule_id`, `rule_name`, `client_ip`, `country`, `path`, `method`, `detail`, `created_at`.
- Footer drawer có button "Open full detail →" navigate `/security-events/{id}`.

### 1.8. Export CSV

Button trong header. Khi click:
- Lấy data hiện tại của `useTable` (đã trả từ backend). KHÔNG fetch lại.
- Build CSV với header `created_at,host_code,client_ip,method,path,rule_id,rule_name,action,country`.
- Trigger download qua `Blob` + `URL.createObjectURL`. Filename: `security-events-${dayjs().format('YYYYMMDD-HHmm')}.csv`.
- Helper trong `src/utils/csv.ts` (tạo mới, pure function). Escape values chứa `,`, `"`, `\n`.

### 1.9. Time range selector

AntD `Segmented` với 4 options `1h | 6h | 24h | 7d`. State drive query `hours` cho `/api/stats/timeseries`. Stats overview KHÔNG có param hours — luôn lấy all-time, ghi note trong UI "Stats cumulative".

---

## 2. Trang chi tiết `/security-events/:id` — Security Event Detail

**File mới:** `web/admin-panel/src/pages/security-events/detail.tsx`

### 2.1. Endpoint

Backend route hiện chỉ có list `/api/security-events`. Detail single event:
- **Verify trong `crates/waf-api/src/server.rs`**: tìm `.route("/api/security-events/{id}"` — nếu **không có**, đánh dấu `// BACKEND-GAP: GET /api/security-events/{id} chưa có` và làm fallback:
  1. Bước 1 (fallback an toàn): `useCustom<{data: SecurityEvent[]}>({url: '/api/security-events', config: {query: {id}}, …})` — chấp nhận n+1 query model, hiển thị warning trong dev.
  2. Bước 2 (chính): khi endpoint detail có, dùng `useOne<SecurityEvent>({resource: 'security-events', id})`.
- KHÔNG tự gọi axios trực tiếp.

### 2.2. Layout

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  [← Back]  Security Event   <id mono>                                        │
│  Tag(action) Tag(category derived) Tag(severity if known)                    │
├──────────────────────────────────────────────────────────────────────────────┤
│  Descriptions card "Overview"  (2 cols)                                      │
│   • Time           • Host code                                               │
│   • Rule ID        • Rule name                                               │
│   • Action         • Category (derived)                                      │
│   • Method         • Path  [copy btn]                                        │
│   • Client IP [copy btn, link to lookup, link to add to blocklist]           │
│   • Country / ISP                                                            │
├──────────────────────────────────────────────────────────────────────────────┤
│  Detail card                                                                 │
│  Multi-line detail text (mono, wrap, copy btn)                               │
├─────────────────────────────────┬────────────────────────────────────────────┤
│  Geo card (nested table from    │  Related events card                       │
│  geo_info JSON object)          │  Top 10 events cùng client_ip trong 24h    │
│                                 │  Top 10 events cùng rule_id trong 24h      │
├─────────────────────────────────┴────────────────────────────────────────────┤
│  Raw JSON card (collapsible, mono pre, copy btn)                             │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 2.3. Components & detailed behaviour

- AntD `Descriptions` size="middle" bordered, 2 cột responsive.
- Mỗi field có icon (e.g. `ClockCircleOutlined` cho time, `GlobalOutlined` cho IP).
- Copy buttons: dùng `navigator.clipboard.writeText` + `message.success`.
- "Add to blocklist" button (chỉ hiện cho `action=block` và user có role admin — check qua existing auth store): mở Modal confirm → POST `/api/block-ips` với `{ip_cidr: client_ip + '/32', host_code, remarks: 'From event ' + id}`. Reuse refine `useCreate` resource `block-ips`.
- "View all events from IP" button → navigate `/security-events?client_ip=...`.
- "View all events for rule" button → navigate `/security-events?rule_id=...`.
- Related events:
  - 2 useCustom queries lấy 10 mới nhất:
    - same IP: `/api/security-events?client_ip={ip}&page_size=10`
    - same rule: `/api/security-events?rule_name={rule_name}&page_size=10`
    - **Lý do dùng `rule_name`:** backend `SecurityEventQuery` filter trên `rule_name` chứ KHÔNG có filter `rule_id` (verify in `repo.rs::list_security_events`).
  - Mini table 4 cột: time, ip (nếu same-rule), path, action.
- Raw JSON: `<pre>` với JSON pretty print, sử dụng `AntD Collapse` mặc định collapsed.
- Loading state: AntD `Skeleton active paragraph={{rows: 10}}`.
- Not found state: AntD `Result status="404"` + back button.

### 2.4. URL filter pre-population

Khi navigate `/security-events?client_ip=X&rule_id=Y`, page `/security-events` (đã tồn tại) phải đọc query string và pre-fill input. Sửa `src/pages/security-events/index.tsx`:
- Dùng `useSearchParams` từ `react-router`.
- `useEffect` khi mount: parse `client_ip`, `host_code`, `action`, `rule_name`, `rule_id` từ URL → setState + `setFilters` ngay.
- Khi user thay filter → cập nhật URL qua `setSearchParams` (để có deep-link share-able).
- **KHÔNG break behavior hiện tại** — chỉ thêm sync layer.

---

## 3. Routing & navigation

### 3.1. Resources (`src/App.tsx` hoặc nơi khai báo `<Refine resources>`)

Thêm resource:
```ts
{ name: "rule-analytics", list: "/rule-analytics", meta: { label: "Rule Analytics", icon: <BarChartOutlined /> } },
```

Thêm route cho detail page (refine 5 + react-router 7):
- `<Route path="/security-events/:id" element={<SecurityEventDetailPage />} />`
- Trong resource `security-events`: thêm `show: "/security-events/:id"`.

### 3.2. Sidebar nav

Trong i18n `nav` thêm key `ruleAnalytics`. Đặt entry này ở group "Security" cùng `securityEvents`, `customRules`, `ruleManager`.

---

## 4. Types — mở rộng `src/types/api.ts`

```ts
// Derive helper for category from rule_id — mirror waf-storage CASE expression
export const deriveCategory = (ruleId?: string | null): string => {
  if (!ruleId) return "other";
  const prefixMap: Array<[RegExp, string]> = [
    [/^SQLI-/, "sqli"], [/^XSS-/, "xss"], [/^RCE-/, "rce"],
    [/^TRAV-/, "path-traversal"], [/^SCAN-/, "scanner"],
    [/^BOT-/, "bot"], [/^CC-/, "cc-ddos"],
    [/^ADV-SSRF/, "ssrf"], [/^ADV-SSTI/, "ssti"], [/^ADV-/, "advanced"],
    [/^CRS-RESP/, "data-leakage"], [/^CRS-/, "owasp-crs"],
    [/^API-MASS/, "mass-assignment"], [/^API-/, "api-security"],
    [/^MODSEC-RESP/, "web-shell"], [/^MODSEC-/, "modsecurity"],
    [/^CVE-/, "cve"], [/^GEO-/, "geo-blocking"], [/^CUSTOM-/, "custom"],
    [/^IP-/, "ip-rule"], [/^URL-/, "url-rule"],
    [/^SENS-/, "sensitive-data"], [/^HOTLINK-/, "anti-hotlink"],
    [/^OWASP-942/, "sqli"], [/^OWASP-941/, "xss"],
    [/^OWASP-930/, "lfi"], [/^OWASP-931/, "rfi"],
    [/^OWASP-932/, "rce"], [/^OWASP-933/, "php-injection"],
    [/^OWASP-913/, "scanner"],
  ];
  for (const [re, cat] of prefixMap) if (re.test(ruleId)) return cat;
  return "other";
};

// Extend SecurityEvent với optional fields đầy đủ trả từ /api/security-events
export interface SecurityEvent {
  id: string;
  host_code: string;
  client_ip: string;
  method: string;
  path: string;
  rule_id: string | null;
  rule_name: string;
  action: string;
  detail: string | null;
  geo_info: {
    country?: string;
    province?: string;
    city?: string;
    isp?: string;
    iso_code?: string;
  } | null;
  created_at: string;
}
```

Verify `geo_info` shape ở `crates/waf-engine/src/engine.rs::log_security_event` — keys là `country, province, city, isp, iso_code`. KHÔNG bịa field khác.

---

## 5. Components mới có thể tách (nhỏ, reusable)

- `src/components/analytics/donut-card.tsx` — wrapper quanh `<Pie>` từ `@ant-design/plots` với KPI center, legend right, click handler. Props: `title`, `data: TopEntry[]`, `colors: Record<string,string>`, `onSliceClick?: (key: string) => void`, `activeKey?: string` (highlight slice đang filter).
- `src/components/analytics/uri-tiles.tsx` — grid render top URIs. Props: `items: {path: string; count: number}[]`, `onSelect: (path: string) => void`, `activePath?: string`.
- `src/components/analytics/time-range-segmented.tsx` — Segmented wrapper. Props: `value`, `onChange`, `options` cố định `[1h, 6h, 24h, 7d]`.

KHÔNG tạo thêm component khác. Tận dụng `KpiCard`, `TopList`, `CategoryBars`, `TrafficChart` đã có.

---

## 6. i18n keys mới (`src/i18n/locales/{en,vi}.json`)

```jsonc
{
  "nav": {
    "ruleAnalytics": "Rule Analytics" / "Phân tích Rule"
  },
  "analytics": {
    "title": "Rule Analytics" / "Phân tích Rule",
    "subtitle": "Attack distribution by rule group, action, and URI" / "Phân bố tấn công theo nhóm rule, action, URI",
    "byRuleGroup": "Total WAF Requests by Rule Group" / "Tổng request WAF theo nhóm rule",
    "byAction": "WAF Actions" / "Hành động WAF",
    "topBlockedUris": "Top Blocked Request URIs" / "URI bị chặn nhiều nhất",
    "topUrisHint": "Click a tile to filter the table below" / "Bấm ô để lọc bảng bên dưới",
    "rulesDetailsSummary": "Top Triggered Rules" / "Rule kích hoạt nhiều",
    "timeline24h": "Traffic timeline" / "Timeline lưu lượng",
    "rulesDetails": "Rules Details" / "Chi tiết Rules",
    "timeRange": "Time range" / "Khoảng thời gian",
    "filterByHost": "Host filter" / "Lọc host",
    "exportCsv": "Export CSV" / "Xuất CSV",
    "clearFilters": "Clear filters" / "Xoá bộ lọc",
    "gapStackedTimeline": "Per-category timeline requires a new backend endpoint" / "Timeline theo category cần endpoint backend mới",
    "selectToFilter": "select to filter" / "chọn để lọc",
    "noEvents": "No events in range" / "Không có sự kiện",
    "totalEvents": "Total events" / "Tổng sự kiện"
  },
  "eventDetail": {
    "title": "Security Event" / "Sự kiện bảo mật",
    "back": "Back" / "Quay lại",
    "overview": "Overview" / "Tổng quan",
    "detail": "Detail" / "Chi tiết",
    "geo": "Geo information" / "Thông tin địa lý",
    "related": "Related events" / "Sự kiện liên quan",
    "sameIp": "From same IP (last 24h)" / "Cùng IP (24h)",
    "sameRule": "Same rule (last 24h)" / "Cùng rule (24h)",
    "rawJson": "Raw JSON" / "JSON gốc",
    "copy": "Copy" / "Sao chép",
    "copied": "Copied" / "Đã sao chép",
    "viewAllFromIp": "View all events from this IP" / "Xem tất cả sự kiện từ IP này",
    "viewAllForRule": "View all events for this rule" / "Xem tất cả sự kiện cho rule này",
    "addToBlocklist": "Add IP to blocklist" / "Thêm IP vào blocklist",
    "addedToBlocklist": "IP added to blocklist" / "Đã thêm IP vào blocklist",
    "addToBlocklistConfirm": "Block all traffic from {{ip}}?" / "Chặn mọi truy cập từ {{ip}}?",
    "notFound": "Event not found" / "Không tìm thấy sự kiện",
    "loading": "Loading event..." / "Đang tải sự kiện..."
  }
}
```

Cập nhật cả 11 locale nếu repo có 11 file — copy en cho locale chưa dịch.

---

## 7. Constraints

- TypeScript strict, `tsc --noEmit` zero error, zero warning.
- **Không thêm dependency mới.** `@ant-design/plots` 2.6.8, `dayjs`, `antd` 5.22, `@refinedev/core` 5 — đã đủ.
- Refresh polling KHÔNG dồn dập: stats 10s, timeseries 60s, security-events list 10s khi auto-refresh on, 0 khi off.
- Không gọi `axios` trực tiếp trong page component — chỉ qua `useCustom` / `useTable` / `useOne` / `useCreate`.
- Mọi mutate có `onError` show `message.error` với backend error đầy đủ.
- Charts phải defensive với empty data — `<Empty>` placeholder thay vì để `@ant-design/plots` crash khi `data: []`.
- Path filter / search là client-side trên tiles, KHÔNG backend.
- Mọi navigate giữa pages dùng `useNavigate` từ `react-router`, không `window.location`.
- Donut `Pie` từ `@ant-design/plots` 2.x API: dùng `angleField`, `colorField`, `innerRadius`, `statistic.title.style`, `statistic.content.style`. Verify với version 2.6.8 — KHÔNG dùng API v1.
- Click slice donut: AntD plots 2.x dùng `onReady` callback với `event` listener: `chart.on('interval:click', e => ...)`. Reference code có sẵn trong `web/admin-panel/src/components/traffic-chart.tsx` nếu chart trả lỗi runtime.

---

## 8. Acceptance Criteria

Hoàn thành khi:

1. `pnpm type-check` exit 0, không warning.
2. `pnpm build` exit 0.
3. `/rule-analytics`: 2 donut hiển thị với data thật từ `/api/stats/overview`, click 1 slice → table phía dưới được filter, click "Clear filters" → reset.
4. `/rule-analytics`: timeline chart hiển thị 24h, đổi time range 7d → chart refetch với `hours=168`.
5. `/rule-analytics`: Top URIs grid 6×N, click 1 tile → table filter theo path đó.
6. `/rule-analytics`: Export CSV download file, mở Excel/LibreOffice không corrupt.
7. `/security-events/{valid-id}`: hiển thị đầy đủ overview, geo, related events. Copy IP → clipboard có IP. Click "View all events for this rule" → navigate `/security-events?rule_name=...` và filter pre-fill.
8. `/security-events/{invalid-id}`: hiển thị `Result 404`, không crash.
9. `/security-events` page hiện tại: navigate với `?client_ip=1.2.3.4` → input client IP pre-filled = `1.2.3.4`, filter applied tự động.
10. Toàn bộ keys i18n có cả en và vi.

---

## 9. Output format

Trả về theo thứ tự:

1. Liệt kê file sẽ tạo/sửa.
2. Diff hoặc full content cho từng file theo thứ tự: types → components/analytics/* → utils/csv → pages/rule-analytics → pages/security-events/detail → pages/security-events (sửa) → App routing → i18n.
3. Checklist 10 acceptance criteria với cách verify từng cái.

Không tóm tắt lan man. Đi thẳng code.
