---
feature: FR-041 Geo Restriction Dashboard
lane: normal
status: draft
priority: P1
date: 2026-06-30
owner: eli@matina.io
---

# FR-041 — Geo Restriction Dashboard (Implementation Plan for Cursor)

> Mục tiêu: nâng trang `geo-restriction` hiện tại từ một bảng CRUD đơn giản thành
> một **dashboard giám sát Geo Restriction chuyên nghiệp**, theo phong cách slide
> "Web Application Firewall Performance" (KPI strip, donut phân bố, bản đồ nguồn,
> bar top nguồn, timeline lưu lượng), **tái sử dụng tối đa** thành phần và API có sẵn.

---

## 0. Bối cảnh & quyết định kiến trúc (đọc trước khi code)

### 0.1 Spec
- `analysis/requirements.md:86` — **FR-041 / Security / Geographic Restriction (Medium)**:
  GeoIP (MaxMind lite DB), block/challenge các vùng tài phán bị hạn chế, phát hiện VPN geo bypass.

### 0.2 Stack frontend (đã có, KHÔNG thêm dependency trừ khi được duyệt)
- React 18 + **Refine** (`useCustom`, `useCustomMutation`) + **Ant Design v5**.
- Charts: **`@ant-design/plots` v2** (`Pie`, `Bar`, `Column`, `Area`, `Line`).
- i18n: **i18next** — 3 locale: `en.json`, `vi.json`, `zh.json` (namespace `geo.*` đã tồn tại tại `en.json:1063`).
- Component dùng lại: `components/kpi-card.tsx` (`KpiCard`), `components/top-list.tsx` (`TopList`),
  `components/category-bars.tsx` (`CategoryBars`, `actionColors`).

### 0.3 Backend đã có sẵn (KHÔNG cần sửa cho Option A)
| Endpoint | Method | Trả về (đã verify trong code) |
| --- | --- | --- |
| `/api/stats/geo` | GET | `{ top_countries:[{key,count}], top_cities:[{key,count}], top_isps:[{key,count}], country_distribution:[{iso_code,country,count}] }` — **all-time**, từ `security_events.geo_info` (`crates/waf-api/src/stats.rs:192`, SQL `crates/waf-storage/src/repo.rs:1523`) |
| `/api/geoip/rules` | GET / POST | list + tạo rule `{id,iso_code,country_name,action,scope,enabled,created_at}` (`crates/waf-api/src/geo_api.rs`) |
| `/api/geoip/rules/{id}` | PATCH / DELETE | toggle `enabled`/`action`/`scope` + xóa |
| `/api/geoip/lookup` | POST | **stub** (`iso_code:"XX"`) — chỉ trả thật khi đã nạp GeoIP xdb |
| `/api/stats/overview` | GET | có thêm `top_countries`, `top_isps`, `action_breakdown`, `recent_events[].country` |

### 0.4 Hai khoảng trống so với slide — quyết định rõ ràng (Simplicity First)
1. **Bản đồ thế giới (choropleth)**: `@ant-design/plots` v2 **không** ship world map.
   → **Quyết định:** Option A render "Source Map" bằng **treemap/ranked bar** từ `country_distribution`
   (không thêm dep). Choropleth thật là **Option C** (cần `@ant-design/maps`/L7 — phải được duyệt vì tăng bundle).
2. **Timeline theo geo** (panel "DDoS Protected Traffic" theo thời gian): backend **chưa** có
   chuỗi thời gian lọc theo country/geo.
   → **Quyết định:** Option A **không** vẽ timeline geo (chỉ dùng số liệu all-time). Timeline geo
   (blocked-by-country theo giờ) là **Option B** — cần thêm 1 endpoint backend (xem §4).

> **Khuyến nghị:** làm **Option A trước** (chỉ frontend, lane *normal*, không đụng public contract).
> Option B/C là tăng cường tùy chọn, đánh giá lại risk khi cần.

---

## 1. Phạm vi (Option A — chỉ frontend, không sửa backend)

Tái cấu trúc `web/admin-panel/src/pages/geo-restriction/index.tsx` thành **2 tab**:

- **Tab "Dashboard"** (mới): KPI strip + donut phân bố + ranked source map + top sources bar + top cities/ISPs.
- **Tab "Country Rules"** (giữ nguyên logic CRUD + IP Lookup hiện có, chỉ chuyển vào tab).

Không đổi route (`/geo-restriction`), không đổi đăng ký resource ở `App.tsx` (đã có sẵn dòng 58/106/183).

### Litmus (Surgical Changes)
- Toàn bộ code CRUD/lookup hiện tại được **di chuyển nguyên trạng** vào component `<RulesTab/>` — không refactor logic.
- Mọi file mới phải truy được về yêu cầu "dashboard chuyên nghiệp cho FR-041".

---

## 2. Cấu trúc file (Option A)

```
web/admin-panel/src/pages/geo-restriction/
├── index.tsx              # MODIFY: bọc <Tabs>, mount DashboardTab + RulesTab
├── dashboard-tab.tsx      # CREATE: dashboard mới (charts + KPI)
├── rules-tab.tsx          # CREATE: bê toàn bộ CRUD + Lookup + Drawer hiện tại sang đây
└── geo-shared.ts          # CREATE: COUNTRY_MAP, countryLabel(), ACTION_OPTIONS, types dùng chung
```

```
web/admin-panel/src/i18n/locales/
├── en.json   # MODIFY: bổ sung khóa geo.dashboard.* + geo.rules.*
├── vi.json   # MODIFY: cùng bộ khóa
└── zh.json   # MODIFY: cùng bộ khóa
```

---

## 3. Đặc tả chi tiết các thành phần (Cursor build theo đây)

### 3.1 `geo-shared.ts`
- Export `COUNTRY_MAP`, `countryLabel(iso, name?)`, `ACTION_OPTIONS` (đang nằm inline trong `index.tsx:54-99`).
- Export type: `GeoRule`, `LookupResult`, `GeoStat`, `AddForm` (đang ở `index.tsx:26-52`).
- Thêm type cho dashboard:
  ```ts
  export interface TopEntry { key: string; count: number; }
  export interface GeoDistEntry { iso_code: string; country: string; count: number; }
  export interface GeoStatsResponse {
    top_countries: TopEntry[];
    top_cities: TopEntry[];
    top_isps: TopEntry[];
    country_distribution: GeoDistEntry[];
  }
  ```

### 3.2 `rules-tab.tsx`
- Bê **nguyên** phần JSX + handler từ `index.tsx` hiện tại (bảng rules, filter action, Drawer "Add country",
  IP Lookup card, "Top Blocked Countries", KpiCard "Total rules").
- Import `COUNTRY_MAP/countryLabel/ACTION_OPTIONS/types` từ `geo-shared.ts` thay vì khai báo inline.
- **Không** đổi endpoint, không đổi logic — chỉ tách module. Giữ nguyên i18n key cũ.

### 3.3 `dashboard-tab.tsx` — layout & data binding

**Data fetch (Refine `useCustom`, đúng pattern repo):**
```ts
const geo = useCustom<GeoStatsResponse>({ url: "/api/stats/geo", method: "get",
  queryOptions: { staleTime: 60_000 }, errorNotification: false });
const rules = useCustom<GeoRule[]>({ url: "/api/geoip/rules", method: "get",
  queryOptions: { staleTime: 30_000 }, errorNotification: false });
```
> Lưu ý unwrap envelope: data thật nằm ở `result?.data?.data` (handler trả `{success,data:{...}}`).
> Tái dùng đúng helper unwrap đã có trong `index.tsx:132-146`.

**Layout (antd `Row`/`Col`, `gutter={[12,12]}`), từ trên xuống:**

1. **KPI strip** — 4 × `KpiCard` (`Col xs={24} sm={12} xl={6}`):
   | Card | Giá trị | Nguồn | icon / color |
   | --- | --- | --- | --- |
   | Active geo rules | `rules.filter(enabled).length` | rules | `GlobalOutlined` / blue |
   | Blocked countries | `rules.filter(r=>r.action==='block' && r.enabled).length` | rules | `StopOutlined` / red |
   | Geo-attributed events | `sum(top_countries.count)` | geo | `AlertOutlined` / orange |
   | Top source country | `countryLabel(country_distribution[0])` | geo | `EnvironmentOutlined` / purple |

2. **Hàng giữa** (2 cột):
   - `Col xs={24} lg={10}` — **Donut "Country Attack Distribution"** (`Pie`, `innerRadius:0.6`):
     dữ liệu = `country_distribution` top 6 + gộp phần còn lại thành `"Others"`. Tooltip = count, legend bên phải.
   - `Col xs={24} lg={14}` — **"Top Attack Source Countries"** (`Bar`, ngang): `top_countries.slice(0,10)`,
     `xField:'count'`, `yField:'key'`, label hiển thị số. (Khớp panel "Top Application Attack Source" của slide.)

3. **Hàng "Source Map"** — `Card` title "Application Security Events Source Map":
   - **Option A:** render `Treemap`/`Bar` từ `country_distribution.slice(0,20)` (mỗi ô = country, size = count).
     Hiển thị cờ qua `COUNTRY_MAP[iso].flag`. Ghi chú nhỏ: "Choropleth map cần GeoIP DB + L7 (Option C)".
   - Trạng thái rỗng: `Empty` khi `country_distribution.length===0`.

4. **Hàng cuối** (2 cột bằng nhau) — tái dùng `TopList`:
   - "Top Source Cities" ← `top_cities` (`Col lg={12}`).
   - "Top Source Networks (ISP)" ← `top_isps` (`Col lg={12}`).

**Chuẩn trạng thái (bắt buộc, theo pattern dashboard hiện có):**
- Mỗi `Card` truyền `loading={geo.query.isLoading}`.
- Khi `geo.query.isError`: `Alert type="warning"` "Geo stats unavailable" thay cho chart.
- Khi mảng rỗng: `Empty` của antd.
- KHÔNG dùng `Date.now()`/`Math.random()` trong render.

### 3.4 `index.tsx` (sau sửa)
```tsx
import { Tabs } from "antd";
import { DashboardTab } from "./dashboard-tab";
import { RulesTab } from "./rules-tab";
// header (title/subtitle) giữ nguyên, bên dưới:
<Tabs defaultActiveKey="dashboard" items={[
  { key: "dashboard", label: t("geo.tabs.dashboard"), children: <DashboardTab/> },
  { key: "rules",     label: t("geo.tabs.rules"),     children: <RulesTab/> },
]}/>
```

### 3.5 i18n (thêm vào CẢ 3 file `en/vi/zh`)
```jsonc
"geo": {
  // ... khóa cũ giữ nguyên ...
  "tabs": { "dashboard": "Dashboard", "rules": "Country Rules" },
  "dashboard": {
    "activeRules": "Active geo rules",
    "blockedCountries": "Blocked countries",
    "geoEvents": "Geo-attributed events",
    "topSource": "Top source country",
    "distribution": "Country Attack Distribution",
    "topSources": "Top Attack Source Countries",
    "sourceMap": "Application Security Events Source Map",
    "topCities": "Top Source Cities",
    "topIsps": "Top Source Networks (ISP)",
    "others": "Others",
    "mapHint": "Choropleth requires GeoIP DB + map layer (optional)"
  }
}
```
> `vi.json` dịch tiếng Việt, `zh.json` dịch tiếng Trung. Giữ nguyên mọi khóa `geo.*` hiện hữu.

---

## 4. Option B (tùy chọn — timeline geo, CẦN sửa backend)

> Chỉ làm khi muốn panel "lưu lượng theo thời gian phân theo country". **Tăng risk → lane normal+**
> (Public contracts: thêm endpoint mới; không đụng auth/data model).

- **Storage** (`crates/waf-storage/src/repo.rs`): thêm `get_geo_timeseries(hours, top_n)` —
  `security_events` group theo `date_trunc('hour', ts)` × `geo_info->>'iso_code'`, đếm `blocked`.
  Trả `Vec<{ ts, iso_code, country, blocked }>`. Tái dùng pattern `get_stats_timeseries_by_category`.
- **API** (`crates/waf-api/src/stats.rs` + đăng ký ở `crates/waf-api/src/server.rs` cạnh dòng `/api/stats/geo`):
  `GET /api/stats/geo/timeseries?hours=24` → `{ success, data:[...] }`.
- **Frontend**: thêm panel `Area` stacked (top 5 country) vào `dashboard-tab.tsx`.
- **Bắt buộc theo CLAUDE.md**: viết test storage + API trước (TDD), giữ shape `/api/stats/geo` cũ không đổi.

## 5. Option C (tùy chọn — bản đồ choropleth thật)
- Cần duyệt thêm dependency `@ant-design/maps` (L7) — đánh giá bundle size.
- Thay block "Source Map" Treemap bằng `Choropleth`, bind `country_distribution` qua `iso_code`.
- Nếu không duyệt → giữ Treemap của Option A.

---

## 6. Tiêu chí nghiệm thu (Goal-Driven)

**Option A (mặc định):**
- [ ] `/geo-restriction` hiển thị 2 tab; tab Rules hoạt động y hệt trước (CRUD + toggle + lookup không hồi quy).
- [ ] Tab Dashboard hiển thị: 4 KPI, donut phân bố, bar top sources, source-map (treemap), top cities + top ISPs.
- [ ] Tất cả số liệu lấy từ `/api/stats/geo` + `/api/geoip/rules`; **không thêm endpoint, không thêm dependency**.
- [ ] Loading / error / empty đều có trạng thái rõ ràng (Card `loading`, `Alert`, `Empty`).
- [ ] i18n đầy đủ ở `en/vi/zh`, không còn chuỗi hardcode mới.
- [ ] `cd web/admin-panel && npm run type-check` (tsc) **pass**, `npm run build` **pass**.
- [ ] Responsive: kiểm tra ở `xs` (mobile) và `xl` (desktop) — KPI strip wrap đúng.

**Verify thủ công:**
```bash
cd web/admin-panel && npm run dev   # mở /geo-restriction, đối chiếu 2 tab
npm run type-check && npm run build # gate trước khi commit
```

---

## 7. Ghi chú cho Cursor (chỉ dẫn sinh code)
1. Bắt đầu bằng `geo-shared.ts` (trích xuất hằng số/type) → rồi `rules-tab.tsx` (cut từ `index.tsx`) →
   rồi `dashboard-tab.tsx` (mới) → cuối cùng thu gọn `index.tsx` thành `<Tabs>`.
2. **Tái sử dụng** `KpiCard`, `TopList`, `actionColors`, helper unwrap envelope — không tự viết lại.
3. Tuân thủ CLAUDE.md: **không** thêm tính năng/abstraction ngoài yêu cầu; **không** sửa code lân cận;
   dọn import mồ côi do chính thay đổi này tạo ra.
4. Không vẽ timeline geo trong Option A (backend chưa có dữ liệu) — đừng bịa endpoint.
5. Mọi chuỗi hiển thị đi qua `t("geo.dashboard.*")`.
