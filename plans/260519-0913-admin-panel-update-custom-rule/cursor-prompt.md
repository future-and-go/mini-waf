# Cursor Prompt — PRX-WAF Admin Panel: Custom Rules & Rule Management Refactor

> **Scope:** sync `web/admin-panel` (React 18 + Refine 5 + Ant Design 5 + Vite 8) với backend WAF API
> **Khoảng commits:** `718045d` → `95648f6` (big update custom_rule + manage_rule).
> **Output:** TypeScript strict, không placeholder, không TODO, đầy đủ i18n (en + vi).

---

## 0. Context bắt buộc đọc trước khi sửa

1. `docs/custom-rules-syntax.md` — schema chuẩn cho `CustomRule` (DB-driven) và `match_tree`.
2. `crates/waf-engine/src/rules/engine.rs` — định nghĩa `CustomRule`, `Condition`, `ConditionNode` (And/Or/Not/Leaf), `Operator`, `ConditionField`, `RuleAction`, `MAX_TREE_DEPTH=16`, `MAX_TREE_LEAVES=256`.
3. `crates/waf-api/src/rules_api.rs` + `crates/waf-api/src/server.rs` — list endpoints hiện hành.
4. `crates/waf-storage/src/repo.rs` — `CreateCustomRule`, `list_custom_rules`, `create_custom_rule`, `set_custom_rule_enabled`, `delete_custom_rule`.
5. `crates/waf-common/src/panel_config.rs` + `crates/waf-api/src/panel_api.rs` — `GET/PUT /api/panel-config`.
6. `web/admin-panel/src/providers/data-provider.ts` — refine dataProvider, envelope unwrap rules.
7. `web/admin-panel/src/types/api.ts` — type definitions hiện tại (cần mở rộng).

---

## 1. Khe hở phải đóng

Hai phần UI dưới đây hiện **không khớp** với contract backend mới:

### A. `web/admin-panel/src/pages/custom-rules/index.tsx`
- Form chỉ hỗ trợ flat fields (`name`, `host_code`, `priority`, `action`, `enabled`, `script`) + `conditions: []` rỗng — **mất hoàn toàn** nested `match_tree` (FR-003 AC-8) và flat `conditions` builder.
- `CustomRule` type ở `types/api.ts` thiếu: `description`, `condition_op`, `conditions`, `match_tree`, `action_status`, `action_msg`, `created_at`, `updated_at`.
- Không có Edit/Update flow (chỉ Create + Delete). Backend cho phép toggle enabled qua `PATCH /api/custom-rules/{id}` (hoặc dedicated `/enabled` endpoint — kiểm tra `repo.rs::set_custom_rule_enabled`).
- Không validate trùng `id`, depth/leaves caps, regex compile, CIDR parse trước khi submit.

### B. `web/admin-panel/src/pages/rules-management/index.tsx`
- Drawer view rule không hiển thị `pattern`, `tags`, `file` (backend trả về trong `RuleEntry`).
- `RegistryResponse.total/enabled/disabled` backend trả KÈM `rules` ở root level (không phải trong `data`) — kiểm tra unwrap.
- Import dialog chỉ cho source path + format, chưa expose error chi tiết khi YAML invalid.
- Bulk enable/disable nhiều rule cùng lúc chưa có (UX cần thiết khi có hàng trăm rule).

### C. `web/admin-panel/src/pages/rule-sources/index.tsx`
- Form add source dùng key `source_type` mismatch với backend (backend dùng `type` — verify trong `RuleSourceEntry` của `waf-common::config`). Hoặc backend đã đổi sang `source_type`: align cả hai bên.
- `BUILTIN` array hard-coded count (15/31/19) — phải fetch động hoặc bỏ count, vì rule registry có thể đã thay đổi.

---

## 2. Yêu cầu cụ thể

### 2.1. Mở rộng `src/types/api.ts`

Thay thế `CustomRule` interface bằng schema đầy đủ + types phụ trợ. Phải dùng `import type` cho discriminated unions để Vite 8 + TypeScript 5.7 strict không lỗi.

```ts
// ── Operator catalog (mirror waf-engine::Operator serde rename_all="snake_case") ──
export type RuleOperator =
  | "eq" | "ne" | "contains" | "not_contains"
  | "starts_with" | "ends_with"
  | "regex" | "wildcard"
  | "in_list" | "not_in_list"
  | "cidr_match"
  | "gt" | "lt" | "gte" | "lte";

// ── Field catalog (mirror ConditionField, including newtypes) ──
export type SimpleField =
  | "ip" | "path" | "query" | "method" | "body"
  | "host" | "user_agent" | "content_type" | "content_length"
  | "geo_country" | "geo_iso" | "geo_province" | "geo_city" | "geo_isp";

// Newtypes: `{header: "x-foo"}` / `{cookie: "session"}` / `{cookie: null}` (legacy)
export type HeaderField = { header: string };
export type CookieField = { cookie: string | null };
export type ConditionField = SimpleField | HeaderField | CookieField;

export type ConditionValue = string | number | string[];

export interface Condition {
  field: ConditionField;
  operator: RuleOperator;
  value: ConditionValue;
}

// ── ConditionNode tree: untagged discriminated by key presence ──
export type ConditionNode =
  | { and: ConditionNode[] }
  | { or: ConditionNode[] }
  | { not: ConditionNode }
  | Condition; // bare leaf

export type ConditionOp = "and" | "or";
export type RuleAction = "block" | "allow" | "log" | "challenge";

export interface CustomRule {
  id: string;
  host_code: string;
  name: string;
  description?: string | null;
  priority: number;
  enabled: boolean;
  condition_op: ConditionOp;
  conditions: Condition[];        // legacy flat shape, may be []
  match_tree?: ConditionNode | null;
  action: RuleAction;
  action_status: number;
  action_msg?: string | null;
  script?: string | null;
  created_at?: string;
  updated_at?: string;
}

export interface CreateCustomRulePayload {
  host_code: string;
  name: string;
  description?: string | null;
  priority?: number;
  enabled?: boolean;
  condition_op?: ConditionOp;
  conditions?: Condition[];
  match_tree?: ConditionNode | null;
  action?: RuleAction;
  action_status?: number;
  action_msg?: string | null;
  script?: string | null;
}

// ── Tree bounds, must match engine.rs constants ──
export const MAX_TREE_DEPTH = 16;
export const MAX_TREE_LEAVES = 256;
```

Cập nhật `RegistryRule` thêm `file?: string`, `pattern?: string | null` đúng `RuleEntry` của backend.

### 2.2. Tách helpers vào `src/utils/conditionTree.ts`

Pure, no React, đầy đủ unit-testable helpers:

- `validateTree(node: ConditionNode): { ok: true } | { ok: false; error: string }` — đếm depth ≤ 16, leaves ≤ 256, return key i18n.
- `compileFieldLabel(f: ConditionField): string` — `"ip" → "ip"`, `{header:"x-foo"} → "header.x-foo"`, `{cookie:"session"} → "cookie.session"`, `{cookie:null} → "cookie"`.
- `parseFieldLabel(label: string): ConditionField` — đảo chiều, throw nếu vô lệ.
- `isLeaf | isAnd | isOr | isNot` — type guards.
- `cloneTree`, `replaceNodeAt(root, path, replacement)` — path là array index như `["and", 0, "or", 2]`.
- `validateLeaf(c: Condition)` — regex thử `new RegExp(value)`, CIDR thử regex tối thiểu (chính validate ở backend); chỉ catch lỗi syntax sơ cấp để UX tốt hơn, không thay thế backend validate.

### 2.3. Custom Rules page — rewrite `src/pages/custom-rules/index.tsx`

Tách thành 3 component:
- `CustomRulesPage` — list + action bar.
- `CustomRuleEditorDrawer` — Drawer width 720, mode `create | edit`, segmented "Visual | JSON".
- `ConditionTreeEditor` — recursive UI render `ConditionNode` với 3 mode: leaf, and-group, or-group, not-wrapper. Mỗi group có button "Add condition", "Add AND/OR group", "Wrap in NOT". Leaf có dropdown field (gồm cả `{header:"…"}`/`{cookie:"…"}` qua input phụ), dropdown operator (lọc theo field type — numeric ops chỉ hiện cho `content_length`/`gt|lt|gte|lte`), input value (string / list chips / number theo operator).

Các requirement:
- List dùng `useTable<CustomRule>({resource: "custom-rules"})` — đã có. Thêm filter theo `host_code`, `action`, `enabled`.
- Columns: name, host_code, priority, action (Tag color theo `actionColor`), `condition_op` mode (badge "tree" nếu `match_tree` truthy, else "flat" hoặc "script"), enabled Switch (gọi `PATCH /api/custom-rules/{id}` với `{enabled}` — kiểm tra method backend; nếu chưa có endpoint, dùng `useUpdate` từ refine với delete-create fallback và mở issue trong code comment).
- Action column: Edit (open drawer mode=edit), Duplicate (open drawer mode=create với pre-filled), Delete (Popconfirm).
- Drawer Save flow:
  1. `form.validateFields()` cho metadata (name required, priority integer ≥ 0, action enum).
  2. Nếu mode tree: chạy `validateTree`. Nếu fail, set `Form.Item` error trên tree editor.
  3. Nếu mode JSON: `JSON.parse` trong try/catch → set error vào textarea `Form.Item`. Validate kết quả là `ConditionNode` shape (basic shape check: phải có exactly 1 trong `and/or/not/field`).
  4. Build payload `CreateCustomRulePayload`: nếu có `match_tree` non-empty, gửi cả `match_tree` và `conditions: []`; ngược lại gửi `conditions[]` và bỏ `match_tree`. Nếu `script` non-empty thì gửi script, các nhánh khác coi như fallback.
  5. `useCreate` / `useUpdate` của refine với `resource: "custom-rules"`, `id` cho update.
  6. Trên success: `message.success(t("rules.saved"))`, close drawer, refetch table.
- Visual ↔ JSON switch: round-trip qua `JSON.stringify(getTreeFromForm(), null, 2)` và parse khi switch back. Nếu JSON invalid, disable switch và show warning.
- Hỗ trợ field newtype: khi user chọn field "header", show thêm Input cho `header.name`; khi chọn "cookie", show Input optional. Empty cookie input → gửi `{cookie: null}` (legacy).
- Operator value input:
  - `in_list` / `not_in_list` → AntD `Select mode="tags"` → ConditionValue thành `string[]`.
  - `gt`/`lt`/`gte`/`lte` → `InputNumber`, ConditionValue thành `number`.
  - `regex` → Input + nút "Test" mở popup nhỏ cho phép paste sample string, hiển thị match/no-match (use `new RegExp` an toàn trong try/catch).
  - `cidr_match` → Input + helper text "10.0.0.0/8 hoặc 2001:db8::/32".
  - `wildcard` → Input + helper text về `*` segment vs `**` cross-segment.
  - Còn lại: Input string.
- "Test rule" button trong drawer (optional, chỉ khi backend có endpoint dry-run): nếu chưa có, ẨN button thay vì hard-code `// TODO`.

### 2.4. Rules Management page — refactor `src/pages/rules-management/index.tsx`

- Drawer rule detail thêm `pattern`, `file` (path), `tags` (tag list), description full markdown plain.
- Filter status thêm "overridden" — rule có entry trong `rule_overrides`. Hiện chưa có flag trong response: yêu cầu backend bổ sung `overridden: boolean` HOẶC tính client-side bằng so sánh `enabled` với baseline (skip nếu khó, ghi comment trong code).
- Bulk actions:
  - Checkbox column (AntD `rowSelection`).
  - Action bar khi có selection: "Enable N", "Disable N", "Export selected (JSON)".
  - Bulk toggle: gọi `PATCH /api/rules/registry/{id}` tuần tự qua `Promise.all` chia chunk 10. Hiển thị Progress.
- Re-validate envelope shape: backend trả top-level `{rules, total, enabled, disabled}` chứ không wrap trong `{data: {rules: …}}`. Hiện `useCustom<RegistryResponse>` qua dataProvider sẽ unwrap `data` nếu có. Phải log + handle cả 2 shape:
  ```ts
  const payload = (result?.data as RegistryResponse | { data: RegistryResponse } | undefined);
  const normalized = payload && "rules" in payload ? payload : payload?.data;
  ```
- Import dialog: hiển thị backend error đầy đủ (backend trả `BadRequest: Invalid YAML: …`).

### 2.5. Rule Sources page — fix `src/pages/rule-sources/index.tsx`

- Field name `source_type` vs `type`: kiểm tra `crates/waf-common/src/config.rs::RuleSourceEntry` (current field tên `name/path/url/format/update_interval`, KHÔNG có `source_type` hay `type`). Backend nhận type qua endpoint riêng (?) — verify trong `crates/waf-api/src/server.rs` xem có route `/api/rule-sources` POST không; nếu chưa, đánh dấu phần này là "blocked: backend missing endpoint" và comment trong code, KHÔNG bịa endpoint.
- Bỏ hard-coded `BUILTIN` count. Thay bằng group rule registry theo `source` từ `/api/rules/registry` và đếm tại client. Show `loading skeleton` khi đang fetch.
- `lastUpdated` field: dùng `dayjs(lastUpdated).fromNow()` (cần install `dayjs/plugin/relativeTime` nếu chưa).

### 2.6. Settings page — `src/pages/settings/index.tsx`

Hiện đã khá đầy đủ. Chỉ verify:
- `WafPanelConfig` TS type khớp 1-1 với `crates/waf-common/src/panel_config.rs`: `shadow_mode`, `risk_allow`, `risk_challenge`, `risk_block`, `challenge_type`, `honeypot_paths`, `response_filtering.{block_stack_traces, json_redact_fields}`, `trusted_waf_bypass.cidrs`, `rate_limits.{default_rps, burst, session_expiry_secs, global_rps, request_timeout_secs, fail_open}`, `auto_block.{enabled, min_events, window_secs}`. Bổ sung field thiếu nếu có.
- Validation client-side: `risk_allow < risk_challenge < risk_block` — show error `t("settings.panel.riskOrderError")` BEFORE submit.
- `honeypot_paths`, `json_redact_fields`, `cidrs`: dùng `Select mode="tags"`. Validate CIDR sơ cấp (regex IPv4/v6 CIDR) trước submit.
- Discard button: gọi `panelQuery.query.refetch()` rồi reset form.
- File mtime conflict: nếu `envelope.revision` thay đổi giữa lúc user dirty form, hiển thị Alert "File changed externally" + button "Reload from disk".

### 2.7. Data provider — `src/providers/data-provider.ts`

- Thêm `useUpdate` (PATCH) support cho `custom-rules` (refine mặc định PATCH/PUT — verify implementation hiện tại có `update` method).
- Bảo đảm envelope unwrap đúng cho cả `/api/rules/registry` (top-level `rules` array, không trong `data`).

### 2.8. i18n — `src/i18n/locales/{en,vi}.json`

Thêm keys mới dưới `rules.*` và `customRules.*`:

```jsonc
{
  "rules": {
    "saved": "Saved" / "Đã lưu",
    "treeMode": "Tree" / "Cây",
    "flatMode": "Flat" / "Phẳng",
    "scriptMode": "Rhai" / "Rhai",
    "visualEditor": "Visual" / "Trực quan",
    "jsonEditor": "JSON" / "JSON",
    "addCondition": "Add condition" / "Thêm điều kiện",
    "addAndGroup": "Add AND group" / "Thêm nhóm AND",
    "addOrGroup": "Add OR group" / "Thêm nhóm OR",
    "wrapNot": "Wrap NOT" / "Bọc NOT",
    "removeNode": "Remove" / "Xoá",
    "treeDepthExceeded": "Tree depth exceeds {{max}}" / "Cây vượt độ sâu {{max}}",
    "treeLeavesExceeded": "Tree exceeds {{max}} leaves" / "Cây vượt {{max}} lá",
    "invalidRegex": "Invalid regex pattern" / "Regex không hợp lệ",
    "invalidCidr": "Invalid CIDR" / "CIDR không hợp lệ",
    "invalidJson": "Invalid JSON" / "JSON không hợp lệ",
    "fieldHeader": "Header name" / "Tên header",
    "fieldCookie": "Cookie name (empty = full header)" / "Tên cookie (trống = cả header)",
    "testRegex": "Test regex" / "Thử regex",
    "regexSample": "Sample string" / "Chuỗi mẫu",
    "regexMatch": "Matched" / "Khớp",
    "regexNoMatch": "No match" / "Không khớp",
    "duplicate": "Duplicate" / "Sao chép",
    "bulkEnable": "Enable selected" / "Bật đã chọn",
    "bulkDisable": "Disable selected" / "Tắt đã chọn",
    "bulkExport": "Export selected" / "Xuất đã chọn",
    "actionStatus": "Action status" / "Mã trạng thái",
    "actionMessage": "Action message" / "Thông điệp"
  }
}
```

Cập nhật cả 11 locale nếu repo đã có 11 file — copy giá trị en cho các locale chưa dịch.

### 2.9. Routing / resources — `src/App.tsx` hoặc nơi khai báo Refine `<Refine resources>`

Đảm bảo `custom-rules` resource có actions: `list`, `create`, `edit`, `clone`. Path `/custom-rules`, `/custom-rules/create`, `/custom-rules/edit/:id`.

---

## 3. Constraints

- **TypeScript strict**: `tsc --noEmit` phải pass. Không `any`, không `as any`. Dùng `unknown` + narrowing.
- **Không thêm dependency mới.** Chỉ dùng những gì có trong `package.json` đã cung cấp.
- **Không tạo file mock**, không tạo `MockData`, không hard-code fake response.
- **Mỗi tool call backend thông qua `useCustom` / `useCustomMutation` / `useTable` / `useCreate` / `useUpdate` / `useDelete` của `@refinedev/core`.** Không gọi `axios` trực tiếp trong page component — đã có httpClient trong data provider.
- **Error path:** mọi mutate có `onError` show `message.error` với backend error đầy đủ. Không nuốt lỗi.
- **A11y**: Drawer có `aria-label`, các button có tooltip nếu chỉ là icon.
- **Style**: theo `web/admin-panel` hiện tại — AntD components, không CSS module, không styled-components. Inline `style={{}}` cho spacing nhỏ.
- **Không sửa Rust code** trong scope này; nếu backend thiếu endpoint (vd. PATCH custom-rules toggle, dry-run test), comment `// BACKEND-GAP: …` và disable UI control thay vì gọi endpoint không tồn tại.

---

## 4. Acceptance Criteria

Hoàn thành khi tất cả các điểm sau pass:

1. `pnpm type-check` (tức `tsc --noEmit`) exit code 0, không warning.
2. `pnpm build` exit code 0.
3. Tạo custom rule với `match_tree` `(ip in 10.0.0.0/8 OR cookie session=bad) AND path~/api/*/admin` qua Visual editor → switch sang JSON editor → JSON đúng schema FR-003 AC-8 → save thành công → reload page → load lại thấy đúng tree.
4. Tạo custom rule depth = 17 → UI báo lỗi `treeDepthExceeded` trước khi submit, không gọi API.
5. Toggle enabled trên Rules Management page persist qua reload (verify `rule_overrides` table).
6. Import YAML invalid → message hiển thị lỗi YAML cụ thể từ backend, không generic "OK"/"error".
7. Settings page: nhập `risk_allow=80, risk_challenge=70` → save fail với i18n error `riskOrderError`, không gọi API.
8. Tất cả page không có console.error/warning trong dev mode.

---

## 5. Output format yêu cầu

Trả về theo thứ tự:

1. Liệt kê các file sẽ sửa/tạo.
2. Diff hoặc full content cho từng file, theo thứ tự dependency (types → utils → components → pages → i18n → router).
3. Cuối cùng: checklist 8 acceptance criteria, đánh dấu cách kiểm tra từng cái.

Không tóm tắt lan man. Không "đây là bản tóm tắt". Đi thẳng vào code.
