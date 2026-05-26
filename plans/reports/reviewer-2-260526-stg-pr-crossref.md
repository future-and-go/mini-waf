---
report: reviewer-2-stg-pr-crossref
date: 2026-05-26
author: reviewer-2
team: stg-issue-triage-260526
target_branch: release/stg
scope: 4 open PRs vs 22 open issues
---

# Reviewer 2 — Cross-ref 4 open PRs vs 22 open issues (release/stg)

## TL;DR

| PR | Title | Author | LOC | Mergeable | CI | Issue link | Verdict cho release/stg |
|---|---|---|---|---|---|---|---|
| #62 | audit backend gap layer | lotusdubai | +5078/-8 | **CONFLICTING** | green | #60 (parent) | **Superseded** — supersede bởi PR-A/B/C/D split (PR #105 = PR-A). Close after split lands |
| #98 | native TLS phase 01+02 | lotusdubai | +4515/-72 | **CONFLICTING** | 12/13 green, `Coverage (waf-engine)` FAILED | #95 | **Hold** — fix waf-engine coverage + rebase, then ship; phases 03-06 follow-up |
| #105 | audit-emitter core (PR-A split) | lotusdubai | +1748/-7 | MERGEABLE | **5+ FAILED** (Lint + 6 Coverage jobs) | #60 (PR-A of 4) | **Block** — DRAFT, CI red. Fix lint + integration tests before leave draft |
| #106 | Bugs/fix proxy waf | **protonmns** (external) | +219/-40 (body trống) | **CONFLICTING** | 11/13, **Test FAILED**, `Coverage (waf-storage)` FAILED | none claimed | **High-risk** — external contributor, empty body, migration filename clash với #98 host_http_redirect, 8x "fix lint" commits |

**release/stg state:** `origin/release/stg` đồng bộ 100% với `origin/main` (zero divergence both ways). Mọi cherry-pick base trên `main`.

---

## 1. PR-to-Issue map (chi tiết)

### PR #62 — audit backend gap (5078 LOC)
- **Issue link:** body khẳng định "Closes #60". Cover 5 sub-issues #2,#3,#4,#5,#6 trong meta-issue #60.
- **Sub-coverage:** relay (#2), tx_velocity (#3), risk-distribution (#4 partial), honeypot (#5 scaffolding only — không live), reputation (#6).
- **State:** OPEN, 0 reviews, 8 ngày stale. Plan `plans/260524-1327-pr-62-split-audit-emitter-ship/plan.md` chính thức tách thành 4 PR (PR-A/B/C/D). PR #105 = PR-A đầu tiên trong split.
- **Action:** close sau khi 4 PR split land. Không cherry-pick vào stg dưới dạng monolith.

### PR #98 — native TLS (4515 LOC)
- **Issue link:** "Refs #95". Body confirm ship phase 01+02; phases 03-06 (ACME, hardening, UI, audit/metrics) là follow-up.
- **Single issue:** #95 enhancement(ssl) — hoàn thành kiến trúc SSL/TLS gốc.
- **CI red point:** `Coverage (waf-engine)` job FAILED (lúc 2026-05-22) trên main rebase tươi. Lint/Test/Build/all-other-Coverage SUCCESS.
- **Action:** hold cho tới khi (a) `Coverage (waf-engine)` xanh, (b) CONFLICTING resolved sau rebase, (c) phase 03 ACME wire-up land hoặc decide ship phased — cử reviewer dedicated.

### PR #105 — audit-emitter core PR-A (1748 LOC, **DRAFT**)
- **Issue link:** "Refs #60. Supersedes #62."
- **PR-A scope only:** core module + intel_status skeleton; relay (PR-B), tx_velocity (PR-C), admin API (PR-D) là PR riêng tiếp theo.
- **CI red point:** Lint FAILED + 6 Coverage jobs FAILED (lúc 2026-05-24). Tests/Build SKIPPED due to Lint gate.
- **Outstanding (per body):** integration tests `tests/audit_emitter_unit.rs`, cardinality tests, testcontainers smoke, Docker rocky9 build, coverage ≥ 90%.
- **Action:** wait for author leave draft + CI green. Sau đó tuần tự PR-B/C/D theo plan.

### PR #106 — "Bugs/fix proxy waf" (219 LOC visible diff, **EXTERNAL author**)
- **Issue link:** body **trống**, không "Closes #". Reviews/comments = 0.
- **Scope inferred từ diff:**
  1. `prx-waf/main.rs` + `waf-api/handlers.rs`: add `preserve_host` field qua HostConfig (mới).
  2. `victoria_logs/sidecar.rs` (+86/-27): rewrite supervisor → auto-restart với exponential backoff, max 5 attempts. Major behavioral change.
  3. `waf-engine/logging/batch_buffer.rs` (+48/-8): tcp_keepalive + pool_idle_timeout + `post_with_retry()` one-shot retry trên connect/request errors.
  4. `migrations/0016_host_preserve_host.sql` (NEW): add `preserve_host` column.
  5. UI: `web/admin-panel/src/pages/hosts/index.tsx` add UI cho preserve_host + i18n keys (en/vi/zh).
  6. `docker-compose.yml` (+26): add new services (cần inspect).
  7. Test fixtures update (5 test files).
- **Possible issue alignment:**
  - Sidecar auto-restart → loose match với production-readiness (không issue cụ thể).
  - `preserve_host` field → enhancement, không match issue đang open.
  - victoria_logs reliability → operational concern, không match bug issue.
- **High-risk callout:**
  - External contributor (lotusdubai = owner; protonmns = NEW; chưa thấy commit trước trong repo).
  - PR body **trống** → không có context cho reviewer.
  - 8 commits với title "Fix lint" / "fix lint" / "Fix lint" — không squash, không conventional commit format (vi phạm CLAUDE.md).
  - Migration filename clash: PR #106 thêm `migrations/0016_host_preserve_host.sql`; PR #98 đụng `migrations/0016_host_http_redirect.sql` — **CÙNG prefix `0016_`**, conflict guaranteed nếu cả 2 land.
  - Test FAILED + Coverage (waf-storage) FAILED.

---

## 2. File overlap matrix

Cols = main areas của các PR; rows = PRs.

| PR \ Area | `gateway/src/ssl/*` | `gateway/src/proxy.rs` | `prx-waf/main.rs` | `waf-api/handlers.rs` | `waf-api/state.rs` | `waf-api/server.rs` | `waf-engine/audit_emitter/*` | `waf-engine/risk/*` | `waf-engine/logging/batch_buffer.rs` | `waf-engine/checks/tx_velocity/*` | `waf-engine/relay/*` | `waf-engine/engine.rs` | `waf-engine/lib.rs` | `waf-storage/db.rs` | `waf-storage/repo.rs` | `waf-storage/models.rs` | `prx-waf/victoria_logs/sidecar.rs` | `migrations/0016_*` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| #62 | — | ✓ (+55) | ✓ (+54) | — | ✓ (+18) | ✓ (+7) | ✓ NEW | ✓ (canary, scorer +220) | — | ✓ (audit_map +125) | ✓ (audit_map, intel +538) | ✓ (+22) | ✓ (+1) | ✓ (+31) | ✓ (+53) | — | — | — |
| #98 | ✓ NEW (322 LOC) | — | ✓ (+96) | — | ✓ (+6) | ✓ (+3) | — | — | — | — | — | — | — | — | — | — | — | — |
| #105 | — | — | — | — | — | — | ✓ NEW (1577 LOC) | — | — | — | — | ✓ (+41) | ✓ (+2) | ✓ (+1) | — | — | — | — |
| #106 | — | — | ✓ (+1) | ✓ (+2) | — | — | — | — | ✓ (+48) | — | — | — | — | — | ✓ (+7) | ✓ (+11) | ✓ MAJOR (+86) | ✓ NEW `0016_host_preserve_host` |

### Hard conflicts (cùng file, overlapping lines)
1. **#62 ↔ #105** — cả hai add `audit_emitter/*` (same files), `engine.rs` set_audit_emitter, `waf-storage/db.rs` broadcast_event visibility. **PR #62 superseded**, sẽ close — không phải conflict thực, chỉ là duplicate-by-design.
2. **#62 ↔ #98** — `waf-api/state.rs`, `waf-api/server.rs`. Cả hai add field/route → text-conflict trong route registration block, dễ resolve.
3. **#62 ↔ #106** — `crates/prx-waf/src/main.rs` (cả 2 modify init/host config) + `waf-storage/repo.rs` + `waf-storage/models.rs`. **Likely conflict** trên struct `HostConfig` (62 không add field, 106 add `preserve_host`).
4. **#98 ↔ #106** — migration cùng prefix `0016_*` → name clash, migration ordering breakage.
5. **#105 ↔ #106** — no direct file overlap. ✅ safe parallel.
6. **#98 ↔ #105** — no direct file overlap. ✅ safe parallel.

### Mềm conflicts (cùng module, separate functions)
- #62 và #106 đều touch `waf-storage/repo.rs` (62: +53, 106: +7). Likely different functions; verify khi merge.
- #98 và #62 đều thêm field vào `AppState` — coordinate field add order.

---

## 3. Conflict matrix với reviewer-1's fix candidate

**Status:** Reviewer-1 publish `plans/reports/reviewer-1-260526-stg-issue-fix-picker.md` — **pick = Issue #77** (SSRF IPv4-compatible IPv6 bypass).

### Concrete conflict check cho R1 pick (#77)
- **Touched files:**
  - `crates/waf-common/src/url_validator.rs:175-211` (add IPv4-compatible IPv6 helper)
  - `crates/waf-engine/src/checks/ssrf_scanners.rs:118-150` (add fallback song song với `to_ipv4_mapped()`)
- **Overlap với 4 PRs:**
  - PR #62 (audit) — **NONE.** Không touch `waf-common/` hay `waf-engine/src/checks/ssrf_scanners.rs`.
  - PR #98 (TLS) — **NONE.** Touch `waf-common/src/config.rs` (khác file), không `url_validator.rs`.
  - PR #105 (audit core) — **NONE.** Chỉ touch `audit_emitter/` + `engine.rs` + `intel_status.rs`.
  - PR #106 (protonmns) — **NONE.** Không touch `waf-common/` hay `ssrf_scanners.rs`.
- **Verdict:** ✅ **Zero conflict.** Fix #77 cherry-pick vào stg an toàn, parallel-safe với cả 4 PRs. Có thể land ngay không cần đợi PR nào.

### Pre-emptive analysis cho 21 issues còn lại (nếu lead muốn pick khác)

| Issue # | Likely fix scope | Conflict với 4 PRs? |
|---|---|---|
| #104 cache write-side (Set-Cookie/Cache-Control) | `gateway/src/proxy.rs` cache layer | **Soft conflict #62** (cùng `proxy.rs:432`-ish anchor) |
| #95 native TLS | covered by #98 (cùng issue) | — pick this = skip new fix, push #98 instead |
| #87 HostRouter case-fold Host header DoS | `gateway/src/router.rs` (probably) | **None** unless #106 router changes (verify) |
| #86 MemoryIdentityStore O(N) per request | `gateway/src/.../identity_store.rs` | **None** |
| #85 charset-blind body/header scanners | `waf-engine/src/checks/*` | **Soft conflict #105** (checks dir untouched by 105 actually) |
| #84 device_fp ConnCtx H2 frames cap | `gateway/src/.../device_fp/*` | **None** |
| #83 PendingForwards leak | `gateway/src/.../pending_forwards.rs` | **None** |
| #82 version-regression guard | likely cluster/storage | **None** |
| #81 unauthenticated lz4 snapshot 4GB bomb | `waf-cluster/src/worker.rs` | **None** |
| #80 heartbeat frozen snapshot | `waf-cluster/src/heartbeat.rs` | **None** |
| #79 rule reload partial state | `waf-engine/src/rules/hot_reload.rs` | **Hard conflict #62, #105** (cả 2 đang delete & rewrite `rules/hot_reload.rs`) |
| #78 WASM MAX_MEMORY_BYTES not enforced | `waf-engine/src/plugins/wasm/*` | **None** |
| #77 SSRF IPv6 bypass | `gateway/src/.../ssrf_guard.rs` | **None** |
| #76 single-node bootstrap split-brain | cluster | **None** |
| #75 cluster main never steps down | cluster | **None** |
| #74 follow-up cleanup (WS DoS, XFF, heatmap) | multiple | medium risk |
| #73 custom rule Regex per-request DoS | `waf-engine/src/rules/.../regex.rs` | **Hard conflict #62, #105** (rules/ being rewritten) |
| #72 cert upload no PEM validate | `waf-api/src/cert_upload.rs` | **Soft conflict #98** (cert subsystem) |
| #71 WASM plugin no size/MIME limit | `waf-api/src/.../wasm_upload.rs` | **Soft conflict #106** (waf-api/handlers.rs) |
| #70 cluster join token unused | cluster | **None** |
| #60 admin panel FR coverage meta | FE work — không touch backend | — meta issue, skip |
| #43 security logs rule_name display | `web/admin-panel/src/pages/security-events/*` | **None** (FE only) |

**Safest fix candidates cho release/stg** (low conflict + isolated):
- #87 case-fold DoS
- #86 O(N) MemoryIdentityStore
- #84 H2 frames cap
- #83 PendingForwards leak
- #76/#75/#80 cluster quorum bugs (separate crate)
- #77 SSRF IPv6
- #78 WASM memory not enforced
- #70 cluster join token

**Avoid pick** (conflict với in-flight PRs):
- #79, #73 — cùng touch `waf-engine/src/rules/*` đang refactor bởi #62/#105
- #95 — already in flight (#98)

---

## 4. Integration sequence cho release/stg

### Constraint analysis
- release/stg = main mirror. Cherry-pick base = main HEAD.
- Mọi PR đều CONFLICTING vs main → buộc author rebase trước khi merge.
- Không merge trực tiếp vào stg; flow chuẩn = merge vào main, cherry-pick vào stg.

### Recommended sequence (ascending risk + dependency-aware)

**Stage 1 — Foundation (low-risk, can land first):**
1. **Reviewer-1's selected fix** (TBD — chọn từ "safe list" trên). Cherry-pick vào stg ngay khi merged main.

**Stage 2 — Audit emitter cascade (sequential):**
2. PR #105 (PR-A core) → wait cho rời draft + CI green + reviewer approval.
3. PR-B (relay wiring, chưa tạo) → blocked by PR-A merged.
4. PR-C (tx_velocity wiring, chưa tạo) → parallel với PR-B.
5. PR-D (admin API, chưa tạo) → parallel với PR-B/C.
6. **Close PR #62** sau khi PR-A/B/C/D đã merged (mark as superseded).

**Stage 3 — TLS:**
7. PR #98 → wait fix `Coverage (waf-engine)` + rebase. Ship phase 01+02 standalone OK. Lưu ý: TLS listener fail-safe (chỉ bind khi có host opt-in `tls_terminate=true`), nên không gây regression nếu zero host configured.

**Stage 4 — External PR review:**
8. PR #106 → **chặn đến khi**:
   - Author fill body, mô tả issue/motivation.
   - Squash 8 "fix lint" commits → 1-3 logical commits.
   - Fix CI Test + Coverage (waf-storage).
   - Resolve migration `0016_*` clash (rename → `0017_host_preserve_host`).
   - Resolve `HostConfig` field conflict với PR #62/PR-D (coordinate add order với owner).
   - **External code review required** — không cherry-pick mà không có ≥1 approving review từ codeowner.

### Risk-ordered ship order if all gates passed
```
stg ← reviewer-1-fix (cheap, isolated)
stg ← #105 (PR-A) → stg ← PR-B → stg ← PR-C → stg ← PR-D
stg ← #98 (phase 01+02)
stg ← #106 (last, after full review)
```

---

## 5. Risk callouts

### High-risk #1: PR #106 external contributor
- Author `protonmns` chưa thấy commit prior trong repo (verify with `gh api repos/future-and-go/mini-waf/commits?author=protonmns` if cần).
- PR body trống vi phạm CLAUDE.md commit/PR style.
- 8 "fix lint" commits cho thấy không local-test trước push.
- victoria_logs sidecar rewrite supervisor — **behavioral change ảnh hưởng prod observability**. Auto-restart loop có thể amplify resource consumption nếu VictoriaLogs binary thực sự broken (5 lần × exponential backoff = 62s total trước khi give up, mỗi attempt spawn child process).
- Migration filename clash với #98.
- batch_buffer `post_with_retry` retry-once trên `is_connect() || is_request()` — okay logic, nhưng `body.clone()` cho mỗi retry = memory blow-up nếu batch lớn (hundreds of KB JSON).

### High-risk #2: Migration ordering `0016_*` collision — **CONFIRMED**
- `main` HEAD đã có `migrations/0016_host_http_redirect.sql` (verified `ls migrations/`).
- PR #106 add `migrations/0016_host_preserve_host.sql` — **HARD COLLISION** trên prefix.
- Author phải rename → `0017_host_preserve_host.sql` trước khi cherry-pick. Nếu cả 2 cùng sequence prefix → sqlx/migrate panic hoặc apply theo lexical order không xác định.
- #98 không add migration (cert subsystem dùng existing `certificates` table).

### High-risk #3: PR #62 vs PR #105 same audit_emitter scope
- Cả 2 active OPEN. Owner duy nhất = lotusdubai → biết về split. Nhưng PR #62 chưa close → reviewer thấy duplicate.
- **Action:** team-lead nudge owner close #62 hoặc convert thành "tracking issue" sau khi PR-A merged.

### Medium-risk: rules/ massive refactor trong #62/#105
- Cả 2 PR đang **delete** `data_file_registry.rs`, `data_file_resolver.rs`, `load_status.rs`, `metrics.rs`, multiple test files (pm_from_file_pinning, pm_matcher_regression_matrix, rule_load_status_failure, sqli_xss_behavior_snapshot). Tổng -2000+ LOC trong rules subdir.
- Đây không phải part của issue #60 scope (audit emitter) — likely artifact của rebase-on-stale-main. **Verify** với owner trước merge.
- Sẽ tạo hard conflict cho mọi fix touch `waf-engine/src/rules/*` (e.g., #73 Regex DoS, #79 rule reload partial state).

### Medium-risk: PR #98 listener fail-safe
- TLS listener chỉ bind khi có host opt-in. Nếu deploy stg với zero `tls_terminate=true` host → no-op, an toàn.
- Nhưng nếu operator quên opt-in mà mong TLS native → silent breakage. Document trong release notes.

---

## 6. Open questions

1. ~~Reviewer-1 final pick~~ **RESOLVED:** R1 pick = #77. Zero conflict với 4 PRs (mục 3 verified).
2. **PR #106 author identity:** `protonmns` lần đầu xuất hiện? Nếu có prior trust history (e.g., team member khác account) thì giảm risk weight. Cần lead xác nhận.
3. **Rules/ deletions trong PR #62/#105:** intentional cleanup hay rebase artifact? Nếu artifact → owner phải rebase fresh on main; nếu intentional → đây là scope creep không document.
4. **Phase 03-06 cho PR #98:** owner kế hoạch ship trong 1 PR hay split? Plan `plans/260522-1551-native-tls-cert-resolver-implementation/` có 6 phases.
5. **Release/stg merge policy:** team có dùng cherry-pick từ main → stg, hay merge PR trực tiếp vào stg? Recommendation hiện tại assume cherry-pick (an toàn hơn).
6. **PR #62 close criteria:** chỉ close sau khi PR-A/B/C/D đều merged, hay close ngay khi PR-A merged + tracking issue mở cho B/C/D?
7. **Coverage gate cứng 90% (per BP8)** áp dụng cho cả stg hay chỉ main?

---

**Reports references:**
- Brainstorm PR #62 split: `plans/reports/brainstorm-260524-pr62-split-strategy.md`
- PR #62 split plan: `plans/260524-1327-pr-62-split-audit-emitter-ship/plan.md`
- Issue audit synthesis: `plans/reports/issue-audit-synthesis-260524.md`
- TLS plan: `plans/260522-1551-native-tls-cert-resolver-implementation/plan.md`
