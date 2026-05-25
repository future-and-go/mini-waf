# Issue Audit Synthesis — 2026-05-24

Branch: `main` @ `61a75e6b`. 30 issues open trước audit.
Team: `mini-waf-issue-audit` (4 researchers parallel).
Source reports:
- `researcher-r1-260524-critical-audit.md` (#70, #75, #76, #77, #78)
- `researcher-r2-260524-distribution-audit.md` (#79–#82)
- `researcher-r3-260524-dos-memory-audit.md` (#83–#88)
- `researcher-r4-260524-validation-older.md` (#71–#74, #95, #60, #57, #47, #43, #20, #13, #11, #9, #8, #7)

## Tổng kết verdict

| # | Severity | Verdict | Hành động đề xuất |
|---|----------|---------|-------------------|
| 70 | Critical | VALID | Comment xác nhận + giữ open |
| 75 | Critical | VALID | Comment xác nhận + giữ open |
| 76 | Critical | VALID | Comment xác nhận + giữ open |
| 77 | Critical | VALID (+OPEN_GAP: bypass rộng hơn — `[::127.0.0.1]`, `[::100.100.100.200]`) | Comment ghi nhận GAP + giữ open |
| 78 | Critical | VALID | Comment xác nhận + giữ open |
| 79 | High | VALID | Comment xác nhận + giữ open |
| 80 | High | VALID | Comment xác nhận + giữ open |
| 81 | High | VALID (+OPEN_GAP: `decompress_snapshot` public fn cùng flaw) | Comment ghi nhận GAP + giữ open |
| 82 | High | VALID (+OPEN_GAP: `ConfigSyncer::apply_sync` cùng pattern) | Comment ghi nhận GAP + giữ open |
| 83 | High | VALID | Comment xác nhận + giữ open |
| 84 | High | VALID (latent — H2FrameTap chưa wired vào gateway, severity downgrade tới khi wire) | Comment cập nhật + giữ open |
| 85 | High | VALID | Comment xác nhận + giữ open |
| 86 | High | VALID | Comment xác nhận + giữ open |
| 87 | High | VALID — commit `331efc43` **KHÔNG fix** case-fold (chỉ thêm authority fallback) | Comment đính chính + giữ open |
| 88 | High | **FALSE_ALARM** as written — read-side guard tại `proxy.rs:664-694` chặn cả pipeline khi request có Authorization/Cookie. Scenario "user A authenticated → cache → user B" không reach. | Comment giải thích false-alarm + đề xuất re-scope response-side (`Set-Cookie` response, `Cache-Control: private`) → **đóng issue cũ, mở issue mới** nếu user đồng ý |
| 71 | High | VALID | Comment + giữ open |
| 72 | High | VALID | Comment + giữ open |
| 73 | High | VALID | Comment + giữ open |
| 74 | Medium | VALID overall (5/7 sub-items valid, sub-item 4 partial-mitigated) | Comment cập nhật sub-item status + giữ open |
| 95 | enhancement | SCOPE_DEFERRED — keep OPEN as roadmap, đang tiến hành Phase 1 Path A (vendor patch) | Giữ open |
| 60 | — | TRACK_OPEN (partial) | Giữ open |
| 57 | — | STALE — rule priority đã implement, chỉ là doc-only spec | **Đóng** |
| 47 | — | STALE — gap snapshot 2026-05-06 đã superseded | **Đóng** |
| 43 | — | TRACK_OPEN — backend done, UI default-query VictoriaLogs chưa fix | Giữ open |
| 20 | — | STALE — build order completed | **Đóng** |
| 13 | — | DONE — FR-001 reverse proxy shipped | **Đóng** |
| 11 | — | STALE/DOC — đã có `docs/custom-rules-syntax.md` | **Đóng** |
|  9 | — | STALE — P0 FRs đã ship | **Đóng** |
|  8 | — | STALE/DONE — dashboard API + migrations đã ship | **Đóng** |
|  7 | — | STALE/DONE — admin panel pages đã ship | **Đóng** |

## Phân loại hành động

### Đóng (8 issues — stale/done)
#7, #8, #9, #11, #13, #20, #47, #57

### Comment + giữ open (20 issues — VALID hoặc TRACK_OPEN)
#43, #60, #70, #71, #72, #73, #74, #75, #76, #77, #78, #79, #80, #81, #82, #83, #84, #85, #86, #95

### Đặc biệt (1 issue — FALSE_ALARM cần user quyết định)
#87 — confirm commit `331efc43` chỉ là partial fix; bug case-fold vẫn còn nguyên. Comment đính chính bắt buộc.
#88 — false-alarm. Đề xuất: comment giải thích → close + mở issue mới scope đúng (response-side `Set-Cookie` / `Cache-Control: private` gates).

## Open questions từ researchers

1. **#87** — Author commit `331efc43` (sub-PR #103) có cố tình bỏ case-fold để giữ raw audit logs? Hỏi trước khi mở fix PR.
2. **#88** — Re-scope hay close-and-replace? User cần chọn.
3. **#95** — Path A (vendor patch) đang là phase 1; user xác nhận trước khi đóng.
4. **#83 #84** — Adjacent observability gaps (pending_count gauge, slot-count cap) — có nên gộp vào fix gốc?

## OPEN_GAPS bổ sung phát hiện ngoài body issue gốc

- **#77** — `[::127.0.0.1]` cũng bypass loopback check (Rust `Ipv6Addr::is_loopback` chỉ match `::1`). Mở rộng scope fix.
- **#81** — `decompress_snapshot` (pub fn) tại `sync/rules.rs:205` cùng flaw — fix tại helper chung.
- **#82** — `ConfigSyncer::apply_sync` (`sync/config.rs:31`) cùng pattern unconditional overwrite.

## Unresolved

- Issue #88 close-vs-rescope quyết định cuối từ user.
- 3 OPEN_GAPS nêu trên — gộp vào issue gốc hay tách issue mới?
