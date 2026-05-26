# Reviewer-1 — Pick 1 Critical issue cho release/stg fix (260526)

Branch read: `main` @ `f0fce2b0` (snapshot từ audit synthesis 260524, source files chưa đổi).
Target branch fix: `release/stg`.
Input gốc: `plans/reports/issue-audit-synthesis-260524.md`, `plans/reports/researcher-r1-260524-critical-audit.md`.

---

## Top-3 candidates

| Rank | Issue | Severity | Scope (file:line) | Effort | FR alignment | Test isolation | Production-impact (stg) |
|------|-------|----------|-------------------|--------|--------------|----------------|-------------------------|
| **#1** | **#77** | Critical | `crates/waf-common/src/url_validator.rs:175-211` + `crates/waf-engine/src/checks/ssrf_scanners.rs:118-150` | ~0.5d (helper + tests + GAP coverage) | **FR-016 SSRF** (P0) + FR-017 | Pure fn — không cần DB / cluster mock. Bestest isolation. | Cao — webhook + outbound check chạy đa số request. Fix khoá luôn IPv4-compat bypass (audit GAP nói `[::127.0.0.1]`, `[::100.100.100.200]`, `[::169.254.169.254]`). |
| #2 | #78 | Critical | `crates/waf-engine/src/plugins/manager.rs:93-135` | ~0.75d (wire `Store::limiter()` + `ResourceLimiter` impl + test với WAT module) | FR-021..024 (plugin hot-reload) gián tiếp; chủ yếu hardening | Cần dựng `wasmtime::Module` từ WAT inline — không DB, không cluster | Trung — plugins WASM khả năng chưa enable ở stg; nếu enabled thì OOM 1 request → kill process toàn node. |
| #3 | #70 | Critical | `crates/waf-cluster/src/transport/server.rs:203-278`, `crates/waf-cluster/src/lib.rs:148` | ~1d (wire `validate_token`, thêm field `join_token` vào `ClusterCryptoConfig`, update CLI/docs) | FR-044/045 (cluster) — không trong P0 | Cần mock NodeState/CA key — phức tạp hơn unit test pure | Thấp ở stg single-node. Quan trọng khi mở thêm node. |

Reject:
- #75 split-brain quorum check — fix đụng election loop + health module, cần integration test multi-node (≥3 peers) — vượt 1 day, không hợp test-isolation per rules.md item 6.
- #76 self-promotion ever_had_peers — cùng lý do #75, đụng election + state machine. Multi-node test required.

---

## Recommended #1 — Issue #77 SSRF IPv4-compatible IPv6 bypass

### Vì sao chọn

1. **Scope rõ + small surface:** 2 file thuần Rust, helper function `is_private_or_reserved` + `is_private_ip`. Không đụng async, không state.
2. **Test isolation tuyệt vời:** pure fn → `#[test]` standalone, không mock DB / cluster / wasmtime / network → đạt 90% coverage rule 6 dễ.
3. **FR-016 SSRF P0 alignment:** fix directly hardens outbound + webhook validation; FR-016 đòi block 169.254.x — currently bypassed.
4. **Production-impact ngay trên stg:** validator được gọi từ webhook config (CrowdSec / community blocklist / outbound notifier). Single-node stg vẫn hứng đủ exposure.
5. **OPEN_GAP đã có sẵn từ R1 audit:** `[::127.0.0.1]`, `[::100.100.100.200]`, `[::169.254.169.254]` — fix gọn trong cùng PR.
6. **Có sẵn pattern tham chiếu:** `ssrf_scanners.rs:125` đã có `to_ipv4_mapped()` cho `::ffff:a.b.c.d` — chỉ cần thêm IPv4-compatible (`::a.b.c.d`, không phải `::ffff:a.b.c.d`).

### Fix approach

**File 1: `crates/waf-common/src/url_validator.rs`**

Thêm helper trong `is_private_or_reserved` IPv6 arm — chuyển đổi IPv4-compatible (RFC 4291 §2.5.5.1):

```rust
// ::a.b.c.d — IPv4-compatible (deprecated nhưng vẫn parse được)
// seg[0..=5] all zero, seg[6..7] mang 32-bit v4
|| {
    let seg = v6.segments();
    seg[0] == 0 && seg[1] == 0 && seg[2] == 0
        && seg[3] == 0 && seg[4] == 0 && seg[5] == 0
        && (seg[6] != 0 || seg[7] != 0)
        && {
            let v4 = std::net::Ipv4Addr::new(
                (seg[6] >> 8) as u8, (seg[6] & 0xff) as u8,
                (seg[7] >> 8) as u8, (seg[7] & 0xff) as u8,
            );
            is_private_or_reserved(&IpAddr::V4(v4))
                || matches!(v4.octets(), [169, 254, _, _] | [100, 100, 100, 200])
        }
}
```

Lưu ý: `const fn` hiện tại đang khó giữ — `Ipv4Addr::new` là `const` nhưng recursion vào `is_private_or_reserved` qua `IpAddr::V4` build cũng const. Nếu compiler kêu, bỏ `const` (acceptable; called per webhook config load, không hot path).

**File 2: `crates/waf-engine/src/checks/ssrf_scanners.rs:118-150`**

Thêm fallback IPv4-compatible song song với `to_ipv4_mapped()` hiện có:

```rust
if let Some(v4) = v6.to_ipv4_mapped() {
    /* existing branch */
}
// IPv4-compatible (::a.b.c.d) — segs[0..=5]=0, segs[6..7] = v4
let segs = v6.segments();
if segs[0..6].iter().all(|&s| s == 0) && (segs[6] != 0 || segs[7] != 0) {
    let v4 = Ipv4Addr::new(
        (segs[6] >> 8) as u8, (segs[6] & 0xff) as u8,
        (segs[7] >> 8) as u8, (segs[7] & 0xff) as u8,
    );
    if PRIVATE_CIDRS.iter().any(|net| net.contains(&v4))
        || METADATA_HOST_SET.is_match(&v4.to_string())
    {
        return true;
    }
}
```

### Test plan (3-5 cases, append to `crates/waf-common/tests/url_validator_edge.rs` + ssrf_scanners inline tests)

1. `rejects_ipv4_compatible_aws_imds` — `http://[::169.254.169.254]/` → `BlockedHost`. Reproduce gốc của issue.
2. `rejects_ipv4_compatible_alibaba_imds` — `http://[::100.100.100.200]/` → `BlockedHost`. GAP từ audit.
3. `rejects_ipv4_compatible_loopback` — `http://[::127.0.0.1]/` → `BlockedHost`. GAP từ audit (`Ipv6Addr::is_loopback` chỉ match `::1`).
4. `rejects_ipv4_compatible_rfc1918` — `http://[::10.0.0.1]/`, `http://[::192.168.1.1]/` → `BlockedHost`. Coverage mở rộng.
5. `accepts_public_ipv4_compatible_not_blocked` — `http://[::1.1.1.1]/` → `Ok` (1.1.1.1 routable). Negative case, đảm bảo không over-block.
6. (ssrf_scanners) `is_private_ip_v4_compatible_metadata` — call `is_private_ip(IpAddr::V6("::a9fe:a9fe".parse()))` → `true`. Bonus inline.

Mỗi test < 5 dòng, deterministic, no I/O.

### Định hướng commit

- Branch base: `release/stg`
- Conventional commit: `fix(ssrf): reject IPv4-compatible IPv6 metadata/private addresses`
- Single squash commit per rules.md item 10.
- Update body PR ghi rõ: bypass surface (AWS, Azure, Alibaba IMDS via `::a.b.c.d`), không reference internal IDs trong comment code (per CLAUDE.md `review-audit-self-decision.md` §5).

---

## Vì sao reject 4 còn lại

- **#70 cluster JoinRequest token validation** — fix đúng (call `validate_token` ở `server.rs:203`), nhưng:
  - Cần thêm field config worker side (`ClusterCryptoConfig.join_token` hoặc CLI flag), update bootstrap flow `lib.rs:147`, update docs.
  - Test cần mock NodeState với ca_key_pem in-memory + chạy QUIC roundtrip (tham khảo `tests/transport_loopback.rs`) — phức tạp hơn pure-fn.
  - Production impact ở stg = thấp (single-node, mTLS đã chặn outsider không có cert CA). Effort ~1 day, value thấp ở stg.

- **#75 split-brain Main quorum** — đụng election loop FSM, cần `is_majority` gate trên writes (sync flow), thêm peer-liveness check. Integration test cần ≥3 node simulator — vi phạm rules.md item 6 (mock được hay không thì cluster timing non-deterministic). Reserve cho multi-node deploy.

- **#76 single-node self-promotion** — gắn liền #75 (cùng path election loop). Fix đòi consult config-declared role + `ever_had_peers` flag persist. Cùng lý do test isolation kém.

- **#78 WASM memory limit** — strong candidate hạng 2, nhưng:
  - Phải implement `wasmtime::ResourceLimiter` trait (~50 LOC) + wire `store.limiter()`.
  - Test cần build WAT module ép `(memory N)` rồi assert instantiate fails. Wasmtime API đáng tin nhưng test setup nặng hơn pure-fn validator.
  - Stg deploy có WASM plugin enabled hay không chưa rõ — nếu chưa enable → severity thực tế giảm. Reserve cho phase sau khi plugins được wired.

---

## Open questions

1. **Stg deploy hiện có dùng webhook outbound (CrowdSec/community/notifier) không?** Nếu có → fix #77 ưu tiên tuyệt đối. Nếu webhook disabled → vẫn giá trị vì FR-016 outbound block cũng dùng `is_private_ip`.
2. **Có cần mở thêm issue tách riêng cho `[::127.0.0.1]` + `[::100.100.100.200]` GAP** hay gộp PR fix #77 cover luôn? Đề xuất gộp (1 PR — 1 commit — cùng helper).
3. **Comment trong code có được mention RFC 4291 không?** Per `review-audit-self-decision.md` §5, RFC numbers là external IDs durable — allowed. Sẽ dùng.
