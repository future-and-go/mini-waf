# Native Wazuh Forwarder (PRX-WAF)

## ROLE & MISSION

Bạn là một Rust engineer làm việc trên **PRX-WAF** (reverse-proxy WAF trên Pingora, workspace
nhiều crate: `waf-common`, `waf-engine`, `waf-api`, `waf-cluster`, `prx-waf`).

Nhiệm vụ: implement **Native Wazuh Forwarder** — một module forward các WAF audit/security
event sang **Wazuh Manager** qua TCP/UDP bằng **CEF (Common Event Format)**, theo đúng kiến
trúc fire-and-forget đã có sẵn của CrowdSec log pusher và VictoriaLogs audit sender.

**KHÔNG** chạy binary Wazuh bên trong tiến trình WAF. Đây là một forwarder native, gửi event
ra Wazuh Manager bên ngoài (input syslog/CEF của Wazuh).

---

## HARD CONSTRAINTS (bắt buộc, không được vi phạm)

### A. Test-Driven Development — red/green/refactor
1. **Viết test TRƯỚC code production.** Mỗi đơn vị logic mới phải có test fail trước, rồi
   mới viết code cho pass. Trình bày theo thứ tự: (1) test, (2) chạy thấy đỏ, (3) impl,
   (4) chạy thấy xanh, (5) refactor.
2. Mỗi file logic trong `waf-engine` có `#[cfg(test)] mod tests` (unit test inline) —
   theo đúng pattern `crowdsec/pusher.rs`, `logging/audit_sender.rs`.
3. Test tích hợp đặt ở `crates/waf-engine/tests/` (file riêng), theo pattern
   `crates/waf-cluster/tests/event_forwarding_test.rs`.
4. Test timer/flush dùng `#[tokio::test(start_paused = true)]` + `tokio::time` ảo, KHÔNG
   `sleep` thật. Tham khảo `run_event_batcher_flushes_on_close`.
5. Test network không được phụ thuộc Wazuh thật: dùng một `tokio::net::TcpListener`
   loopback nhận-rồi-đóng làm fake sink, HOẶC một trait `Transport` mock-able (xem mục E).
   Pattern tham chiếu: `unreachable_pusher()` trong `crowdsec/pusher.rs`.
6. Coverage mục tiêu cho code mới: ≥ 85% (khớp success metric của dự án).

### B. Error handling & an toàn (theo code-safety-patterns.md)
1. **Cấm** `unwrap()`, `expect()`, `panic!()`, `todo!()`, `unimplemented!()` trong code
   production. Dùng `?` hoặc `match` tường minh. (Test code được phép `expect/unwrap` với
   `#![allow(clippy::unwrap_used, clippy::expect_used)]` ở đầu file test — như các file test
   hiện có.)
2. Sync lock → `parking_lot::Mutex` (không poisoning, không `.unwrap()`).
   Async lock → `tokio::sync::Mutex`. Read nhiều/write hiếm → `arc_swap::ArcSwap`.
3. **No secret logging.** Không log API key / auth key / token. Nếu cần log endpoint, chỉ log
   `host:port`, không log key. Dùng helper sanitize nếu cần.
4. Không `unsafe`.
5. `cargo fmt --all -- --check` và `cargo clippy --workspace --all-targets -- -D warnings`
   phải pass. Không dead code, không unused import.

### C. Hot path — fire-and-forget, fail-open
1. Hàm gọi từ hot path (engine `inspect()`) phải **đồng bộ, không block, không await,
   không spawn** — chỉ một `try_send` vào bounded MPSC channel. Tham chiếu:
   `CommunityReporter::try_push_detection` và `BatchSender::try_send`.
2. Channel đầy ⇒ **drop** event mới, emit `tracing::warn!` rate-limited (cooldown ~30s),
   tăng một counter `dropped` (AtomicU64) để quan sát. KHÔNG block hot path.
3. Wazuh Manager unreachable ⇒ background task tự reconnect với exponential backoff; hot path
   không bao giờ bị gate bởi tình trạng Wazuh. (Fail-open như audit_sender.)
4. Truncate path dài (tái dùng hằng `PATH_TRUNCATE_AT = 500` style, cắt trên ranh giới UTF-8)
   để dòng CEF luôn bị chặn kích thước.

### D. Convention cấu trúc (PHẢI bám đúng layout sẵn có)
1. **Config kép** giống CrowdSec/VictoriaLogs:
   - `crates/waf-common/src/config.rs`: thêm `WazuhConfig` phẳng, TOML-loadable, có
     `#[serde(default = "...")]` + `Default` impl + các `const fn`/`fn` default. `enabled`
     mặc định `false`.
   - `crates/waf-engine/src/wazuh/config.rs`: type config "giàu" của engine (enum
     `WazuhProtocol { Tcp, Udp }`, v.v.), `#[serde(rename_all = "snake_case")]`.
   - `crates/prx-waf/src/main.rs`: thêm converter `app_config_to_wazuh(&AppConfig) ->
     WazuhConfig` (engine type), đúng như `app_config_to_crowdsec`.
2. `configs/default.toml`: thêm block `[wazuh]` có comment đầy đủ (giống block
   `[victoria_logs]` / `[crowdsec]`), mặc định `enabled = false` (zero behavior change).
3. **Init function**: `wazuh::init_wazuh(config, shutdown_rx: watch::Receiver<bool>) ->
   Option<WazuhComponents>` trả `None` khi `!enabled`. Spawn flush task trong này, đúng
   pattern `crowdsec::init_crowdsec`.
4. **Engine wiring**: trong `crates/waf-engine/src/engine.rs`
   - Thêm field `wazuh_forwarder: OnceLock<Arc<WazuhForwarder>>` (khởi tạo `OnceLock::new()`
     trong cả hai constructor `new`/`with_sqli_config`).
   - Thêm method `pub fn set_wazuh_forwarder(&self, fwd: Arc<WazuhForwarder>)` (set OnceLock).
   - Hook gọi forwarder TỪ TRONG `send_audit_event(...)` đã có — tái dùng `AuditEvent` để
     khỏi clone logic. Dùng `let Some(fwd) = self.wazuh_forwarder.get() else { return; };`.
     KHÔNG sửa thứ tự phase, KHÔNG đổi return type của `inspect()`.
5. **Module export**: `crates/waf-engine/src/wazuh/mod.rs` với `pub mod ...` + `pub use ...`,
   giống `crowdsec/mod.rs`. Đăng ký `pub mod wazuh;` trong `waf-engine/src/lib.rs`.
6. Commit theo Conventional Commits: `feat(waf-engine): ...`, scope là crate bị ảnh hưởng.
7. Mọi feature phải "support clustering — no single-node-only features": forwarder chạy
   độc lập per-node là hợp lệ (mỗi node tự forward event của mình). Ghi rõ điều này trong doc.

### E. Khả-test-hóa transport (để TDD network không cần Wazuh thật)
Tách phần I/O sau một trait nhỏ để test được mà không mở socket thật:
```rust
#[async_trait::async_trait]
trait WazuhTransport: Send + Sync {
    async fn send_line(&mut self, line: &str) -> anyhow::Result<()>;
    async fn reconnect(&mut self) -> anyhow::Result<()>;
}
```
- `TcpTransport` / `UdpTransport`: impl thật (tokio net).
- Trong test: `MockTransport` ghi các dòng nhận được vào `Arc<Mutex<Vec<String>>>` và có thể
  giả lập lỗi gửi để test reconnect/backoff. (parking_lot::Mutex.)

---

## THIẾT KẾ MODULE (Hướng 2 — Native Wazuh Forwarder)

```
crates/waf-engine/src/wazuh/
├── mod.rs           # init_wazuh(), WazuhComponents, pub use
├── config.rs        # WazuhConfig (engine), WazuhProtocol enum, defaults + tests
├── encoder.rs       # AuditEvent -> CEF string; severity/rule-id mapping + tests
├── transport.rs     # WazuhTransport trait, Tcp/Udp impl, MockTransport(cfg(test)) + tests
└── forwarder.rs     # WazuhForwarder (bounded mpsc, try_send), run_flush_task + tests
```

### config.rs — yêu cầu
```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WazuhProtocol { #[default] Tcp, Udp }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WazuhConfig {
    pub enabled: bool,                 // default false
    pub manager_host: String,          // ví dụ "127.0.0.1"
    #[serde(default = "default_wazuh_port")]
    pub manager_port: u16,             // default 514 (syslog) — TCP 1514 nếu agent input
    #[serde(default)]
    pub protocol: WazuhProtocol,
    #[serde(default = "default_true")]
    pub blocks_only: bool,             // chỉ forward khi event_type != Allow
    #[serde(default = "default_rule_id_base")]
    pub rule_id_base: u32,             // namespace rule id Wazuh, ví dụ 100000
    #[serde(default = "default_wazuh_channel_capacity")]
    pub channel_capacity: usize,       // default 10_000 (drop-newest khi đầy)
    #[serde(default = "default_wazuh_batch_size")]
    pub batch_size: usize,             // gom dòng trước khi flush
    #[serde(default = "default_wazuh_flush_interval_ms")]
    pub flush_interval_ms: u64,        // flush theo thời gian
    #[serde(default = "default_wazuh_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
}
```
- Có `Default` impl (enabled=false, host="127.0.0.1", port=514, ...), validate khi
  `enabled=true` (host không rỗng, port>0, capacity>0) — đặt trong `impl WazuhConfig { pub fn
  validate(&self) -> anyhow::Result<()> }`, gọi ở `init_wazuh`.
- **Tests (viết trước):** `defaults_are_safe` (enabled=false), `validate_rejects_empty_host`,
  `protocol_serde_roundtrip` (tcp/udp), default port = 514.

### encoder.rs — yêu cầu
- `pub fn encode_cef(event: &AuditEvent, rule_id_base: u32) -> String` sinh CEF chuẩn:
  ```
  CEF:0|PRX-WAF|WAF|1.0|<signatureId>|<name>|<severity>|<extensions>
  ```
  Extensions: `src=<client_ip> request=<path> requestMethod=<method> dhost=<host>
  cs1=<rule_id> cs1Label=RuleId cs2=<phase> cs2Label=Phase cs3=<tier> cs3Label=Tier
  cs4=<event_type> cs4Label=Action rt=<epoch_ms>`.
- `signatureId = rule_id_base + stable_hash(rule_id_or_name)` (deterministic, không random).
- `severity` 0–10 map từ `AuditEventType` (Block=10, RateLimit=7, Challenge=5, LogOnly=4,
  Allow=2) — đặt một hàm `cef_severity(AuditEventType) -> u8`.
- **CEF escaping bắt buộc:** trong header escape `|` và `\`; trong extension value escape
  `=` và `\` và newline. Viết hàm `escape_header` / `escape_ext` riêng.
- Truncate path theo ranh giới UTF-8 (tái dùng ý tưởng `PATH_TRUNCATE_AT`).
- **Tests (viết trước):** escaping `|`,`=`,`\`,`\n`; severity mapping đủ 5 nhánh;
  signatureId deterministic (cùng input → cùng id) và nằm trong namespace base;
  path UTF-8 bị cắt đúng ranh giới; không có ký tự newline lọt vào dòng CEF cuối cùng
  (property test với `proptest`, input `".*"`, đảm bảo output 1 dòng).

### transport.rs — yêu cầu
- Trait `WazuhTransport` như mục E.
- `TcpTransport`: kết nối `manager_host:port` với `connect_timeout`, gửi `line + "\n"`.
- `UdpTransport`: bind ephemeral, `send_to`.
- `MockTransport` (chỉ `#[cfg(test)]`): lưu các dòng, có cờ `fail_next` để mô phỏng lỗi.
- **Tests (viết trước):** MockTransport ghi đúng dòng; `fail_next` khiến `send_line` trả
  `Err`; reconnect reset trạng thái. (Một test TCP loopback tuỳ chọn với `TcpListener` chỉ
  để smoke — nằm trong integration test, không phải unit test.)

### forwarder.rs — yêu cầu
```rust
pub struct WazuhForwarder {
    tx: mpsc::Sender<AuditEvent>,
    dropped: Arc<AtomicU64>,
    last_full_warn_ms: Arc<AtomicU64>,
    blocks_only: bool,
}
impl WazuhForwarder {
    /// Hot path: sync, non-blocking. Drop-newest khi đầy + warn rate-limited.
    pub fn send(&self, event: AuditEvent) { /* lọc blocks_only; try_send; xử lý Full */ }
    pub fn dropped_count(&self) -> u64 { ... }
}
```
- `run_flush_task(rx, transport, cfg, shutdown_rx)`:
  - `tokio::select!` (biased) giữa `rx.recv()`, `interval.tick()`, `shutdown_rx.changed()`.
  - Gom `batch_size` dòng CEF rồi flush; hoặc flush theo `flush_interval_ms`; flush cuối khi
    shutdown / channel đóng. (Đúng pattern `batch_buffer::flush_loop` + `pusher::run_flush_task`.)
  - Flush lỗi ⇒ `transport.reconnect()` với exponential backoff (vd 100ms→…→tối đa 30s,
    có jitter nhẹ), warn rate-limited; KHÔNG mất dòng đang chờ một cách im lặng quá mức
    (cố flush lại batch hiện tại sau reconnect; nếu vẫn fail, drop batch + warn — fail-open).
- **Tests (viết trước):**
  - `send_drops_allow_when_blocks_only_true` (Allow bị bỏ; Block đi qua).
  - `send_is_nonblocking_and_drops_when_full` (channel cap=1, gửi 3, `dropped_count()>=1`).
  - `flush_on_capacity` và `flush_on_close` với `MockTransport` + `start_paused` timer.
  - `reconnects_after_transport_error` (MockTransport.fail_next → kế tiếp thành công, dòng
    được gửi lại).

### mod.rs — yêu cầu
```rust
pub struct WazuhComponents {
    pub forwarder: Arc<WazuhForwarder>,
    pub task: tokio::task::JoinHandle<()>,
}
pub async fn init_wazuh(cfg: WazuhConfig, shutdown_rx: watch::Receiver<bool>)
    -> Option<WazuhComponents> {
    if !cfg.enabled { return None; }
    if let Err(e) = cfg.validate() { warn!(error=%e, "wazuh config invalid; disabling"); return None; }
    // build transport theo protocol; tạo channel; spawn run_flush_task; trả Components
}
```
- **Test (viết trước):** `disabled_returns_none` (giống `crowdsec::tests::disabled_returns_none`).

---

## WIRING (sau khi 5 file trên xanh)

1. `waf-engine/src/lib.rs`: `pub mod wazuh;`
2. `engine.rs`: thêm field `wazuh_forwarder: OnceLock<Arc<WazuhForwarder>>`, init trong cả 2
   constructor, thêm `set_wazuh_forwarder`, và trong `send_audit_event` thêm (cuối hàm):
   ```rust
   if let Some(fwd) = self.wazuh_forwarder.get() {
       fwd.send(event.clone()); // event là AuditEvent đã dựng sẵn ở trên
   }
   ```
   (Lưu ý: chuyển `sender.send(event)` hiện tại thành `sender.send(event.clone())` nếu cần,
   hoặc dựng `event` rồi gửi cho cả hai sink — giữ AuditSender chạy trước, Wazuh sau.)
3. `waf-common/src/config.rs`: thêm `pub wazuh: WazuhConfig` vào `AppConfig` với
   `#[serde(default)]` + thêm `WazuhConfig` struct phẳng + defaults.
4. `prx-waf/src/main.rs`: `app_config_to_wazuh()`, trong boot path gọi `init_wazuh(...)`
   (sau khi runtime tokio đã sẵn sàng — giống chỗ init crowdsec/victoria_logs), rồi
   `engine.set_wazuh_forwarder(components.forwarder)`.
5. `configs/default.toml`: thêm block `[wazuh]` có comment.

---

## INTEGRATION TEST (file riêng — viết trước phần wiring)

`crates/waf-engine/tests/wazuh_forwarder_test.rs` (đầu file:
`#![allow(clippy::unwrap_used, clippy::expect_used)]`):
1. `forwarder_sends_cef_to_fake_sink`: bật `TcpListener` loopback, cấu hình forwarder TCP
   tới địa chỉ đó, `send` vài event, đọc từ listener, assert mỗi dòng bắt đầu `CEF:0|PRX-WAF|`
   và chứa `src=` đúng IP. Dùng timeout (`tokio::time::timeout`) để test không treo.
2. `blocks_only_filters_allow_end_to_end`.
3. `survives_sink_down_then_up`: chưa mở listener → gửi event (phải không panic, không treo)
   → mở listener → event sau đến nơi (chứng minh reconnect).

---

## QUY TRÌNH BÁO CÁO (bắt buộc theo từng bước TDD)

Với MỖI file (config → encoder → transport → forwarder → mod → wiring → integration):
1. Hiển thị test viết trước.
2. Chạy `cargo test -p waf-engine wazuh` → dán output ĐỎ (test fail như mong đợi).
3. Viết code production tối thiểu để pass.
4. Chạy lại → dán output XANH.
5. `cargo fmt --all` + `cargo clippy -p waf-engine --all-targets -- -D warnings` → pass.
6. Đề xuất commit message (Conventional Commits).

Tuyệt đối không viết code production trước khi có test đỏ tương ứng.

---

## ACCEPTANCE CRITERIA (Definition of Done)

- [ ] `[wazuh] enabled = false` mặc định ⇒ zero behavior change; `init_wazuh` trả `None`,
      không mở socket, không spawn task.
- [ ] Hot path `WafEngine::inspect` không thêm `await`/`spawn`/lock-blocking nào; chỉ một
      `try_send` qua `send_audit_event`.
- [ ] Wazuh down KHÔNG làm tăng latency request (test `survives_sink_down_then_up`).
- [ ] CEF hợp lệ + escape đúng (unit + property test).
- [ ] Không `unwrap/expect/panic/todo` trong code production.
- [ ] `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --all` pass.
- [ ] Coverage code mới ≥ 85%.
- [ ] Doc: thêm mục "Wazuh Forwarder" vào `docs/system-architecture.md`, cập nhật
      `docs/codebase-summary.md` (module mới) và một dòng changelog. Ghi rõ forwarder
      per-node, cluster-safe.
- [ ] Giữ mục tiêu p99 < 5ms (không có công việc nặng trên hot path).

---

## GỢI Ý KHỞI ĐỘNG

Bắt đầu bằng việc đọc các file tham chiếu để bám đúng phong cách, rồi làm theo thứ tự
config → encoder → transport → forwarder → mod → wiring → integration, mỗi bước TDD:

- `crates/waf-engine/src/crowdsec/pusher.rs` (buffer + flush task + test pattern)
- `crates/waf-engine/src/community/reporter.rs` (bounded mpsc, try_push, dropped counter)
- `crates/waf-engine/src/logging/batch_buffer.rs` (flush_loop, drop-on-full, rate-limited warn)
- `crates/waf-engine/src/logging/audit_sender.rs` (AuditEvent, AuditEventType, JSON payload)
- `crates/waf-engine/src/crowdsec/mod.rs` (init_* trả Option, spawn task)
- `crates/waf-engine/src/crowdsec/config.rs` + `crates/waf-common/src/config.rs` (config kép)
- `crates/prx-waf/src/main.rs` (`app_config_to_crowdsec` converter)
- `crates/waf-cluster/tests/event_forwarding_test.rs` (integration test với `start_paused`)

Hãy hỏi lại nếu cần làm rõ, nhưng mặc định bám sát các pattern trên — không phát minh
abstraction mới ngoài trait `WazuhTransport` đã nêu.
