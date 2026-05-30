# Cursor Prompt — Chuyển Admin Panel sang HTTPS (Self‑Signed, In‑Binary) + Hardening Truyền Tải Admin↔BE

> **Loại tác vụ:** Feature implementation, multi-crate (Rust + Vite/React)
> **Phạm vi:** `crates/waf-api`, `crates/waf-common`, `crates/prx-waf`, `web/admin-panel`, `Dockerfile`, `docker-compose.yml`, `configs/default.toml`, docs
> **Backwards compat:** Bắt buộc — config cũ (chỉ có `listen_addr`) vẫn phải boot được, mặc định bật HTTPS nhưng có thể tắt qua TOML
> **Ngôn ngữ:** Code + identifier giữ tiếng Anh. Comment/docstring giữ phong cách codebase hiện tại.

---

## 0. Đọc bắt buộc trước khi code

Trước khi sửa bất kỳ file nào, đọc và tuân thủ:

1. `docs/code-standards.md` — Seven Iron Rules (no `unwrap()`, `expect()`, `panic!()`, `todo!()`, `unimplemented!()` trong code production)
2. `docs/code-safety-patterns.md` — cụ thể các section:
   - **Mutex & Synchronization** → dùng `parking_lot::Mutex` cho sync, `tokio::sync::Mutex` cho async, `arc-swap::ArcSwap` cho NodeState-style read-mostly
   - **No Secret Logging** → KHÔNG log private key PEM, password, JWT, tokens
   - **Logging & Tracing** → structured fields, không `println!`
   - **Minimal Allocations in Hot Paths**
   - **SQL Safety** (không liên quan trực tiếp nhưng cần thiết khi đụng audit log)
   - **Code Review Checklist** ở cuối file
3. `docs/cluster-guide.md` — §"Certificate Management" + §"Auto-generate mode" → tái sử dụng đúng convention `validity_days`, `renewal_before_days`, `auto_generate`
4. `crates/waf-cluster/src/crypto/ca.rs` và `node_cert.rs` — pattern rcgen Ed25519 chuẩn của dự án
5. `crates/gateway/src/ssl.rs` — hàm `SslManager::generate_self_signed()` đã tồn tại; có thể dùng làm fallback nhưng KHÔNG đủ cho admin panel (cần SAN list, renewal, multi-IP).
6. `crates/prx-waf/src/main.rs::ensure_self_signed_cert()` — pattern lưu cert ra `data_dir/tls/`. **Tham khảo nhưng KHÔNG copy nguyên** — admin TLS có yêu cầu riêng (SAN tự suy ra hostname + listen IP, renewal, structured AdminTlsMaterial).

---

## 1. Mục tiêu (Goals)

| # | Goal | Acceptance |
|---|------|------------|
| G1 | Admin API (`/api/*`, `/ui/*`, `/ws/*`, `/health`) phục vụ qua HTTPS | `curl -kI https://localhost:9527/health` → `HTTP/2 200`, `Strict-Transport-Security: max-age=...` hiện diện |
| G2 | Cert + key được **tự sinh ở runtime startup đầu tiên** (không bake vào binary), persist vào `data_dir/admin-tls/`, tự renew khi sắp hết hạn | Boot lần 2 với `data_dir/admin-tls/cert.pem` đã tồn tại → log `"Reusing existing admin TLS material"`, KHÔNG sinh lại; xoá file → boot lại tự sinh mới |
| G3 | Logic sinh/tải/renew cert được build cùng binary (không cần `openssl`, không cần script ngoài) | `cargo build --release` xong là chạy được; `ldd target/release/prx-waf | grep -i openssl` không có (đã ban qua `deny.toml`) |
| G4 | Tăng bảo mật truyền tải Admin Panel → BE API | Xem §4 "Hardening Checklist" — tất cả mục đều pass |
| G5 | Backwards compatible: deployment cũ không config TLS vẫn boot được (fallback HTTP có cảnh báo) hoặc opt-out qua flag | Boot với `configs/default.toml` cũ (không có `[api.tls]`) → vẫn lên HTTPS với cert auto-gen; set `[api.tls] enabled = false` → fallback HTTP với `WARN` log mỗi 60s |
| G6 | Vite dev server (`npm run dev`) vẫn chạy được, proxy sang HTTPS backend với `secure: false` (chấp nhận self-signed) | `cd web/admin-panel && npm run dev` → mở `http://localhost:5174` đăng nhập OK |

---

## 2. Phạm vi (In Scope / Out of Scope)

### In scope
- Tạo module `crates/waf-api/src/tls.rs` quản lý vòng đời cert admin (generate, persist, load, renew, build rustls config)
- Refactor `crates/waf-api/src/server.rs` để hỗ trợ cả HTTP và HTTPS qua một entry point thống nhất
- Thêm struct `AdminTlsConfig` vào `crates/waf-common/src/config.rs::ApiConfig`
- Thêm middleware/header tightening cho hardening truyền tải (xem §4)
- Cập nhật `configs/default.toml`, `docker-compose.yml`, `Dockerfile` healthcheck, Vite proxy
- Thêm CLI subcommand `prx-waf admin-tls {info,regenerate,export-ca}` cho việc vận hành
- Viết unit tests (offline, không cần network) + integration test bind ephemeral port

### Out of scope (không làm trong PR này)
- ❌ ACME / Let's Encrypt cho admin panel (đã có cho proxy hosts qua `gateway::SslManager`, không scope vào admin port)
- ❌ Client cert mTLS bắt buộc cho admin (có thể thêm flag optional nhưng KHÔNG bật mặc định — sẽ làm follow-up)
- ❌ Sửa HTTP proxy port 80/443 (đã có TLS qua Pingora, không liên quan)
- ❌ Thay đổi JWT scheme hoặc auth flow
- ❌ Migrate từ localStorage sang HttpOnly cookie (có note ở §10, để follow-up)

---

## 3. Thiết kế

### 3.1 Config schema mới

Mở rộng `crates/waf-common/src/config.rs`:

```rust
/// Management API configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub listen_addr: String,
    /// TLS configuration cho admin API. None = HTTPS auto-on với defaults.
    #[serde(default)]
    pub tls: AdminTlsConfig,
}

/// TLS configuration cho admin API endpoint.
///
/// Mặc định: bật HTTPS, tự sinh self-signed cert ở `data_dir/admin-tls/`,
/// renew 30 ngày trước expiry, TLS 1.2+ với HTTP→HTTPS redirect listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminTlsConfig {
    /// Bật TLS. Default: true. Đặt false để fallback HTTP (KHÔNG khuyến nghị).
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Chế độ vận hành.
    /// - `"auto"` (default): tự sinh cert nếu chưa có, persist, renew tự động
    /// - `"provided"`: dùng cert/key từ `cert_pem` + `key_pem`, không tự renew
    #[serde(default)]
    pub mode: AdminTlsMode,

    /// PEM cert path — chỉ dùng khi `mode = "provided"`.
    #[serde(default)]
    pub cert_pem: Option<PathBuf>,

    /// PEM key path — chỉ dùng khi `mode = "provided"`.
    #[serde(default)]
    pub key_pem: Option<PathBuf>,

    /// Thư mục lưu cert auto-gen. Default: `<geoip.data_dir>/admin-tls/`
    /// hoặc `/var/lib/prx-waf/admin-tls/`.
    #[serde(default)]
    pub data_dir: Option<PathBuf>,

    /// SAN bổ sung (hostname + listen IP sẽ được tự nối thêm).
    /// Default: ["localhost", "127.0.0.1", "::1"]
    #[serde(default = "default_admin_tls_sans")]
    pub extra_sans: Vec<String>,

    /// Cert validity. Default: 365 ngày.
    #[serde(default = "default_admin_tls_validity")]
    pub validity_days: u32,

    /// Tự renew khi còn ≤ giá trị này. Default: 30 ngày.
    #[serde(default = "default_admin_tls_renew_before")]
    pub renewal_before_days: u32,

    /// Min TLS version: "1.2" hoặc "1.3". Default "1.2" cho khả năng tương thích.
    /// Khuyến nghị production: "1.3".
    #[serde(default = "default_min_tls_version")]
    pub min_tls_version: String,

    /// Bind thêm HTTP listener và 301 redirect sang HTTPS.
    /// Default: true khi `enabled = true`.
    #[serde(default = "default_true")]
    pub http_redirect: bool,

    /// Port cho HTTP redirect listener. Default: `listen_addr.port() - 1`.
    /// (e.g. nếu HTTPS chạy 9527 thì HTTP chạy 9526.) None = không bind.
    #[serde(default)]
    pub http_redirect_port: Option<u16>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdminTlsMode {
    #[default]
    Auto,
    Provided,
}

fn default_admin_tls_sans() -> Vec<String> {
    vec!["localhost".into(), "127.0.0.1".into(), "::1".into()]
}
fn default_admin_tls_validity() -> u32 { 365 }
fn default_admin_tls_renew_before() -> u32 { 30 }
fn default_min_tls_version() -> String { "1.2".into() }
fn default_true() -> bool { true }
```

Cập nhật `ApiConfig::default()`:
```rust
impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9527".to_string(),
            tls: AdminTlsConfig::default(),
        }
    }
}
impl Default for AdminTlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: AdminTlsMode::Auto,
            cert_pem: None,
            key_pem: None,
            data_dir: None,
            extra_sans: default_admin_tls_sans(),
            validity_days: 365,
            renewal_before_days: 30,
            min_tls_version: "1.2".into(),
            http_redirect: true,
            http_redirect_port: None,
        }
    }
}
```

**Lưu ý parse:** `min_tls_version` validate ở `AdminTlsConfig::validate()` — chỉ chấp nhận `"1.2"` / `"1.3"`, các giá trị khác → `anyhow::bail!`. Validate được gọi trong `AppConfig::load()` (file `crates/waf-common/src/config.rs::AppConfig::load`) sau khi parse TOML.

### 3.2 Module mới: `crates/waf-api/src/tls.rs`

```rust
//! Admin API TLS certificate lifecycle.
//!
//! - Auto mode: sinh Ed25519 self-signed cert lần đầu, lưu vào `data_dir`,
//!   reuse ở lần boot sau, tự renew khi còn ≤ renewal_before_days.
//! - Provided mode: load cert/key từ filesystem, không renew.
//!
//! Tất cả I/O đều fail-fast với `anyhow::Context` — không silently fall back.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use parking_lot::RwLock;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, version};
use rustls_pki_types::pem::PemObject as _;
use time::OffsetDateTime;
use tracing::{info, warn};
use waf_common::config::{AdminTlsConfig, AdminTlsMode};

/// In-memory TLS material ready for serving.
#[derive(Clone)]
pub struct AdminTlsMaterial {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub key: Arc<PrivateKeyDer<'static>>,
    pub not_after: OffsetDateTime,
    pub fingerprint_sha256: String, // hex; for /health and CLI export
}

/// Owns the TLS material and the rotation worker.
pub struct AdminTlsManager {
    config: AdminTlsConfig,
    listen_addr: SocketAddr,
    material: Arc<RwLock<Arc<AdminTlsMaterial>>>, // Arc<RwLock<Arc<...>>> để swap atomic
}

impl AdminTlsManager {
    pub fn bootstrap(config: AdminTlsConfig, listen_addr: SocketAddr) -> Result<Self> { /* ... */ }

    /// Build a `rustls::ServerConfig` snapshot from current material.
    /// Note: rustls config không hot-reload sẵn; rotation phải restart listener
    /// hoặc dùng cert_resolver (xem §3.4).
    pub fn server_config(&self) -> Result<Arc<ServerConfig>> { /* ... */ }

    /// SHA-256 fingerprint of current cert — expose qua `/health` + CLI.
    pub fn fingerprint(&self) -> String { /* ... */ }

    /// Spawn background renewal task (only meaningful in Auto mode).
    pub fn spawn_renewal(self: Arc<Self>) -> tokio::task::JoinHandle<()> { /* ... */ }
}

/// SAN list resolver: hostname() + listen IP + config.extra_sans + dedupe.
fn resolve_sans(listen_addr: SocketAddr, extras: &[String]) -> Vec<String> { /* ... */ }

/// Generate fresh self-signed Ed25519 cert with given SANs.
fn generate(sans: &[String], validity_days: u32) -> Result<(String, String, OffsetDateTime)> { /* ... */ }

/// Load cert+key from PEM files. Validate that key parses and matches cert.
fn load_from_files(cert: &Path, key: &Path) -> Result<AdminTlsMaterial> { /* ... */ }

/// Check `not_after - now < renewal_before_days`.
fn is_due_for_renewal(not_after: OffsetDateTime, before: Duration) -> bool { /* ... */ }
```

**Implementation contract:**

1. **`bootstrap()` flow:**
   - Nếu `!config.enabled` → return error sentinel mà caller xử lý (hoặc trả `Option<Self>` — chọn 1 cho consistent; khuyến nghị `Option<Arc<AdminTlsManager>>` ở caller).
   - Nếu `mode == Provided`:
     - Validate `cert_pem.is_some() && key_pem.is_some()` → load qua `load_from_files`
     - Renewal worker không spawn.
   - Nếu `mode == Auto`:
     - Resolve `data_dir`: ưu tiên config; nếu None → `/var/lib/prx-waf/admin-tls/` (Linux) hoặc fallback `./data/admin-tls/` (relative tới cwd). Tạo dir nếu chưa có (`std::fs::create_dir_all`).
     - Path: `{data_dir}/cert.pem`, `{data_dir}/key.pem`, `{data_dir}/metadata.json` (chứa SANs đã dùng, để detect SAN drift).
     - Nếu cả 2 file tồn tại và không due_for_renewal và SANs trong metadata khớp với SANs hiện tại → load.
     - Ngược lại → generate, ghi atomic (write to `cert.pem.tmp` rồi rename), log `INFO` với fingerprint.

2. **File permissions:**
   ```rust
   #[cfg(unix)]
   {
       use std::os::unix::fs::PermissionsExt;
       std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
           .with_context(|| format!("chmod 600 {key_path:?}"))?;
   }
   ```
   KHÔNG log key path/content. Cert path có thể log.

3. **`spawn_renewal()`:**
   - Chạy mỗi 6h (`tokio::time::interval(Duration::from_secs(6 * 3600))`).
   - Mỗi lần check `is_due_for_renewal` → re-generate → swap qua `RwLock<Arc<...>>`.
   - **Quan trọng:** rustls `ServerConfig` đã bound vào listener KHÔNG tự refresh. Phải dùng `Arc<dyn ResolvesServerCert>` (xem §3.4). Trong renewal task, cập nhật resolver internal state thay vì replace `ServerConfig`.

### 3.3 Cert resolver hot-swap

Implement `ResolvesServerCert` để tránh restart listener khi renew:

```rust
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

pub struct AdminCertResolver {
    current: ArcSwap<CertifiedKey>, // arc-swap để read lock-free (xem code-safety-patterns.md)
}

impl AdminCertResolver {
    pub fn new(material: &AdminTlsMaterial) -> Result<Self> { /* ... */ }
    pub fn swap(&self, material: &AdminTlsMaterial) -> Result<()> { /* ... */ }
}

impl ResolvesServerCert for AdminCertResolver {
    fn resolve(&self, _hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}
```

Wire vào `ServerConfig::builder().with_no_client_auth().with_cert_resolver(resolver)`.

### 3.4 Refactor `crates/waf-api/src/server.rs`

Thay vì hai hàm tách biệt, expose một entry point:

```rust
pub async fn start_api_server(
    config: &waf_common::config::ApiConfig,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config.listen_addr.parse()
        .with_context(|| format!("invalid api.listen_addr: {}", config.listen_addr))?;

    let app = build_router(state.clone());

    if !config.tls.enabled {
        warn!(
            "Admin API serving plaintext HTTP on {} — \
             traffic includes JWT tokens. Set [api.tls] enabled = true for production.",
            listen_addr
        );
        return serve_plain(listen_addr, app).await;
    }

    let tls_manager = Arc::new(AdminTlsManager::bootstrap(config.tls.clone(), listen_addr)
        .context("failed to bootstrap admin TLS material")?);

    // Spawn renewal in background (no-op in Provided mode)
    let _renewal_handle = Arc::clone(&tls_manager).spawn_renewal();

    info!(
        addr = %listen_addr,
        fingerprint = %tls_manager.fingerprint(),
        mode = ?config.tls.mode,
        "Admin API listening on HTTPS"
    );

    // Optional HTTP→HTTPS redirect
    if config.tls.http_redirect {
        spawn_http_redirect(listen_addr, config.tls.http_redirect_port);
    }

    serve_tls(listen_addr, app, tls_manager).await
}
```

**Crate cần thêm:** `axum-server` với feature `tls-rustls` (đã sẵn trong ecosystem). Update `crates/waf-api/Cargo.toml`:

```toml
axum-server = { version = "0.7", features = ["tls-rustls"] }
# rustls re-export đã có qua các crate khác — pin version khớp với workspace
```

`serve_tls` dùng:
```rust
use axum_server::tls_rustls::RustlsConfig;
let rustls_config = RustlsConfig::from_config(tls_manager.server_config()?);
axum_server::bind_rustls(listen_addr, rustls_config)
    .serve(app.into_make_service_with_connect_info::<SocketAddr>())
    .await
    .context("axum-server tls serve failed")?;
```

**Cập nhật caller** `crates/prx-waf/src/main.rs`:

```rust
// Trước:
// if let Err(e) = start_api_server(&api_listen, api_state_bg).await { ... }

// Sau:
let api_cfg = config.api.clone();
if let Err(e) = start_api_server(&api_cfg, api_state_bg).await {
    tracing::error!("API server error: {}", e);
}
```

Đảm bảo `rustls::crypto::ring::default_provider().install_default()` đã chạy ở `main()` (đã có sẵn ở `crates/prx-waf/src/main.rs` đầu hàm `main` — không cần thêm).

---

## 4. Hardening Checklist (G4) — Bảo mật truyền tải Admin↔BE

Mỗi mục dưới đây là một acceptance gate, có test tương ứng.

### H1. TLS version & cipher
- `min_tls_version` được tôn trọng. Map sang `rustls::version::{TLS12, TLS13}`.
- Khi `min_tls_version = "1.3"` → chỉ enable TLS13 trong `ServerConfig::builder_with_protocol_versions(&[&version::TLS13])`.
- ALPN: advertise `h2` rồi `http/1.1`.
- Test: `openssl s_client -connect localhost:9527 -tls1_2` khi config 1.3 → connection refused.

### H2. Security headers (mở rộng `crates/waf-api/src/security.rs::security_headers_middleware`)

Hiện tại đã có HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, CSP. **Bổ sung/sửa:**

| Header | Giá trị mới |
|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` (2 năm) |
| `Content-Security-Policy` | giữ `default-src 'self'` + thêm `; upgrade-insecure-requests; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cross-Origin-Resource-Policy` | `same-origin` |
| `Cross-Origin-Embedder-Policy` | `require-corp` (chỉ apply cho `/ui/*`, không apply `/api/*` vì có thể block CORS calls; điều kiện hóa qua path) |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=(), payment=()` |

**Chỉ apply HSTS khi response đến từ TLS listener** — kiểm tra qua extension hoặc đơn giản: nếu `config.tls.enabled` thì luôn add (an toàn vì HTTP redirect 301 ngay).

### H3. Cache control cho `/api/*`
Thêm middleware: với mọi response path bắt đầu bằng `/api/`, set:
```
Cache-Control: no-store, no-cache, must-revalidate, private
Pragma: no-cache
Expires: 0
```
Lý do: chống cache JWT/admin data ở proxy trung gian. Apply qua tower layer.

### H4. CORS tightening
File: `crates/waf-api/src/server.rs::build_router`.

Hiện tại: nếu `cors_origins` rỗng → `Any` (insecure). 

**Đổi mặc định:**
- Nếu rỗng và đang ở HTTPS mode → CORS chỉ allow same-origin (axum-extra `same-origin`). Cụ thể: dùng `AllowOrigin::predicate` reject nếu `Origin` header khác `Host` header.
- Nếu rỗng và `tls.enabled = false` → giữ `Any` cho dev (nhưng log WARN).
- Nếu có list → giữ behavior cũ.

### H5. Request size limit
Áp dụng `tower_http::limit::RequestBodyLimitLayer` toàn router với giá trị từ `security.max_request_body_bytes`. Đã có config nhưng chưa wire.

```rust
let body_limit = state.security_config.max_request_body_bytes as usize;
Router::new()
    .merge(...)
    .layer(tower_http::limit::RequestBodyLimitLayer::new(body_limit))
    ...
```

### H6. Login endpoint hardening
- Đảm bảo `login_rate_limiter` đã wire vào `/api/auth/login` (verify trong code hiện tại — nếu chưa, thêm middleware riêng).
- Add timing-attack mitigation: nếu username không tồn tại, **vẫn run argon2 verify** trên một dummy hash (fixed constant) để equalize timing. Pattern phổ biến — implement trong `auth.rs::login_handler`.
- Log failure (chỉ `username` + IP, **không** log password) qua tracing.

### H7. Request-ID correlation
Middleware mới: nếu request thiếu `X-Request-Id`, generate `uuid::Uuid::new_v4().simple().to_string()`. Add vào response. Lưu vào `req.extensions_mut()` để các handler có thể log với cùng id.

### H8. Frontend axios layer
File: `web/admin-panel/src/utils/axios.ts`.

- Thêm interceptor request: gắn `X-Request-Id: ${crypto.randomUUID()}` mỗi request. Server bypass generation nếu đã có header.
- Thêm `withCredentials: false` rõ ràng (đang dùng Bearer trong localStorage, không cần cookie).
- Tăng timeout cho heavy endpoints (stats, geo) qua `meta.timeout` per call — pattern hiện tại OK; không sửa logic.
- Thêm response interceptor: nếu `err.response?.status === 403 && err.response?.data?.error?.includes("TLS")` → friendly toast "Vui lòng truy cập qua HTTPS"; không tự reload.

### H9. Vite dev proxy (chỉ ảnh hưởng dev workflow)
File: `web/admin-panel/vite.config.ts`.

```ts
import fs from "node:fs";
// ...
server: {
  port: 5174,
  proxy: {
    "/api": {
      target: "https://localhost:9527",
      changeOrigin: true,
      secure: false, // accept self-signed in dev
    },
    "/ws": {
      target: "wss://localhost:9527",
      ws: true,
      secure: false,
    },
  },
},
```
Tài liệu hóa trong comment ở đầu file: dev backend phải chạy HTTPS hoặc bật `[api.tls] enabled = false`.

---

## 5. Plan triển khai theo Phase

Thực hiện theo thứ tự dưới đây. Sau mỗi phase commit riêng (conventional commits theo §"Commit Style" trong code-safety-patterns.md).

### Phase 1 — Config schema (no behavior change)
- [ ] Thêm `AdminTlsConfig`, `AdminTlsMode`, validate functions vào `crates/waf-common/src/config.rs`
- [ ] Thêm test parse TOML cho 4 case: missing block, `enabled=false`, `mode=auto`, `mode=provided`
- [ ] Update `configs/default.toml` thêm section `[api.tls]` (full commented form)
- Commit: `feat(waf-common): add AdminTlsConfig schema for admin API HTTPS`

### Phase 2 — TLS module (pure, no server wiring)
- [ ] Thêm dep `axum-server` (feature `tls-rustls`), `time` (đã có), confirm `rcgen` reachable từ `waf-api` (re-export hoặc add direct dep — direct dep sạch hơn)
- [ ] Tạo `crates/waf-api/src/tls.rs` với 100% functions ở §3.2 + §3.3
- [ ] Unit tests:
  - `generate_produces_parseable_cert`
  - `load_then_reload_roundtrip` (write to tempdir, read back, fingerprint match)
  - `renewal_due_when_within_window`
  - `san_resolver_includes_listen_ip_and_hostname`
  - `resolver_swap_returns_new_cert` (cert resolver test)
  - `provided_mode_missing_paths_returns_error`
  - `auto_mode_creates_data_dir_with_0700` (Unix only, `#[cfg(unix)]`)
- Commit: `feat(waf-api): add admin TLS material manager with auto-rotation`

### Phase 3 — Server wiring
- [ ] Refactor `start_api_server` per §3.4
- [ ] Implement `spawn_http_redirect` trong `tls.rs`: axum router 1-route 301 đơn giản, bind port redirect, log `INFO` khi bind thành công, `WARN` khi fail (không panic — redirect là optional)
- [ ] Update `crates/prx-waf/src/main.rs` để truyền `&config.api` thay vì chỉ `listen_addr`
- [ ] Cập nhật module pub trong `crates/waf-api/src/lib.rs`: `pub mod tls;`
- [ ] Smoke test thủ công: `cargo run -- run` → `curl -kI https://localhost:9527/health`
- Commit: `feat(waf-api): serve admin API over HTTPS with embedded self-signed cert`

### Phase 4 — Hardening middlewares
- [ ] Update `crates/waf-api/src/security.rs::security_headers_middleware` per H2
- [ ] Add `cache_control_middleware` cho `/api/*` per H3
- [ ] Tighten CORS per H4 trong `build_router`
- [ ] Wire `RequestBodyLimitLayer` per H5
- [ ] Add `request_id_middleware` per H7
- [ ] Update `login` handler timing equalization per H6
- [ ] Update các unit tests trong `security.rs` cho header value mới
- [ ] Add test cho cache-control: hit `/api/health-mock` (hoặc bất kỳ /api/* path) phải có `cache-control: no-store, ...`
- Commit: `feat(waf-api): harden admin transport (HSTS, COOP/CORP, body limit, request-id)`

### Phase 5 — Frontend & dev workflow
- [ ] Update `web/admin-panel/src/utils/axios.ts` per H8
- [ ] Update `web/admin-panel/vite.config.ts` per H9
- [ ] Update doc string ở đầu vite.config.ts
- Commit: `feat(admin-panel): point dev proxy at HTTPS backend, propagate X-Request-Id`

### Phase 6 — CLI subcommands
- [ ] Thêm `AdminTlsCommands` enum trong `crates/prx-waf/src/main.rs`:
  - `prx-waf admin-tls info` — in path, fingerprint, not_before, not_after, SANs
  - `prx-waf admin-tls regenerate` — force regen ngay (chỉ Auto mode)
  - `prx-waf admin-tls export-ca` — dump CA cert ra stdout (hữu ích để import vào browser trust store)
- [ ] Subcommand handler đọc config, gọi `AdminTlsManager::bootstrap` với `force_regenerate` flag hoặc đọc metadata file
- Commit: `feat(prx-waf): add admin-tls CLI subcommands for cert ops`

### Phase 7 — Docker & docs
- [ ] Update `Dockerfile`: không thay đổi build (rcgen đã trong tree), nhưng đảm bảo `RUN mkdir -p /var/lib/prx-waf/admin-tls && chown ...` nếu chạy non-root
- [ ] Update `docker-compose.yml`:
  - `healthcheck.test`: `curl -sfk https://localhost:9527/health || exit 1` (thêm `-k`)
  - Mount volume `waf_admin_tls:/var/lib/prx-waf/admin-tls`
  - Thêm `waf_admin_tls:` vào top-level `volumes:`
- [ ] Update `configs/default.toml` với block `[api.tls]` full options + comment giải thích
- [ ] Update `README.md` section "Configuration" + "Health probe": dùng `https://` và `-k`
- [ ] Update `docs/deployment-guide.md` thêm section "Admin TLS" + "Importing the admin CA into your browser"
- Commit: `docs: update deployment docs for HTTPS-by-default admin panel`

### Phase 8 — Integration test
- [ ] Tạo `crates/waf-api/tests/admin_tls_integration.rs`:
  - Bind ephemeral port (`std::net::TcpListener::bind("127.0.0.1:0")` rồi drop để lấy port)
  - Boot full API với config Auto mode → mở reqwest client với `danger_accept_invalid_certs(true)` → GET `/health` → assert 200
  - Test HTTP→HTTPS redirect: hit HTTP port → expect 301 với `Location: https://...`
  - Test `min_tls_version = "1.3"`: client với `min_protocol_version(rustls::version::TLS12)` MAX only → expect connection error
- Commit: `test(waf-api): integration tests for admin HTTPS bootstrap`

---

## 6. File checklist

| File | Hành động |
|------|-----------|
| `crates/waf-common/src/config.rs` | + `AdminTlsConfig`, `AdminTlsMode`, defaults, validate |
| `crates/waf-api/Cargo.toml` | + `axum-server = { version = "0.7", features = ["tls-rustls"] }`, + `rcgen` (nếu chưa direct), + `time`, + `arc-swap` |
| `crates/waf-api/src/lib.rs` | + `pub mod tls;` |
| `crates/waf-api/src/tls.rs` | **NEW** — toàn bộ TLS lifecycle |
| `crates/waf-api/src/server.rs` | Refactor `start_api_server` chữ ký nhận `&ApiConfig`; wire `RequestBodyLimitLayer`; tighten CORS; add `cache_control_middleware`, `request_id_middleware` |
| `crates/waf-api/src/security.rs` | Update header values per H2; add `cache_control_middleware`, `request_id_middleware`; cập nhật tests |
| `crates/waf-api/src/auth.rs` | Timing equalization trong `login` handler |
| `crates/waf-api/build.rs` | KHÔNG đổi (placeholder dist vẫn giữ) |
| `crates/waf-api/tests/admin_tls_integration.rs` | **NEW** |
| `crates/prx-waf/src/main.rs` | Đổi call site `start_api_server(&api_cfg, api_state_bg)`; thêm `AdminTlsCommands` enum và handler |
| `configs/default.toml` | + section `[api.tls]` (commented full form + sane defaults) |
| `web/admin-panel/vite.config.ts` | proxy → `https://`/`wss://` + `secure: false` |
| `web/admin-panel/src/utils/axios.ts` | + `X-Request-Id` interceptor, + `withCredentials: false` |
| `docker-compose.yml` | healthcheck `-k`, + volume `waf_admin_tls` |
| `Dockerfile` | (optional) `RUN mkdir -p /var/lib/prx-waf/admin-tls` |
| `README.md` | URL `https://`, healthcheck `-k`, mention auto-cert |
| `docs/deployment-guide.md` | + "Admin TLS" section |
| `CHANGELOG.md` | + entry under `Added` + `Changed` (breaking: admin URL scheme) |

---

## 7. Non-functional requirements

- **Performance:** HTTPS overhead phải < 5ms p99 trên `/health` so với HTTP plaintext (ed25519 + TLS 1.3 negotiation rất nhẹ — không phải overhead thực, chỉ cần kiểm tra không có regression do bad implementation).
- **Memory:** Renewal worker idle < 1MB. `Arc<CertifiedKey>` swap không leak.
- **Startup time:** Auto-gen cert lần đầu thêm < 200ms (ed25519 cực nhanh).
- **No new unsafe code.** Nếu cần `unsafe`, phải có `// SAFETY:` comment đầy đủ per code-safety-patterns.md §"Unsafe Code". Không có chỗ nào trong design này cần unsafe.
- **No new dependencies có OpenSSL.** `axum-server`'s `tls-rustls` feature đảm bảo điều này. Verify qua `cargo deny check bans` — `openssl` đã bị deny.

---

## 8. Logging (theo code-safety-patterns.md §"No Secret Logging")

| Sự kiện | Level | Fields |
|---|---|---|
| Bootstrap auto-gen new cert | `INFO` | `data_dir`, `fingerprint_sha256`, `not_after`, `sans` |
| Bootstrap reuse existing cert | `INFO` | `data_dir`, `fingerprint_sha256`, `not_after`, `days_until_renewal` |
| Cert renewal triggered | `INFO` | `old_fingerprint`, `new_fingerprint`, `not_after` |
| HTTP redirect listener bound | `INFO` | `redirect_addr`, `target_https_addr` |
| HTTP redirect listener failed | `WARN` | `error` (no panic — chỉ disable redirect) |
| Plaintext fallback (TLS disabled) | `WARN` (mỗi 60s lặp lại) | `listen_addr` |
| Login failure | `WARN` | `username` (truncate 32 chars), `client_ip`, `reason` (KHÔNG password) |
| Provided cert load failure | `ERROR` then `bail!` | `cert_path`, `error` |

**Cấm tuyệt đối log:**
- Nội dung `key_pem` hoặc `key_pem` path content
- JWT (access_token, refresh_token) raw value
- Password plaintext hoặc Argon2 hash
- Authorization header raw value

---

## 9. Tests (chi tiết)

### 9.1 Unit (cargo test -p waf-api)

```rust
#[tokio::test]
async fn admin_tls_auto_mode_generates_and_persists() { /* tempdir, bootstrap, check files, fingerprint */ }

#[tokio::test]
async fn admin_tls_reuse_on_second_boot() { /* bootstrap, drop, bootstrap again, fingerprint equals */ }

#[tokio::test]
async fn admin_tls_renews_when_within_window() { /* generate validity=2, renew_before=3 → must regenerate */ }

#[tokio::test]
async fn admin_tls_san_drift_triggers_regenerate() { /* metadata SANs ≠ resolved SANs → regenerate */ }

#[tokio::test]
async fn admin_tls_provided_mode_missing_paths_errors() { /* mode=Provided, paths=None → bail */ }

#[tokio::test]
async fn admin_cert_resolver_swap_atomic() { /* swap from resolver thread while another reads */ }

#[test]
fn admin_tls_config_validate_rejects_invalid_tls_version() { /* "1.0" → Err */ }

#[test]
fn admin_tls_config_validate_rejects_provided_without_paths() { /* mode=Provided + cert_pem=None → Err */ }
```

### 9.2 Security middleware (extend existing security.rs tests)

```rust
#[tokio::test]
async fn hsts_header_value_is_two_years_with_preload() { /* assert exact value */ }

#[tokio::test]
async fn cache_control_no_store_on_api_paths() { /* hit /api/test → cache-control set */ }

#[tokio::test]
async fn cache_control_absent_on_ui_paths() { /* hit /ui/index.html → no cache-control override */ }

#[tokio::test]
async fn request_id_generated_when_missing() { /* no X-Request-Id in → response has X-Request-Id */ }

#[tokio::test]
async fn request_id_propagated_when_provided() { /* X-Request-Id: abc → response X-Request-Id: abc */ }

#[tokio::test]
async fn cors_same_origin_predicate_blocks_cross_origin() { /* Origin: https://evil.test → not in allow-origin */ }

#[tokio::test]
async fn body_limit_enforced() { /* POST 11MB to /api/anything with limit=10MB → 413 */ }
```

### 9.3 Integration (`crates/waf-api/tests/admin_tls_integration.rs`)

Tham khảo pattern `crates/waf-cluster/tests/cluster_integration.rs` (đã có sẵn dùng ephemeral port + reqwest).

```rust
#[tokio::test]
async fn end_to_end_https_health_check() {
    install_ring_provider_once();
    let port = pick_ephemeral_port();
    let cfg = build_test_app_config(port);
    let handle = tokio::spawn(async move { start_api_server(&cfg.api, app_state).await });

    // Wait for bind (poll with timeout)
    wait_for_https_ready(port).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build().unwrap();
    let resp = client.get(format!("https://127.0.0.1:{port}/health")).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().contains_key("strict-transport-security"));

    handle.abort();
}

#[tokio::test]
async fn http_port_redirects_to_https() { /* hit redirect port → 301 → Location starts with https:// */ }

#[tokio::test]
async fn tls13_only_rejects_tls12_client() { /* config min=1.3, client max=1.2 → connect error */ }
```

### 9.4 E2E (cluster test runner đã có)
- Sửa `tests/e2e-cluster.sh` để dùng `https://` cho API checks (xem `cluster-guide.md` §"Run the end-to-end test"). Thêm `--insecure` cho curl.

---

## 10. Decisions & rationale (ghi trong PR description)

1. **Tại sao không bake cert vào binary?**
   - Nếu bake → mọi instance có cùng private key → trivial MITM. Auto-gen at first run + persist là pattern đúng (giống cluster `auto_generate` mode trong `cluster-guide.md`).
2. **Tại sao Ed25519 thay vì RSA?**
   - Đồng bộ với `crates/waf-cluster/src/crypto/ca.rs` (đã dùng `PKCS_ED25519`). Cert nhỏ hơn, sign/verify nhanh hơn, không có CVE history. Browser hiện đại (Chrome ≥98, Firefox ≥97, Safari ≥16.4) đều support.
3. **Tại sao `axum-server` thay vì custom hyper + rustls?**
   - Tránh tự viết accept loop + giữ tương thích với `axum::serve` semantics. Đã production-ready, maintained, không có OpenSSL.
4. **Tại sao không bắt buộc client cert mTLS?**
   - Out of scope — sẽ làm follow-up. JWT + IP allowlist + rate limit + HTTPS đã đủ cho v1.
5. **Tại sao localStorage thay vì HttpOnly cookie?**
   - Giữ behavior cũ để không phải refactor auth flow. **Theo dõi:** HttpOnly cookie + SameSite=Strict + CSRF token là follow-up bắt buộc nếu khách hàng cần phòng XSS token theft (XSS hiện được giảm thiểu mạnh qua CSP `default-src 'self'` + không có inline script).
6. **Tại sao default `min_tls_version = "1.2"` mà không phải "1.3"?**
   - Để tránh breaking trên các môi trường legacy (corporate proxies, older curl). Khuyến nghị production trong docs.

---

## 11. Acceptance test commands (chạy thủ công sau khi merge)

```bash
# Build
cd web/admin-panel && npm ci && npm run build && cd ../..
cargo build --release

# Run (sạch state)
rm -rf data/admin-tls && ./target/release/prx-waf -c configs/default.toml run &
SERVER_PID=$!
sleep 2

# G1: HTTPS works
curl -kI https://127.0.0.1:9527/health | grep -i "strict-transport-security"
curl -kI https://127.0.0.1:9527/health | grep -i "HTTP/2 200"

# G2: Persistence
FP1=$(./target/release/prx-waf -c configs/default.toml admin-tls info | grep fingerprint)
kill $SERVER_PID; sleep 1
./target/release/prx-waf -c configs/default.toml run &
SERVER_PID=$!
sleep 2
FP2=$(./target/release/prx-waf -c configs/default.toml admin-tls info | grep fingerprint)
test "$FP1" = "$FP2"  # must be equal

# G4 / H3: cache-control on /api
TOKEN=$(curl -sk https://127.0.0.1:9527/api/auth/login -d '{"username":"admin","password":"admin123"}' -H 'Content-Type: application/json' | jq -r .data.access_token)
curl -skI -H "Authorization: Bearer $TOKEN" https://127.0.0.1:9527/api/hosts | grep -i "cache-control: no-store"

# G4 / H2: COOP header
curl -skI https://127.0.0.1:9527/ui/ | grep -i "cross-origin-opener-policy: same-origin"

# G4 / H4: CORS reject cross-origin
curl -skI -H "Origin: https://evil.test" https://127.0.0.1:9527/api/hosts | grep -v "access-control-allow-origin: https://evil.test"

# G4 / H5: body limit
dd if=/dev/zero bs=1M count=20 2>/dev/null | curl -sk -X POST -H "Authorization: Bearer $TOKEN" --data-binary @- https://127.0.0.1:9527/api/rules/import -w "%{http_code}\n" -o /dev/null
# Expect: 413

kill $SERVER_PID
```

---

## 12. Definition of Done

- [ ] Tất cả `cargo fmt --all -- --check` pass
- [ ] Tất cả `cargo clippy --workspace --all-targets -- -D warnings` pass
- [ ] Tất cả `cargo test --all` pass (Linux x86_64)
- [ ] `cargo deny check` pass (đặc biệt không add transitive OpenSSL)
- [ ] Không có `unwrap()`, `expect()`, `panic!()`, `todo!()`, `unimplemented!()` trong code mới của `src/`
- [ ] Không có `println!`/`eprintln!` trong code mới (dùng `tracing`)
- [ ] Test e2e thủ công ở §11 chạy được trên một máy sạch
- [ ] PR description ghi:
  - Breaking change note (URL admin panel đổi sang `https://`)
  - Migration guide cho ops (import CA, healthcheck `-k`)
  - Reference issue/spec
  - Conformance results: `cargo test` + smoke test commands
- [ ] `CHANGELOG.md` updated dưới `[Unreleased]` với entry `### Added — Admin API now serves over HTTPS by default with auto-generated self-signed certificates`
- [ ] Vite dev mode đã verified chạy được (manual)
- [ ] Tài liệu `docs/deployment-guide.md` có section "Admin TLS" hoàn chỉnh + screenshot import CA vào Chrome/Firefox (optional)

---

## 13. Lưu ý vận hành cho người review/operator

1. **Lần boot đầu sau upgrade:** Cert mới sẽ được sinh tự động. Browser sẽ cảnh báo "Not secure" (đúng bản chất self-signed). Có 3 lựa chọn cho ops:
   - Accept exception trong browser (phù hợp single admin nội bộ).
   - Export CA: `prx-waf admin-tls export-ca > admin-ca.pem` → import vào trust store của hệ điều hành / browser.
   - Đổi sang `mode = "provided"` với cert do PKI nội bộ ký (best practice production).
2. **Backups:** `data_dir/admin-tls/` chứa private key — phải nằm trong scope backup nhưng **mã hóa at-rest** (filesystem encryption hoặc volume snapshot encryption).
3. **Cluster mode:** Khác hoàn toàn với cluster CA (port 16851, mTLS QUIC) — admin TLS là một subsystem độc lập. Không tái sử dụng `cluster-ca.pem`.

---

## 14. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| User boot lại nhiều container ephemeral → mỗi node có CA riêng → browser warning chồng chất | Khuyến nghị `mode = "provided"` với cert nội bộ trong production; document rõ |
| Renewal task chết im lặng | Spawn task có log `ERROR` mỗi lần fail; healthcheck endpoint `/health` expose `days_until_renewal` |
| `0.0.0.0` listen + cert chỉ SAN `localhost` → cert mismatch khi truy cập qua IP | `resolve_sans` tự thêm hostname + listen IP (kể cả `0.0.0.0` → mở rộng thành tất cả interface IPs qua `if-addrs` crate hoặc skip — document trade-off) |
| Multi-replica behind L4 LB → mỗi replica self-signed khác nhau, browser flap | Production phải dùng `mode = "provided"` + shared cert hoặc terminate TLS ở LB |
| Time skew → cert `not_before` ở future → rustls reject | `not_before = now - 60s` để absorb skew nhỏ |

---

## 15. Reference snippets

### resolve_sans (handle 0.0.0.0 / [::])

```rust
fn resolve_sans(listen_addr: SocketAddr, extras: &[String]) -> Vec<String> {
    let mut out: Vec<String> = extras.iter().cloned().collect();

    // hostname
    if let Ok(host) = hostname::get()
        && let Some(s) = host.to_str()
        && !s.is_empty()
    {
        out.push(s.to_owned());
    }

    let ip = listen_addr.ip();
    if ip.is_unspecified() {
        // expand 0.0.0.0 / :: to all known interface IPs (best-effort)
        if let Ok(addrs) = if_addrs::get_if_addrs() {
            for a in addrs {
                let s = a.ip().to_string();
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
    } else {
        let s = ip.to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }

    out.sort();
    out.dedup();
    out
}
```

> `hostname` (0.4) và `if-addrs` (0.13) là pure-Rust, no-OpenSSL. Confirm với `cargo deny` trước khi add.

### generate (Ed25519 self-signed)

```rust
fn generate(sans: &[String], validity_days: u32) -> Result<(String, String, OffsetDateTime)> {
    let key = KeyPair::generate_for(&PKCS_ED25519)
        .context("ed25519 keypair generation")?;

    let mut params = CertificateParams::new(sans.to_vec())
        .context("invalid SAN list for admin cert")?;

    params.not_before = OffsetDateTime::now_utc() - time::Duration::seconds(60);
    let not_after = OffsetDateTime::now_utc() + time::Duration::days(i64::from(validity_days));
    params.not_after = not_after;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "prx-waf admin");
    dn.push(DnType::OrganizationName, "prx-waf");
    params.distinguished_name = dn;

    let cert = params.self_signed(&key)
        .context("self-sign admin cert")?;

    Ok((cert.pem(), key.serialize_pem(), not_after))
}
```

### build_rustls_server_config

```rust
pub fn build_server_config(
    material: &AdminTlsMaterial,
    min_tls: &str,
) -> Result<Arc<ServerConfig>> {
    let resolver = Arc::new(AdminCertResolver::new(material)?);

    let versions: &[&'static rustls::SupportedProtocolVersion] = match min_tls {
        "1.3" => &[&version::TLS13],
        "1.2" => &[&version::TLS12, &version::TLS13],
        other => bail!("unsupported min_tls_version: {other}"),
    };

    let mut cfg = ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(cfg))
}
```

---

## 16. Câu hỏi clarification (hỏi user trước khi code nếu không rõ)

- [ ] `data_dir` mặc định nên là `/var/lib/prx-waf/admin-tls` (Linux FHS) hay `<geoip.data_dir>/admin-tls`? → Mặc định bài này chọn **fallback chain**: `config.tls.data_dir` → `<geoip.data_dir>/admin-tls` → `/var/lib/prx-waf/admin-tls`.
- [ ] Có cần expose endpoint `/api/admin/tls/info` (auth-protected) để Admin UI hiển thị fingerprint + ngày hết hạn không? → Khuyến nghị có, nhưng để **Phase 6 follow-up** vì cần thêm UI panel; PR này chỉ expose qua CLI.

---

**END OF PROMPT.** Cursor: thực hiện theo thứ tự Phase 1 → 8. Mỗi Phase tạo commit riêng. Trước khi mở PR, chạy đủ §12 Definition of Done.
