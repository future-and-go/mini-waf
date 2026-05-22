---
phase: 2
title: "DbCertResolver + cache hydration + SslManager wire main.rs"
status: pending
priority: P1
effort: "3d"
dependencies: [1]
---

# Phase 02: DbCertResolver + cache hydration + SslManager wire

## Overview

Implement `DbCertResolver` (rustls `ResolvesServerCert` impl) backed bởi in-memory `DashMap<String, Arc<CertifiedKey>>`. Extend `SslManager` để own shared cache. Wire `SslManager` + `DbCertResolver` vào `crates/prx-waf/src/main.rs::run_server`. Mini-waf binary bind listener TLS (port 443) qua `TlsSettings::with_cert_resolver` (constructor mới từ phase 01). Cert lookup từ DB qua resolver per-SNI. Phase này KHÔNG include ACME (giữ upload PEM path only).

## Requirements

### Functional
- `DbCertResolver` impl `rustls::server::ResolvesServerCert::resolve(ClientHello) -> Option<Arc<CertifiedKey>>`
- `SslManager` thêm field `cache: Arc<DashMap<String, Arc<CertifiedKey>>>`
- `SslManager::hydrate_cache()` query `SELECT * FROM certificates WHERE status='active' AND not_after > now()` → parse PEM → build `CertifiedKey` → insert cache. **Must complete `await` BEFORE Pingora `Server::run_forever` binds listener** (block startup nếu chưa xong).
- **Fail-fast threshold (red-team C4)**: nếu DB query trả ≥1 row nhưng `hydrate_cache` load 0 cert thành công → bail startup với error `"All N certificates failed to parse, refusing to start TLS listener"`. Empty DB (0 row) thì OK warn-and-continue.
- **Per-host `tls_terminate` gate (red-team C2)**: `DbCertResolver` chỉ trả `Some(cert)` cho SNI thuộc danh sách hosts có `tls_terminate=true` trong config TOML. Resolver constructor nhận `Arc<HashSet<String>>` allowlist. Hosts có `tls_terminate=false` → resolver trả None bất kể cert có trong cache (preserve PR #93 fix orthogonality).
- `SslManager::invalidate(&str)` remove domain khỏi cache
- `SslManager::reload_cert(Uuid)` reload từ DB cho 1 cert id
- `SslManager::spawn_cache_refresh_task(60s)` background poll PG + emit `last_successful_refresh_at` gauge để observability (phase 06 wire Prometheus)
- mini-waf binary listen TLS:443 wire qua TlsSettings + resolver
- TOML `HostEntry.cert_file`/`key_file` deprecated với startup warning nếu set, KHÔNG load
- API `POST /api/certificates/{id}/reload` mới — trigger reload cache cho 1 cert. **Handler MUST return 503 "TLS not configured" khi `AppState.ssl_manager.is_none()`, never `.unwrap()` (Iron Rule 1)**
- API endpoint `POST /api/certificates` extend invalidate khi insert/update — nhưng **KHÔNG expose ACME issue path (`request_certificate`) ở phase 02 nữa**. Existing handler chỉ accept upload PEM. ACME issue API ship phase 03.
- `tls.acme_email` config field là `Option<String>` (KHÔNG required ở phase 02 — operator chỉ cần upload PEM, chưa cần ACME)

### Non-functional
- Cache lookup hot path < 1µs (DashMap lock-free)
- 50 hosts × ~5KB `CertifiedKey` ≈ 250KB RAM
- SNI null case → return None (reject handshake)
- PEM parse error tại startup → log error + skip cert (degrade gracefully)
- KHÔNG block I/O trong `resolve()` hot path

## Architecture

```
crates/gateway/src/ssl/
├── mod.rs                      (existing ssl.rs renamed thành module dir)
├── manager.rs                  (existing SslManager logic)
└── resolver.rs                 (NEW — DbCertResolver)

DbCertResolver {
    cache: Arc<DashMap<String, Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for DbCertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?.to_ascii_lowercase();
        self.cache.get(&sni).map(|v| Arc::clone(v.value()))
    }
}

SslManager {
    db: Arc<Database>,
    challenges: Arc<ChallengeStore>,                      // existing, ACME phase 03 wire
    acme_email: String,
    acme_staging: bool,
    cache: Arc<DashMap<String, Arc<CertifiedKey>>>,       // NEW shared với resolver
}

impl SslManager {
    pub fn cache_handle(&self) -> Arc<DashMap<...>> { Arc::clone(&self.cache) }
    pub async fn hydrate_cache(&self) -> Result<usize>;
    pub async fn invalidate(&self, domain: &str);
    pub async fn reload_cert(&self, cert_id: Uuid) -> Result<()>;
    pub fn spawn_cache_refresh_task(self: Arc<Self>, interval_secs: u64) -> tokio::task::JoinHandle<()>;
}
```

### Wire trong `prx-waf/src/main.rs::run_server`

```rust
// Sau init_async, trước proxy_service construction:
let ssl_mgr = Arc::new(SslManager::new(
    Arc::clone(&db),
    &config.tls.acme_email,
    config.tls.acme_staging,
));
ssl_mgr.hydrate_cache().await?;
Arc::clone(&ssl_mgr).spawn_cache_refresh_task(60);

// Wire vào AppState để API/CLI gọi
api_state.ssl_manager = Some(Arc::clone(&ssl_mgr));

// TLS listener:
let resolver: Arc<dyn ResolvesServerCert> = Arc::new(DbCertResolver::new(ssl_mgr.cache_handle()));
let mut tls_settings = TlsSettings::with_cert_resolver(resolver)?;
tls_settings.enable_h2();
proxy_service.add_tls_with_settings(&config.proxy.listen_addr_tls, None, tls_settings)?;
```

### Build `CertifiedKey` từ PEM

```rust
fn build_certified_key(cert_pem: &str, key_pem: &str) -> Result<Arc<CertifiedKey>> {
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<_, _>>()?;
    let key_der = rustls_pemfile::private_key(&mut key_pem.as_bytes())?
        .ok_or_else(|| anyhow!("no private key"))?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}
```

## Related Code Files

### Create
- `crates/gateway/src/ssl/resolver.rs` — `DbCertResolver` struct + impl
- `crates/gateway/src/ssl/build_certified_key.rs` — PEM → `CertifiedKey` helper

### Modify
- `crates/gateway/src/ssl.rs` → split thành `crates/gateway/src/ssl/mod.rs` + `manager.rs` (preserve all existing logic)
- `crates/gateway/src/lib.rs` — pub use new items
- `crates/prx-waf/src/main.rs::run_server` — wire SslManager + DbCertResolver + TLS listener
- `crates/waf-common/src/config.rs` — add `tls.acme_email`, `tls.acme_staging`, `proxy.listen_addr_tls` fields
- `configs/default.toml` — example new `[tls]` section
- `crates/waf-api/src/handlers.rs` — POST `/api/certificates/{id}/reload` handler
- `crates/waf-api/src/state.rs` — `AppState` thêm `ssl_manager: Option<Arc<SslManager>>` field
- `crates/waf-common/src/config.rs::HostEntry` — log deprecation warning khi `cert_file`/`key_file` set

### Reference (no edit)
- `vendor/pingora/pingora-core/src/listeners/tls/rustls/mod.rs` — TlsSettings from phase 01

## Implementation Steps

1. Split `crates/gateway/src/ssl.rs` thành module dir `ssl/` với `mod.rs` + `manager.rs` (preserve mọi logic + tests).
2. Add `cache: Arc<DashMap<String, Arc<CertifiedKey>>>` field vào `SslManager`. Update `new()` init empty cache.
3. Implement `build_certified_key()` helper trong `ssl/build_certified_key.rs`.
4. Implement `SslManager::hydrate_cache()` — query DB, build `CertifiedKey` per row, insert cache. Log skip nếu parse fail.
5. Implement `SslManager::invalidate()` + `reload_cert()`.
6. Implement `spawn_cache_refresh_task()` — tokio interval 60s, scan DB for `updated_at > last_check`, reload changed.
7. Create `ssl/resolver.rs` — `DbCertResolver { cache }`, impl `ResolvesServerCert`. SNI normalization to_ascii_lowercase.
8. Add config fields trong `waf-common/src/config.rs`: `tls.acme_email`, `tls.acme_staging`, `proxy.listen_addr_tls`. Update `default.toml` example.
9. Wire vào `prx-waf::run_server`: init SslManager, hydrate, spawn refresh, build resolver, build TlsSettings, attach to proxy_service.
10. Add API `POST /api/certificates/{id}/reload` handler — call `ssl_mgr.reload_cert(id)`.
11. Add deprecation warning trong `init_async`: scan `config.hosts` for any `cert_file`/`key_file` set → `tracing::warn!`.
12. Update API `POST /api/certificates` (existing handler) — sau insert DB, call `ssl_mgr.reload_cert(new_id)`.
13. Build trong Docker rocky9 + rust 1.95 (per `summary.md §13` constraints).
14. **Cutover w/ rollback (red-team M4)**: trước khi swap, backup `cp /opt/mini-waf/bin/prx-waf /home/lotus/cutover-backup-$(date +%Y%m%d-%H%M%S)/` + `tar czf` `/etc/mini-waf/`, `/etc/nginx/`. Health-gate: nếu mini-waf không pass `curl https://mini-waf.../` trong 60s sau start → restore backup + restart nginx + abort.
15. Test diversity matrix (red-team M5): `nmap --script ssl-enum-ciphers -p 443` + `testssl.sh` baseline trước/sau cutover compare; verify TLS 1.2 compat client (Java 8, Android 7) hand-shake.
16. Live cutover VM Singapore: stop nginx, swap binary + config, start mini-waf. Run smoke §13.

## Success Criteria

- [ ] `DbCertResolver` impl `ResolvesServerCert`, SNI normalization lowercase
- [ ] `SslManager::hydrate_cache()` populate cache từ DB
- [ ] `SslManager::spawn_cache_refresh_task(60)` poll PG mỗi 60s, reload changed cert
- [ ] `POST /api/certificates/{id}/reload` invalidate + repopulate cache
- [ ] mini-waf bind listener 443 qua resolver
- [ ] TOML `cert_file`/`key_file` log warning, KHÔNG load
- [ ] Live VM Singapore: nginx stopped, mini-waf serve 443 trực tiếp
- [ ] Smoke test §13 summary.md pass: 3 happy + 3 WAF block + cert SAN check + handshake p99 < 800ms
- [ ] `cargo test -p gateway` xanh, `cargo check --all` xanh
- [ ] Coverage `crates/gateway/src/ssl/` ≥ 90% (rules.md)

## Risk Assessment

| Risk | Severity | Mitigation |
|---|---|---|
| Listener bind 443 break như PR #90 (ssl field overload, H2 host missing) | **High** | Re-check 2 bug đã fix trong PR #93 vẫn còn: (1) `tls_terminate` orthogonal với `ssl`, (2) `resolve_host_from_parts` đọc `:authority` cho H2. Test rằng cả 2 case work với resolver path. |
| Listener crash khi resolver return None (no cert match) | Med | rustls reject handshake với alert, client thấy `ERR_SSL_PROTOCOL_ERROR`. Log domain miss trong resolver. Document expected behavior. |
| PEM parse fail tại startup làm hydrate panic | Med | `hydrate_cache` skip bad rows + log error, không bail. Count return số cert loaded vs skipped. |
| Cache poll 60s lag với manual upload qua API | Low | API handler trigger `reload_cert` ngay sau insert/update DB. Phase 03 sẽ refine khi ACME wire. |
| Memory leak khi domain renamed (old entry sót lại) | Low | Phase 04 thêm `cleanup_stale_entries` task. Phase 02 chấp nhận grow-only. |
| Rocky9 + rust 1.95 Docker build chậm 11-13 min (per summary.md §13) | Low | Cache target/ qua bind mount. Document trong deployment-guide. |
| pingora `add_tls_with_settings` API surface đổi giữa version | Med | Pin pingora 0.8 + vendor fork. Compile test catches. |
| ChallengeStore phase 03 cần xài cùng SslManager → field positioning | Low | Add field at struct creation, phase 03 wire HTTP-01 filter. Forward-compat. |

## Verification gates

- `cargo test -p gateway` — xanh
- `cargo check --all --features gateway/valkey` — xanh
- `cargo llvm-cov -p gateway --ignore-filename-regex '...'` cho ssl/ ≥ 90%
- Live VM smoke §13 pass
- `curl -v https://mini-waf.ace-trail.com/` cert chain match DB, server header absent (no nginx)
- `openssl s_client -connect mini-waf.ace-trail.com:443 -servername mini-waf.ace-trail.com` SAN cert đúng

## References

- Research: [research/researcher-01-rustls-resolver-api.md](./research/researcher-01-rustls-resolver-api.md)
- summary.md §13 (native TLS cutover lessons learned, 2 bug PR #90)
- Phase 01 dependency: vendor patch must land first
