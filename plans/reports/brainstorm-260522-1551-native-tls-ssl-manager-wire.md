# Brainstorm — Native TLS / SSL Manager Wire (Issue #95)

**Date:** 2026-05-22
**Author:** Claude (brainstorm session)
**Status:** Design approved, ready for `/ck:plan` hard mode
**Source issue:** GitHub mini-waf #95 — "hoàn thành kiến trúc SSL/TLS gốc — wire SslManager + DB cert + ACME vào Pingora runtime"
**Scope target:** 1 node, ~50 hosts, no cluster (yet), production-ready, native theo intent tác giả

---

## 1. Problem Statement

Codebase đã có sẵn `SslManager` + ACME (instant-acme) + CSR (rcgen) + schema `certificates` + API `/api/certificates` + UI page Certificates. **Tất cả chưa wire vào Pingora runtime.** PR #96 đã rollback về nginx fronting làm TLS terminator vì PR #90 đi tắt (load cert từ TOML thay vì DB).

Mục tiêu: kill nginx, mini-waf tự terminate TLS, cert đọc từ DB qua rustls cert resolver, ACME tự issue + renew, đúng design gốc.

## 2. Requirements (Exact)

| Item | Concrete value |
|---|---|
| Expected output | mini-waf binary listen TLS:443, terminate per-SNI cert đọc từ PG `certificates` table, ACME HTTP-01 auto-issue/renew, UI Certificates có button "Request via ACME", CLI `prx-waf cert ...` |
| Acceptance | (a) 50 hosts mỗi host cert riêng, SNI resolver hit ≥99.9%; (b) ACME issue 1 cert end-to-end staging+production OK; (c) renewal task tự renew cert <30d expiry; (d) cache reload không drop connection; (e) HTTP-01 challenge filter bypass WAF rule engine; (f) backward-compat TOML `cert_file/key_file` với deprecation warning 1 release; (g) full smoke test §13 summary.md pass |
| Scope boundary OUT | Multi-cluster cert sync, DNS-01/wildcard, OCSP stapling, mTLS, PG column encryption, cert sharding, upstream PR pingora |
| Non-negotiable constraints | Rust 2024, rustls 0.23 ring (KHÔNG switch boringssl/aws-lc-rs), Pingora 0.8 vendored fork, instant-acme, sqlx, Postgres 18, LE production |
| Touchpoints | `vendor/pingora/pingora-core/src/listeners/tls/rustls/mod.rs`, `crates/gateway/src/ssl.rs`, `crates/gateway/src/lib.rs`, `crates/gateway/src/pipeline/request_filter_chain.rs`, `crates/prx-waf/src/main.rs`, `crates/waf-storage/migrations/`, `crates/waf-api/src/handlers.rs`, `web/admin-panel/src/pages/certificates/index.tsx`, `configs/default.toml` |

## 3. Decision — Path A (patch vendored pingora rustls + DbCertResolver)

Chọn Path A vì:

- **Native theo intent tác giả** = DB-backed cert serve + ACME automation + no-nginx. 4 path khả thi (A patch vendor, B file materialize, C custom listener, D boringssl flag) → A là cách duy nhất giữ rustls single stack + live per-SNI rotation + zero-downtime renew.
- **Vendor patch chi phí thấp** vì repo đã fork pingora cho FR-010. Researcher C xác nhận patch ~20 LOC enum-based `CertSource`, không đụng handshake code, backward-compat hoàn toàn. PR #632 thượng nguồn cloudflare/pingora dormant nhưng xác nhận đúng hướng.
- **Performance an toàn**: researcher A báo `resolve()` 100-500ns/connection với DashMap lock-free, 50 hosts ~150-200KB RAM cache. Ring crypto provider đã install sẵn ở `main.rs:294`.
- **ACME khả thi 50 hosts**: researcher B xác nhận LE production "300 new orders/account/3h" thoải mái cho 50 hosts. Bug `Account::create` mỗi lần fix bằng persist `AccountCredentials` JSON sang PG (~100 LOC), tránh "10 accounts/IP/3h" ratelimit.

### Tại sao không các path khác

| Path | Loại vì |
|---|---|
| B (DB→file + restart) | 50 hosts × ~100ms downtime/host khi xoay renew = ops nightmare; phá invariant "DB là source of truth" vì cert phải vật chất hoá ra disk |
| C (custom tokio+rustls listener pre-Pingora) | Re-implement HTTP/2 logic risky — PR #90 chỉ wire `add_tls_with_settings` đã ra 2 bug (ssl field overload, H2 host header) |
| D (boringssl feature flag) | h3-quinn vẫn rustls → 2 TLS stack song song, duplicate SNI logic, complexity drift |

## 4. Architecture — Component breakdown

### 4.1 Vendor patch (`vendor/pingora/pingora-core/src/listeners/tls/rustls/mod.rs`)

```rust
pub enum CertSource {
    StaticFiles { cert_path: String, key_path: String },
    Resolver(Arc<dyn ResolvesServerCert>),
}

pub struct TlsSettings {
    alpn_protocols: Option<Vec<Vec<u8>>>,
    cert_source: CertSource,
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
}

impl TlsSettings {
    pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self> { /* unchanged */ }
    pub fn with_cert_resolver(resolver: Arc<dyn ResolvesServerCert>) -> Result<Self> { /* new */ }
}

impl TlsSettings {
    pub fn build(self) -> Acceptor {
        // ...
        let config = match self.cert_source {
            CertSource::StaticFiles { cert_path, key_path } => {
                builder.with_single_cert(certs, key).explain_err(...)?
            }
            CertSource::Resolver(resolver) => {
                builder.with_cert_resolver(resolver)  // resolver Arc::clone OK
            }
        };
        // alpn + return Acceptor
    }
}
```

Plus 1 line trong `vendor/pingora/pingora-rustls/src/lib.rs` re-export `ResolvesServerCert` + `CertifiedKey`.

LOC delta ≤30. Single commit, không file `.patch`. Rebase manual khi upstream sync.

### 4.2 `DbCertResolver` (`crates/gateway/src/ssl/resolver.rs` — new file)

```rust
pub struct DbCertResolver {
    cache: Arc<DashMap<String, Arc<CertifiedKey>>>,
}

impl ResolvesServerCert for DbCertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = hello.server_name()?.to_ascii_lowercase();
        self.cache.get(&sni).map(|v| Arc::clone(v.value()))
    }
}
```

SNI null case → return None (reject handshake). Industry standard, tránh fingerprinting fallback cert.

Wildcard match defer phase wildcard (DNS-01).

### 4.3 SslManager extend (`crates/gateway/src/ssl.rs`)

```
+ pub struct SslManager {
+   db, acme_email, acme_staging,
+   challenges: Arc<ChallengeStore>,
+   cache: Arc<DashMap<String, Arc<CertifiedKey>>>,         // shared với DbCertResolver
+   acme_account: tokio::sync::OnceCell<Account>,            // persisted credentials
+   domain_locks: DashMap<String, Arc<tokio::sync::Mutex<()>>>,  // per-domain idempotency
+ }
+ async fn hydrate_cache(&self) -> Result<usize>
+ async fn invalidate(&self, domain: &str) -> Result<()>
+ async fn reload_cert(&self, cert_id: Uuid) -> Result<()>
+ async fn get_or_create_account(&self) -> Result<&Account>
```

### 4.4 ACME account persistence — migration mới

```sql
CREATE TABLE acme_accounts (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  server_url    TEXT NOT NULL,
  email         TEXT NOT NULL,
  credentials   TEXT NOT NULL,                  -- JSON từ instant-acme AccountCredentials, app-level chacha20-poly1305 encrypted
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at  TIMESTAMPTZ,
  UNIQUE (server_url, email)
);
```

Encryption key từ env `ACME_CREDENTIALS_KEY` (32 bytes hex). Reuse pattern từ `JWT_SECRET` env.

### 4.5 ACME HTTP-01 challenge filter

Inject vào `pipeline/request_filter_chain.rs` ở **EARLY position** (trước WAF rule engine, trước host policy):

```rust
// acme_challenge_filter (NEW)
const PREFIX: &str = "/.well-known/acme-challenge/";
if path.starts_with(PREFIX) {
    let token = &path[PREFIX.len()..];
    // Strict token validation: RFC 8555 token = base64url 43 chars
    if !is_valid_acme_token(token) {
        return respond(404, ...);
    }
    if let Some(key_auth) = ssl_mgr.challenges.get(token) {
        return respond(200, "text/plain", key_auth.as_bytes());  // body exact key_auth, no whitespace
    }
    return respond(404, ...);
}
```

Test phải include `/.well-known/acme-challenge/../../etc/passwd` không bypass.

### 4.6 ACME flow hardening (theo recommendation researcher B)

- **Pre-validation self-check**: trước khi `order.set_challenge_ready()`, `reqwest::get("http://127.0.0.1/.well-known/acme-challenge/{token}")` confirm body == key_authorization. Tránh LE validate trong khi endpoint chưa serve.
- **Per-domain Mutex** trong `domain_locks` (DashMap) — tránh 2 concurrent issue cùng domain.
- **Exponential backoff** trên Invalid order state: 5 retries với interval 5s → 10s → 20s → 40s → 80s.
- **Token cleanup** sau `Valid` HOẶC 10-minute timeout (tránh stuck Invalid orders giữ challenge mãi).
- **Polling interval**: 2s cho Pending→Ready (giữ nguyên hiện tại), max wait 60s.

### 4.7 Cache hydration & reload

- **Startup**: `SslManager::hydrate_cache()` query `SELECT * FROM certificates WHERE status='active' AND not_after > now()` → parse PEM → build `CertifiedKey` → populate cache.
- **Reload trigger**: poll PG mỗi 60s + explicit `POST /api/certificates/{id}/reload`.
- **Future**: PG LISTEN/NOTIFY khi multi-cluster (defer).
- **Failure mode**: PEM parse error → log error + skip cert (degrade gracefully, host vẫn serve các cert khác).

### 4.8 Wire vào `main.rs::run_server`

```
let ssl_mgr = Arc::new(SslManager::new(db.clone(), &config.tls.acme_email, config.tls.acme_staging));
ssl_mgr.hydrate_cache().await?;
Arc::clone(&ssl_mgr).spawn_renewal_task();              // daily check, renew <30d
Arc::clone(&ssl_mgr).spawn_cache_refresh_task(60);      // PG poll 60s

let resolver: Arc<dyn ResolvesServerCert> = Arc::new(DbCertResolver::new(ssl_mgr.cache_handle()));
let mut tls_settings = TlsSettings::with_cert_resolver(resolver)?;
tls_settings.enable_h2();                                // ALPN h2,http/1.1
proxy_service.add_tls_with_settings(&config.proxy.listen_addr_tls, None, tls_settings)?;
```

Wire `ssl_mgr` vào `AppState` để API/CLI gọi được.

### 4.9 API endpoints (extend)

| Method | Path | Body | Phase |
|---|---|---|---|
| POST | `/api/certificates` | PEM upload | 1 (extend invalidate) |
| POST | `/api/certificates/acme/issue` | `{host_code, domain}` | 2 |
| POST | `/api/certificates/{id}/renew` | force renew | 3 |
| POST | `/api/certificates/{id}/reload` | reload cache | 1 |
| GET | `/api/certificates/{id}/status` | expiry, last_renewal, ACME error msg | 4 |
| GET | `/health/certs` | certs <7d expiry list | 5 |

### 4.10 UI extend (`web/admin-panel/src/pages/certificates/`)

- Button **"Request via ACME"** modal: input domain + host code.
- Action **"Renew now"** per row.
- Column **"Expires in"** với badge warning <14d, danger <7d.
- Status indicator hiển thị ACME last error nếu renew fail.

### 4.11 CLI commands (`crates/prx-waf/src/main.rs`)

```
prx-waf cert list
prx-waf cert issue --host-code <code> --domain <fqdn> [--staging]
prx-waf cert upload --host-code <code> --domain <fqdn> --cert <path> --key <path>
prx-waf cert renew <cert-id>
prx-waf cert delete <cert-id>
prx-waf cert show <cert-id>
```

### 4.12 Observability + audit (phase cuối)

- **Prometheus gauge** `prx_waf_cert_expiry_seconds{domain}` — alert <14d.
- **Counter** `prx_waf_acme_requests_total{result}` (success/fail/ratelimit).
- **Audit table** `cert_audit_log` (event_type, cert_id, actor, timestamp, details).
- **Key zeroize**: `Drop` impl wipe PEM bytes khỏi RAM khi cert eviction.

### 4.13 Backward compat

- TOML `HostEntry.cert_file` / `key_file` → giữ field 1 release, log warning ở startup khi set, hint operator migrate.
- TOML `HostEntry.tls_terminate` → giữ nguyên (per-host opt-in flag, useful cho mixed HTTP+HTTPS hosts).
- HTTP-01 cert acquisition: SG/firewall mở port 80 PERMANENT từ `0.0.0.0/0`. Cập nhật `infra/cloudformation/mini-waf-other-test.yaml`.

## 5. Phase breakdown (6 phase, 6 PR squashed)

| # | Scope | LOC | Risk | Verify |
|---|---|---|---|---|
| 0 | Vendor patch `TlsSettings::with_cert_resolver` + re-export `ResolvesServerCert` + vendor unit test | ~80 | Low | `cargo test -p pingora-core` xanh trong vendor workspace |
| 1 | `DbCertResolver` + cache hydration + SslManager wire (upload PEM path only, no ACME) + listener bind 443 | ~400 | **Med** — listener bind đã từng break trong PR #90 | Live cutover VM Singapore, smoke §13 |
| 2 | `acme_accounts` migration + persist + ACME HTTP-01 filter + `/api/certificates/acme/issue` + pre-validation self-check | ~500 | Med — staging LE test mandatory | LE staging issue 1 cert end-to-end |
| 3 | Background renewal task + per-domain Mutex + exponential backoff + token cleanup timeout | ~250 | Low | Test renew với cert nhân tạo expiry +7d |
| 4 | UI "Request via ACME" + `Renew now` + expiry column + CLI 6 commands | ~300 | Low | Manual UI smoke |
| 5 | Prometheus metrics + `/health/certs` + `cert_audit_log` table + key zeroize | ~200 | Low | Prometheus scrape check |

**Tổng ~1700 LOC mới, ~30 LOC vendor patch.** Ship trong 6 PR squashed. Plan hard mode sẽ tách thành phase files chi tiết.

## 6. Limits (current scope) + Future scaling

### 6.1 Limits đã chấp nhận

| Limit | Value | Reason | Future-proof |
|---|---|---|---|
| Hosts/node | ≤500 | Cache RAM (~2.5MB at 500), single ACME issuer, no sharding | Phase cluster: PG LISTEN/NOTIFY + leader election ACME |
| Cert type | Single-domain only | HTTP-01 challenge | Phase wildcard: DNS-01 + DNS provider plugin |
| ACME accounts | 1 per env (staging/prod) | LE ratelimit "10 accounts/IP/3h" | Multi-account khi vượt 300 orders/3h |
| Cache reload | poll 60s | KISS 1 node | PG LISTEN/NOTIFY khi multi-cluster |
| OCSP | None | LE 6-day short-lived sẽ thay OCSP | Add staple khi LE-short-lived rollout |
| Cluster sync | None | 1 node | waf-cluster transport đã có, add `CertReplica` message type |
| PG encryption | App-level chacha20 cho `acme_accounts.credentials` only | Cert PEM trong `certificates` trust DB at-rest | Phase compliance: extend chacha20 sang cert_pem/key_pem |
| mTLS | None | Out of scope | Pingora hỗ trợ `set_client_cert_verifier`, wire khi cần |

### 6.2 Future scale path (KHÔNG implement phase này nhưng design phải allow)

1. **Multi-cluster cert sync** → `waf-cluster` add message `CertReplica { domain, cert_pem, key_pem, version }`. Leader-only ACME issuer (raft leader election). Worker poll DB hoặc nhận push.
2. **Wildcard + DNS-01** → SslManager extend `request_certificate_wildcard(domain, dns_provider_config)`. Schema thêm `challenge_type` + `dns_provider` columns.
3. **Per-host ACME account** → `acme_accounts` schema đã có `(server_url, email)` UNIQUE — nâng cấp thành `(server_url, email, host_code)` không break.
4. **OCSP stapling** → add background fetcher, cache OCSP response, set `CertifiedKey::ocsp` field.
5. **Cert sharding cross-node** → consistent hash domain → node; resolver fallback proxy lookup cross-node.
6. **mTLS** → SslManager add CA cert store, `set_client_cert_verifier` ở `TlsSettings`.
7. **Hardware HSM key storage** → `rustls::sign::SigningKey` trait abstraction → implement HSM-backed signing key.

Schema + module boundaries đã design để các path trên KHÔNG breaking change phase 1.

## 7. Risks + Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Vendor patch trôi khi sync upstream pingora | Med | Single commit, vendor unit test guard, CI re-run khi diff vendor/ |
| LE ACME ratelimit hit do bug renewal loop | High | Account persist (fix root cause) + per-domain Mutex + exponential backoff + circuit breaker khi LE 429 |
| Cache stale khi renew xảy ra | Low (1 node) | Invalidate sau renew + cache_refresh 60s. Multi-cluster sau dùng LISTEN/NOTIFY. |
| ACME challenge filter false-positive bypass WAF | High | Strict path match prefix + token regex `^[A-Za-z0-9_-]{43}$`, test path traversal không bypass |
| HTTP-01 endpoint unreachable khi LE validate | High | Pre-validation self-check qua 127.0.0.1 trước `set_challenge_ready()` |
| Cert reload race với in-flight handshake | None | rustls `Arc<CertifiedKey>` semantics — researcher A xác nhận safe |
| Port 80 mở 0.0.0.0/0 permanent | Med | Trade-off documented; DNS-01 path tương lai cho operator muốn close port 80 |
| Key material lộ qua memory dump / coredump | Low | Key zeroize on Drop (phase 5), PG at-rest encryption trust |
| Migration acme_accounts conflict với existing schema | Low | Migration number sequential, additive only, không touch `certificates` table phase 1 |

## 8. Success metrics

- Sau phase 1: `curl -v https://mini-waf.ace-trail.com/` cert chain DB-sourced, không nginx, không thread panic.
- Sau phase 2: `prx-waf cert issue --staging --domain test.ace-trail.com` end-to-end OK, DB ghi cert + acme_account row.
- Sau phase 3: cert giả lập expiry 7d → renewal task tự renew trong 24h, audit log capture.
- Sau phase 5: Prometheus scrape `prx_waf_cert_expiry_seconds{domain="..."}` trả gauge giảm dần.
- Production VM Singapore: nginx fully removed, smoke §13 pass, handshake p99 <800ms từ US client (hiện ~650ms với nginx).

## 9. Next steps

1. **Now**: handoff sang `/ck:plan` hard mode với report path này làm context để sinh 6 phase files chi tiết.
2. **Plan validate** (post-plan gate): chạy `/ck:plan validate` để cross-check phase với 3 research reports.
3. **Plan red-team** (post-plan gate): chạy `/ck:plan red-team` cho phase 0 (vendor patch) + phase 2 (ACME flow) — 2 phase risk cao nhất.
4. **Implement phase 0** trên branch riêng `feat/native-tls-cert-resolver-phase-0-vendor-patch`.

## 10. Open questions (unresolved)

1. **Encryption key rotation** cho `acme_accounts.credentials` chacha20 — strategy chưa định. Manual re-encrypt khi rotate? Defer phase 5.
2. **Observed HTTP-01 latency** từ LE tới mini-waf production — chưa đo. Affects polling tuning (researcher B raised). Sẽ đo trong phase 2 staging.
3. **ARI (ACME Renewal Info)** — instant-acme v2 feature, có nên opt-in phase 3? Defer, monitor crate roadmap.
4. **CSR key reuse vs rotation** mỗi renewal — speed vs security trade-off. Default: rotate (current code rcgen new each time). Document.
5. **vendored pingora upstream PR submission timing** — defer, không block phase này.

## Sources

- `/Users/admin/lab/mini-waf/plans/reports/researcher-rustls-23-dynamiccert-20260522.md`
- `/Users/admin/lab/mini-waf/plans/reports/researcher-instant-acme-production-acme.md`
- `/Users/admin/lab/mini-waf/plans/reports/researcher-pingora-cert-resolver-patch.md`
- `/Users/admin/lab/mini-waf/summary.md` §13 (native TLS cutover lessons)
- GitHub issue mini-waf #95
