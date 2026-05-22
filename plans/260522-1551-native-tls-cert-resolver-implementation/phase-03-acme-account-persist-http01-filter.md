---
phase: 3
title: "ACME account persist + HTTP-01 challenge filter + issue API"
status: pending
priority: P1
effort: "4d"
dependencies: [2]
---

# Phase 03: ACME account persist + HTTP-01 challenge filter + issue API

## Overview

Fix bug `Account::create` mỗi lần (LE ratelimit "10 accounts/IP/3h") bằng persist `AccountCredentials` JSON vào table mới `acme_accounts`. Wire ACME HTTP-01 challenge handler vào Pingora request pipeline (bypass WAF rule engine). Expose API `POST /api/certificates/acme/issue`. Pre-validation self-check trước khi `set_challenge_ready()`. Per-domain Mutex + exponential backoff.

## Requirements

### Functional
- Migration mới `acme_accounts` table với UNIQUE(server_url, email)
- `SslManager::get_or_create_account()` lookup existing creds → `Account::from_credentials` HOẶC `Account::create` + persist
- `SslManager::request_certificate()` xài shared account (KHÔNG tạo new mỗi call)
- Pipeline filter `acme_challenge_filter` mount sớm trong `request_filter_chain.rs`, BYPASS WAF guard
- Path match strict prefix `/.well-known/acme-challenge/` + token regex `^[A-Za-z0-9_-]{22,128}$` (red-team C1 — RFC 8555 quy định ≥128-bit entropy + base64url, KHÔNG fix length. LE prod hiện 43 char nhưng pebble staging 32 char, future rotate khả thi).
- Path normalization defense (red-team H1): reject any path chứa `%` (URL-encoded), reject leading `//` double-slash, reject trailing whitespace. Test cases bắt buộc: `//.well-known/...`, `/.well-known/acme-challenge/%2e%2e`, `/.well-known/acme-challenge/foo/`, query string variant.
- Filter MOUNT POSITION (red-team C2): tại **TOP của `request_filter`** trong `proxy.rs:428`, ngay sau `ctx.protocol = detect_from_session(session)` và TRƯỚC `RelayDetector`, `DeviceFpDetector`, `RequestCtxBuilder`, fail-closed 503 guard, `/health` shortcut, `access_lists.evaluate()`. ACME challenge bypass HOÀN TOÀN mọi guard kể cả router resolution (vì domain mới chưa add vào router vẫn cần HTTP-01 bootstrap).
- Token lookup `ssl_mgr.challenges.get(token)` → respond 200 body exact `key_authorization` (text/plain)
- Pre-validation self-check (red-team H2): HTTP GET tới address derive từ `config.proxy.listen_addr` (không hardcode `127.0.0.1:80`). Default `http://127.0.0.1:{port}/.well-known/acme-challenge/{token}`. IPv6-only deployment: fallback `[::1]`. Configurable override env `ACME_SELF_CHECK_URL`.
- Per-domain `tokio::sync::Mutex` trong `DashMap<String, Arc<Mutex<()>>>` tránh concurrent issue
- Order state polling: 2s interval, max wait 60s
- Invalid state retry: 5 attempts exponential backoff 5s → 10s → 20s → 40s → 80s
- Token cleanup (red-team H7): tied to ORDER STATE polling — chỉ remove sau khi order chuyển sang terminal state (`Valid` HOẶC `Invalid` HOẶC fatal timeout 60 min). KHÔNG dùng independent 10-min timer parallel với polling loop (LE legit pending có thể >10 min vì DNS propagation hoặc validator backlog).
- API `POST /api/certificates/acme/issue` body `{host_code, domain}` trigger `request_certificate()`
- Field `credentials` **XChaCha20-Poly1305** encrypted (red-team C3 — sử dụng XChaCha20 24-byte nonce thay vì ChaCha20 12-byte để tránh nonce-reuse catastrophic break). Mỗi row sinh per-row random nonce (24 bytes), store layout `nonce || ciphertext || tag` trong column BYTEA. Key từ env `ACME_CREDENTIALS_KEY` (32 byte hex). Crate name chính xác: `chacha20poly1305` (không có dấu nối).
- Env `ACME_CREDENTIALS_KEY` **lazy validation** (red-team M7): fail-fast chỉ khi operator gọi ACME issue/renew (không required ở startup nếu operator chỉ upload PEM manual).

### Non-functional
- LE ratelimit safe: 50 hosts × 1 issue per 60d = 0.83 orders/day, well under 300/3h
- ACME challenge filter < 10µs latency overhead
- Token validation regex compile once (`lazy_static`)
- Credentials encryption key NOT logged

## Architecture

### Migration (`migrations/0012_acme_accounts.up.sql`)

> **Red-team M2**: `0011_category_function.sql` đã tồn tại trong tree. Use `0012`. Migration numbering MUST verify against `git ls-files migrations/` ngay trước khi implement (race với concurrent work).

```sql
CREATE TABLE acme_accounts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_url    TEXT NOT NULL,
    email         TEXT NOT NULL,
    credentials   BYTEA NOT NULL,                    -- XChaCha20-Poly1305 encrypted: nonce(24) || ciphertext || tag
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,     -- red-team M3: deactivate orphan rows after email rotation
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    UNIQUE (server_url, email)
);

CREATE INDEX idx_acme_accounts_server_email ON acme_accounts (server_url, email);
```

### SslManager extend

```rust
pub struct SslManager {
    db: Arc<Database>,
    challenges: Arc<ChallengeStore>,
    acme_email: String,
    acme_staging: bool,
    cache: Arc<DashMap<String, Arc<CertifiedKey>>>,
    acme_account: tokio::sync::OnceCell<Account>,                       // NEW — MUST use get_or_try_init only (red-team C4)
    domain_locks: DashMap<String, Arc<tokio::sync::Mutex<()>>>,         // NEW
    credentials_cipher: chacha20poly1305::XChaCha20Poly1305,            // NEW (XChaCha20, 24-byte nonce)
    issue_semaphore: Arc<tokio::sync::Semaphore>,                       // NEW (red-team H4) — global concurrency cap 5
}

impl SslManager {
    /// Use get_or_try_init semantics — error never poisons the cell.
    async fn get_or_create_account(&self) -> Result<&Account>;
    /// Output: 24-byte nonce || ciphertext || 16-byte tag
    async fn encrypt_credentials(&self, json: &str) -> Result<Vec<u8>>;
    async fn decrypt_credentials(&self, ciphertext: &[u8]) -> Result<String>;
    async fn lock_domain(&self, domain: &str) -> tokio::sync::OwnedMutexGuard<()>;
}
```

### Pipeline filter (`crates/gateway/src/pipeline/request_filter_chain.rs`)

```rust
const ACME_PREFIX: &str = "/.well-known/acme-challenge/";

static ACME_TOKEN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[A-Za-z0-9_-]{43}$").expect("static regex")
});

pub async fn acme_challenge_filter(
    session: &Session,
    ssl_mgr: &Arc<SslManager>,
) -> Option<Response> {
    let path = session.req_header().uri.path();
    if !path.starts_with(ACME_PREFIX) {
        return None;
    }
    let token = &path[ACME_PREFIX.len()..];
    if !ACME_TOKEN_RE.is_match(token) {
        return Some(respond_404("invalid token"));
    }
    match ssl_mgr.challenges.get(token) {
        Some(key_auth) => Some(respond_200_text(key_auth)),  // body == key_auth exact, no whitespace
        None => Some(respond_404("token not found")),
    }
}
```

Mount tại EARLY position trong `pipeline/mod.rs` — TRƯỚC WAF rule engine + host policy. BYPASS guard hoàn toàn.

### Pre-validation self-check

```rust
async fn self_check_challenge(&self, token: &str, expected_key_auth: &str) -> Result<()> {
    let url = format!("http://127.0.0.1/.well-known/acme-challenge/{token}");
    let resp = reqwest::get(&url).await?;
    if resp.status() != 200 { bail!("self-check non-200"); }
    let body = resp.text().await?;
    if body != expected_key_auth { bail!("self-check body mismatch"); }
    Ok(())
}
```

### `request_certificate` refactor

```
async fn request_certificate(self: Arc<Self>, host_code: &str, domain: &str) -> Result<Uuid> {
    let _semaphore_permit = self.issue_semaphore.clone().acquire_owned().await?;  // red-team H4 — cap 5 in-flight
    let _guard = self.lock_domain(domain).await;                       // per-domain mutex

    let account = self.get_or_create_account().await?;                  // shared, get_or_try_init semantics

    let mut order = account.new_order(...).await?;
    let cert_row = self.db.create_certificate(...).await?;

    for auth in order.authorizations().await? {
        let challenge = auth.challenges.iter().find(|c| c.r#type == Http01)?;
        let key_auth = order.key_authorization(challenge);
        self.challenges.set(challenge.token.clone(), key_auth.as_str().to_string());

        self.self_check_challenge(&challenge.token, key_auth.as_str()).await?;  // NEW
        order.set_challenge_ready(&challenge.url).await?;
    }

    // Poll with exponential backoff on Invalid:
    let mut backoff = Duration::from_secs(5);
    for attempt in 0..5 {
        match poll_until_terminal(&mut order, Duration::from_secs(60)).await? {
            OrderStatus::Ready | OrderStatus::Valid => break,
            OrderStatus::Invalid if attempt < 4 => {
                tokio::time::sleep(backoff).await;
                backoff *= 2;
                continue;
            }
            OrderStatus::Invalid => bail!("ACME order invalid after retries"),
            _ => {}
        }
    }

    // ... CSR + finalize + persist cert + invalidate cache + reload resolver
}
```

## Related Code Files

### Create
- `migrations/0011_acme_accounts.up.sql` + `.down.sql`
- `crates/waf-storage/src/models/acme_account.rs` — model + CRUD
- `crates/gateway/src/ssl/account.rs` — account persist + encryption helpers
- `crates/gateway/src/ssl/challenge_filter.rs` — pipeline filter logic
- `crates/gateway/src/ssl/acme_flow.rs` — refactored request_certificate

### Modify
- `crates/gateway/src/ssl/manager.rs` — add fields + methods
- `crates/gateway/src/pipeline/mod.rs` — mount filter EARLY
- `crates/gateway/src/pipeline/request_filter_chain.rs` — add to chain
- `crates/waf-api/src/handlers.rs` — `POST /api/certificates/acme/issue`
- `crates/prx-waf/src/main.rs::run_server` — env `ACME_CREDENTIALS_KEY` validation + pass vào SslManager::new
- `Cargo.toml` — add `chacha20poly1305 = "0.10"` workspace dep

### Reference
- Phase 02 SslManager structure

## Implementation Steps

1. Write migration `0011_acme_accounts.up.sql` (+ down).
2. Add model `acme_account.rs` (insert, lookup_by_server_email, update_last_used).
3. Implement encrypt/decrypt với `chacha20poly1305`, key từ env `ACME_CREDENTIALS_KEY` (32-byte hex). Fail fast khi missing/invalid length.
4. Implement `get_or_create_account()`: lookup → `Account::from_credentials` → fallback `Account::create` + persist encrypted creds.
5. Implement `lock_domain()` helper.
6. Refactor `request_certificate` xài `_guard` + `account` shared + pre-validation self-check + exponential backoff.
7. Implement `acme_challenge_filter` pipeline filter với strict token regex + path traversal protection.
8. Mount filter EARLY trong `pipeline/mod.rs` — verify thứ tự: acme_challenge → WAF guard → host policy → ...
9. Implement API handler `POST /api/certificates/acme/issue` body `{host_code, domain}` → trigger `request_certificate`. Return cert_id.
10. Wire `ACME_CREDENTIALS_KEY` env trong main.rs (validate hex 32-byte, fail fast).
11. Update CFN template `infra/cloudformation/mini-waf-other-test.yaml` mở port 80 permanent từ `0.0.0.0/0`.
12. Unit test: `acme_challenge_filter` reject `/.well-known/acme-challenge/../../etc/passwd`, accept valid token, return 404 missing token.
13. Integration test: LE staging issue 1 cert end-to-end với 1 domain test.
14. Token auto-expire: background task remove tokens >10min old từ ChallengeStore (regardless of order state).

## Success Criteria

- [ ] Migration `0011_acme_accounts` apply + revert clean
- [ ] LE staging: `prx-waf cert issue --staging --domain test.ace-trail.com` issue 1 cert end-to-end OK (phase 05 thêm CLI; phase 03 verify qua API curl)
- [ ] `acme_accounts` row chứa encrypted credentials, 2 issue cùng env KHÔNG tạo row mới
- [ ] Filter bypass WAF: `curl http://VM/.well-known/acme-challenge/<token>` trả 200 body exact `key_authorization`, không bị block bởi WAF rule
- [ ] Path traversal: `curl http://VM/.well-known/acme-challenge/../../etc/passwd` trả 404, KHÔNG bypass
- [ ] Pre-validation self-check fail → bail trước khi gọi `set_challenge_ready`
- [ ] Per-domain Mutex: 2 concurrent `POST /acme/issue` cùng domain → 1 thực thi, 1 wait
- [ ] LE Invalid state → retry 5 lần với backoff
- [ ] Token cleanup sau 10 min stuck order
- [ ] `cargo test -p gateway` xanh, coverage `ssl/` + `pipeline/` ≥ 90%

## Risk Assessment

| Risk | Severity | Mitigation |
|---|---|---|
| ACME challenge filter bypass WAF + leak path traversal | **High** | Regex `^[A-Za-z0-9_-]{43}$` strict; integration test path traversal; security review |
| LE staging API change vs production | Low | `acme_staging` flag config-driven; test cả 2 env |
| Encryption key `ACME_CREDENTIALS_KEY` rotation | Med | Phase 03 chấp nhận manual rotate (operator re-encrypt offline). Document. Phase compliance sau implement KMS. |
| `Account::from_credentials` schema break giữa instant-acme version | Med | Pin instant-acme version, integration test deserialize stored creds |
| Self-check qua 127.0.0.1 fail vì listener chưa ready trong startup | Med | Self-check timeout 5s + retry 3 lần. Document operator requirement: ACME issue chỉ sau `mini-waf` startup complete. |
| LE 429 ratelimit hit dù đã persist account | Med | Circuit breaker: nếu 429 xảy ra → halt new orders 1h. Audit log. |
| Concurrent issue cùng domain race | Low | Per-domain Mutex giải quyết |
| Port 80 mở 0.0.0.0/0 permanent attack surface | Med | mini-waf chính nó là WAF — guard tất cả request port 80 trừ /.well-known/acme-challenge/ |
| Order state stuck Pending → filter giữ token forever | Med | 10-min auto-expire token + spawn cleanup task |

## Verification gates

- `cargo test -p gateway` — xanh
- LE staging end-to-end test
- Path traversal pen-test
- Coverage `ssl/` + `pipeline/` ≥ 90%
- CFN stack update OK với port 80 rule

## References

- Research: [research/researcher-02-instant-acme-persistence.md](./research/researcher-02-instant-acme-persistence.md)
- RFC 8555 §7.1.6 (Order states), §8.4 (HTTP-01 challenge response format)
- LE rate limits: https://letsencrypt.org/docs/rate-limits/
- Phase 02 dependency: SslManager structure + cache wiring
