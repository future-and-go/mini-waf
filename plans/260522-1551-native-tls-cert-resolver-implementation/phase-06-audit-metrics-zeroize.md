---
phase: 6
title: "Audit log + Prometheus metrics + key zeroize + health check"
status: pending
priority: P3
effort: "1.5d"
dependencies: [5]
---

# Phase 06: Audit log + metrics + zeroize

## Overview

Production hardening cuối: audit table `cert_audit_log` cho compliance trail; Prometheus gauge cert expiry + ACME counters; key material zeroize on Drop; `/health/certs` liveness endpoint. Phase này không feature mới cho end-user, chỉ tăng quan sát + security defense-in-depth.

## Requirements

### Functional
- Migration `cert_audit_log` table
- Audit insert mỗi event: cert upload, ACME issue, renew, delete, reload, ACME failure
- Prometheus exporter expose:
  - `prx_waf_cert_expiry_seconds{domain}` — gauge, seconds until expiry
  - `prx_waf_acme_requests_total{result}` — counter, labels = success/fail/ratelimit/circuit_open
  - `prx_waf_cert_cache_size` — gauge, số cert trong DashMap
  - `prx_waf_cert_resolver_lookups_total{result}` — counter, labels = hit/miss/no_sni
- `/health/certs` endpoint trả JSON `{healthy, certs_expiring_7d: [...], certs_expiring_14d: [...]}`. HTTP 503 nếu có cert < 24h.
- Key zeroize: `Drop` impl wipe key bytes của `CertifiedKey` khỏi RAM khi eviction
- Audit log query API `GET /api/audit/cert?from=&to=&domain=` pagination

### Non-functional
- Metric export sub-µs (Prometheus crate proven)
- Zeroize KHÔNG impact handshake hot path
- Audit log không block business logic (fire-and-forget tokio::spawn)

## Architecture

### Migration `0013_cert_audit_log.up.sql`

> Numbering reconciled: 0011 (existing category_function), 0012 (phase 03 acme_accounts), 0013 (this phase audit log), 0014 (phase 04 acme_rate_limit_state). Re-verify với `git ls-files migrations/` trước khi implement.

```sql
CREATE TABLE cert_audit_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type    TEXT NOT NULL,    -- 'upload','acme_issue','acme_renew','delete','reload','acme_fail','circuit_open'
    cert_id       UUID,
    domain        TEXT NOT NULL,
    actor         TEXT,             -- 'system','api:<user>','cli'
    details       JSONB,            -- error msg, LE response code, etc.
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_cert_audit_domain_created ON cert_audit_log (domain, created_at DESC);
CREATE INDEX idx_cert_audit_event_created ON cert_audit_log (event_type, created_at DESC);
```

### Audit helper

```rust
async fn audit_event(
    db: &Database,
    event_type: &str,
    cert_id: Option<Uuid>,
    domain: &str,
    actor: &str,
    details: Option<serde_json::Value>,
) {
    let db = db.clone();
    let domain = domain.to_string();
    let actor = actor.to_string();
    let event_type = event_type.to_string();
    tokio::spawn(async move {
        if let Err(e) = db.insert_cert_audit(...).await {
            tracing::warn!("audit insert failed: {}", e);
        }
    });
}
```

### Prometheus metrics (`crates/gateway/src/ssl/metrics.rs`)

```rust
pub struct SslMetrics {
    pub cert_expiry: prometheus::GaugeVec,
    pub acme_requests: prometheus::IntCounterVec,
    pub cache_size: prometheus::IntGauge,
    pub resolver_lookups: prometheus::IntCounterVec,
}

impl SslMetrics {
    pub fn register(registry: &prometheus::Registry) -> Result<Self>;
}
```

Hook gauge update vào:
- Cache reload — update `cache_size` + per-domain `cert_expiry`
- DbCertResolver::resolve — increment `resolver_lookups{result}`
- ACME flow — increment `acme_requests{result}`

### Key zeroize

`CertifiedKey` chứa `Arc<dyn SigningKey>` — keys allocated bởi rustls. `zeroize` crate apply trên `key_pem` bytes trong SslManager cache layer khi eviction.

```rust
struct CachedKey {
    cert: Arc<CertifiedKey>,
    key_pem_bytes: zeroize::Zeroizing<Vec<u8>>,   // wraps Vec, Drop wipes
}
```

### `/health/certs` handler

```rust
async fn health_certs(State(s): State<AppState>) -> Response {
    let now = chrono::Utc::now();
    let certs = s.db.list_certificates_active().await?;
    let expiring_7d: Vec<_> = certs.iter().filter(|c| (c.not_after - now).num_days() < 7).collect();
    let expiring_14d: Vec<_> = certs.iter().filter(|c| (c.not_after - now).num_days() < 14).collect();
    let healthy = certs.iter().all(|c| (c.not_after - now).num_hours() >= 24);
    let body = json!({ healthy, expiring_7d, expiring_14d });
    if healthy { (StatusCode::OK, body) } else { (StatusCode::SERVICE_UNAVAILABLE, body) }
}
```

## Related Code Files

### Create
- `migrations/0013_cert_audit_log.up.sql` + `.down.sql`
- `crates/waf-storage/src/models/cert_audit.rs` + queries
- `crates/gateway/src/ssl/metrics.rs`
- `crates/gateway/src/ssl/audit.rs` — audit helper
- `crates/waf-api/src/handlers/health_certs.rs`

### Modify
- `crates/gateway/src/ssl/manager.rs` — call `audit_event` ở các point + hook metrics
- `crates/gateway/src/ssl/resolver.rs` — increment `resolver_lookups` counter
- `crates/waf-api/src/handlers.rs` — `/health/certs` + `GET /api/audit/cert`
- `crates/prx-waf/src/main.rs` — register SslMetrics vào Prometheus registry
- `Cargo.toml` — add `zeroize` workspace dep (nếu chưa có)

## Implementation Steps

1. Write migration `0013_cert_audit_log` + `.down.sql`.
2. Add model + queries `cert_audit.rs`.
3. Implement `audit_event()` helper với tokio::spawn fire-and-forget.
4. Add `audit_event` call ở: upload, acme issue, acme renew, delete, reload, acme fail, circuit_open.
5. Implement `SslMetrics::register` với 4 metric.
6. Hook cache reload + resolver lookup + ACME flow vào metric.
7. Implement `/health/certs` handler với 503 logic.
8. Implement `GET /api/audit/cert?from=&to=&domain=` với pagination.
9. Apply `zeroize::Zeroizing` cho key PEM bytes trong cache layer.
10. Unit test audit insert async, metric increment, health check 503 path.
11. Verify Prometheus scrape qua `/metrics` endpoint (đã có hay không? Nếu chưa, defer Prometheus exposition).

## Success Criteria

- [ ] Migration apply + revert clean
- [ ] Audit row written cho mỗi cert event
- [ ] Prometheus `prx_waf_cert_expiry_seconds{domain}` exposed
- [ ] `/health/certs` return 503 khi có cert < 24h
- [ ] Key PEM bytes wiped khi cert eviction (verify qua memory inspection test)
- [ ] `GET /api/audit/cert` paginate work
- [ ] `cargo test -p gateway` + `cargo test -p waf-storage` xanh

## Risk Assessment

| Risk | Severity | Mitigation |
|---|---|---|
| Audit insert chậm block business logic | Low | tokio::spawn fire-and-forget; warn log on fail không retry |
| Prometheus gauge update mỗi resolver lookup quá nhiều atomics | Low | IntCounter atomic add ~5ns, OK at 10k RPS |
| Zeroize không cover memory layout rustls bên trong | Med | Document scope: chỉ wipe PEM bytes ở app cache layer, không guarantee rustls internal. Defense-in-depth not absolute. |
| Audit log table grow vô hạn | Med | Phase compliance sau thêm retention task (TTL 365 days). Phase 06 chấp nhận grow-only. |
| /health/certs gọi DB list mỗi liveness probe | Low | Cache result 30s. Liveness probe interval ≥30s |

## Verification gates

- `cargo test -p gateway` xanh, coverage ssl/ ≥ 90%
- Prometheus scrape `/metrics` thấy 4 metric
- `curl /health/certs` JSON đúng schema
- Audit query API pagination

## References

- Existing migration pattern: `migrations/0001_*.up.sql`
- Existing Prometheus integration (nếu có): grep `prometheus::Registry` trong codebase
- Iron Rule 7: Minimize allocations — Zeroize wraps Vec, no extra alloc
