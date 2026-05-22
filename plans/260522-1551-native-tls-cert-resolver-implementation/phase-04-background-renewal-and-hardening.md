---
phase: 4
title: "Background renewal + per-domain mutex + exponential backoff"
status: pending
priority: P2
effort: "2d"
dependencies: [3]
---

# Phase 04: Background renewal + hardening

## Overview

Wire `SslManager::spawn_renewal_task()` (đã code sẵn) vào `prx-waf::run_server`. Renewal task chạy daily, scan `certificates WHERE not_after - now() < 30 days AND auto_renew = true`, gọi `request_certificate()` re-issue. Tận dụng per-domain Mutex + exponential backoff từ phase 03. Circuit breaker khi LE trả 429 ratelimit. Hardening edge case: stuck order cleanup, stale challenge cleanup, cert renewal failure isolation (1 host fail không block 49 host khác).

## Requirements

### Functional
- `spawn_renewal_task()` chạy daily (24h interval) + jitter ±2h tránh thundering herd
- Query `list_certificates_due_renewal(30)` — certs hết hạn < 30 days
- Mỗi cert: spawn task qua `tokio::spawn` (parallel) nhưng KHÔNG block lẫn nhau khi 1 fail
- Per-domain Mutex + issue Semaphore(5) giữ nguyên từ phase 03
- Exponential backoff trên LE error: 5min → 15min → 45min → 2h → 6h
- Circuit breaker (red-team H5): persist state vào DB `acme_rate_limit_state` table (`account_id, opened_until, rate_limit_count, first_429_at`), KHÔNG chỉ in-memory DashMap. Restart phải đọc lại state để không re-trigger LE block.
- Typed error matching (red-team H6): match `instant_acme::Error::Acme(Problem { type: "urn:ietf:params:acme:error:rateLimited", status: 429, .. })` qua downcast, KHÔNG dùng `e.to_string().contains("429")`.
- Failure cooldown (red-team H3): thêm column `certificates.consecutive_failure_count` + `last_attempt_at`. Sau N=5 consecutive failures trong 24h → exclude khỏi auto-renewal query, audit log + Prometheus metric. Operator phải manual force qua API `POST /api/certificates/{id}/renew?force=true` để reset counter.
- Stale challenge cleanup: tied to order state (red-team H7) — không cleanup token theo TTL độc lập
- Stale order cleanup: cert status `pending` > 1h → mark `error`, increment `consecutive_failure_count`, renewal cycle pickup tôn trọng cooldown rule
- Failure isolation: 1 cert renewal panic KHÔNG kill renewal task (`tokio::JoinSet` thay vì spawn-and-forget — red-team L3 cho observability)
- Active renewal gauge `prx_waf_active_renewals` exposed (Prometheus, phase 06 wire)

### Non-functional
- Renewal task không block listener serve traffic
- Renewal log mỗi cert: domain + result (success/fail) + duration
- Audit log row mỗi renewal attempt vào `cert_audit_log` (phase 06 sẽ tạo table; phase 04 dùng `tracing::info!` placeholder)

## Architecture

```rust
impl SslManager {
    pub fn spawn_renewal_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let base_interval = Duration::from_secs(86_400);
            loop {
                let jitter = rand::thread_rng().gen_range(0..7200);
                tokio::time::sleep(base_interval + Duration::from_secs(jitter)).await;
                if let Err(e) = Arc::clone(&self).renew_due_certificates().await {
                    tracing::warn!("renewal cycle failed: {}", e);
                }
            }
        })
    }

    async fn renew_due_certificates(self: Arc<Self>) -> Result<()> {
        let due = self.db.list_certificates_due_renewal(30).await?;
        for cert in due {
            let mgr = Arc::clone(&self);
            let domain = cert.domain.clone();
            let host_code = cert.host_code.clone();
            // Spawn isolated task — panic in 1 doesn't kill others
            tokio::spawn(async move {
                let result = mgr.renew_with_backoff(&host_code, &domain).await;
                tracing::info!(domain = %domain, "renewal result: {:?}", result);
            });
        }
        Ok(())
    }

    async fn renew_with_backoff(self: Arc<Self>, host_code: &str, domain: &str) -> Result<Uuid> {
        if self.circuit_breaker.is_open(domain).await {
            bail!("circuit breaker open for {domain}");
        }
        let mut backoff = Duration::from_secs(300);  // 5 min
        for attempt in 0..5 {
            match Arc::clone(&self).request_certificate(host_code, domain).await {
                Ok(id) => return Ok(id),
                Err(e) if is_rate_limited(&e) => {
                    self.circuit_breaker.record_429(domain).await;
                    if self.circuit_breaker.should_open(domain).await {
                        bail!("LE 429 too many times — circuit opened 6h");
                    }
                }
                Err(_) if attempt < 4 => {
                    tokio::time::sleep(backoff).await;
                    backoff *= 3;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        bail!("renewal exhausted after 5 attempts")
    }
}

struct CircuitBreaker {
    state: DashMap<String, CircuitState>,
}

struct CircuitState {
    rate_limit_count: u32,
    first_429_at: Option<Instant>,
    opened_until: Option<Instant>,
}
```

### Wire trong main.rs

```rust
Arc::clone(&ssl_mgr).spawn_renewal_task();
Arc::clone(&ssl_mgr).spawn_stale_challenge_cleanup_task(60);    // poll 60s
Arc::clone(&ssl_mgr).spawn_stale_order_cleanup_task(300);       // poll 5min
```

## Related Code Files

### Create
- `crates/gateway/src/ssl/renewal.rs` — renewal task + backoff logic
- `crates/gateway/src/ssl/circuit_breaker.rs` — CircuitBreaker

### Modify
- `crates/gateway/src/ssl/manager.rs` — add CircuitBreaker field, wire spawn_renewal_task
- `crates/waf-storage/src/queries/certificates.rs` — `list_certificates_due_renewal(days, max_failures)` query exclude rows `consecutive_failure_count >= 5 AND last_attempt_at > now() - 24h`
- `crates/prx-waf/src/main.rs::run_server` — spawn renewal + cleanup tasks
- `Cargo.toml` — add `rand` dep nếu chưa có

### Create migration
- `migrations/0014_acme_rate_limit_state.up.sql` — CircuitBreaker persistence table
- Migration ALTER `certificates` ADD `consecutive_failure_count INT NOT NULL DEFAULT 0`, ADD `last_attempt_at TIMESTAMPTZ`

## Implementation Steps

1. Implement `CircuitBreaker` struct trong `ssl/circuit_breaker.rs` với `record_429`, `is_open`, `should_open`, time-based reset.
2. Implement `renew_with_backoff` với exponential backoff + circuit breaker check.
3. Refactor `renew_due_certificates` — spawn isolated task per cert, không bail toàn cycle khi 1 fail.
4. Add jitter ±2h vào `spawn_renewal_task` interval.
5. Implement `spawn_stale_challenge_cleanup_task` — poll ChallengeStore, remove tokens > 10 min (thêm timestamp khi `set`).
6. Implement `spawn_stale_order_cleanup_task` — query `certificates WHERE status='pending' AND created_at < now()-1h`, mark `error`.
7. Wire 3 task vào main.rs.
8. Helper `is_rate_limited(&anyhow::Error)` — match instant-acme error variant.
9. Unit test: CircuitBreaker open sau 3 lần 429, reset sau 6h.
10. Integration test với cert mock expiry +7d — verify renewal task pickup + renew.

## Success Criteria

- [ ] Renewal task daily + jitter, không block listener
- [ ] Cert expiry < 30d auto-renew thành công
- [ ] 1 host renewal fail KHÔNG ảnh hưởng 49 host khác
- [ ] LE 429 trigger circuit breaker, halt 6h
- [ ] Stale challenge tokens > 10 min tự cleanup
- [ ] Stale orders > 1h pending tự mark error
- [ ] Audit log mỗi renewal attempt (tracing::info!)
- [ ] `cargo test -p gateway` xanh, coverage ssl/ ≥ 90%

## Risk Assessment

| Risk | Severity | Mitigation |
|---|---|---|
| Renewal storm sau restart (50 cert đồng loạt) | Med | Jitter ±2h + tokio::spawn isolated; LE 300 orders/3h vẫn safe |
| Circuit breaker false positive khi LE down ngắn hạn | Low | Reset sau 6h auto. Operator có thể force renew qua API |
| Stuck order forever (instant-acme bug) | Low | 1h timeout mark error, renewal cycle tiếp pick up retry |
| Renewal task panic kill toàn task | Med | tokio::spawn isolated per cert. Main task catch + log |
| Time skew giữa server và LE | Low | NTP sync mandatory (đã có trong RHEL 9 default chrony) |
| jitter dùng `rand::thread_rng()` block async runtime | Low | rand::thread_rng() là sync, OK trong async sleep computation |

## Verification gates

- `cargo test -p gateway::ssl::circuit_breaker` xanh
- LE staging: simulate 4 cert expire trong 5 phút → all renew OK
- Manual force 429 (mock) → circuit open

## References

- Phase 03 dependency: per-domain Mutex + exponential backoff implementation
- Existing code `crates/gateway/src/ssl.rs:262-296` — `renew_due_certificates` + `spawn_renewal_task` đã có, cần extend
