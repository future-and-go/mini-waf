# FR-039: Pingora Upstream Timeout & Circuit Breaker Research

**Date:** 2026-05-12  
**Researcher:** Technical Analyst  
**Context:** FR-039 mandate: "If backend unresponsive, WAF returns 503 instead of hanging"

---

## Executive Summary

Pingora provides **fine-grained upstream timeout controls** via `HttpPeer` options (`connection_timeout`, `total_connection_timeout`, `read_timeout`, `write_timeout`, `idle_timeout`) but **does NOT include a built-in circuit breaker**. A surgical implementation for FR-039 requires:

1. **Configure per-peer timeouts** (not retry on connection failures, disable default retry logic)
2. **Trap `fail_to_connect()` and `error_while_proxy()`** to map timeout/connection errors → 503
3. **Simple state machine** (optional): track consecutive failures per upstream; return 503 fast after N failures
4. **Avoid HTTP/2 stream-level complexity** — apply connection-level timeouts only
5. **Test with mock slow servers** (tokio TcpListener + sleep)

---

## 1. Pingora Upstream Timeout APIs

### Timeout Types in `HttpPeer::options`

| Timeout | Scope | Applies To | Semantics |
|---------|-------|-----------|-----------|
| `connection_timeout` | TCP handshake only | Upstream only | How long before giving up on TCP SYN/ACK/ACK |
| `total_connection_timeout` | TCP + TLS handshake | Upstream only | Includes full TLS handshake (larger window) |
| `read_timeout` | Per-read operation | Upstream only | Time between individual read() calls; **timer resets after each read** |
| `write_timeout` | Per-write operation | Upstream only | Time between individual write() calls |
| `idle_timeout` | Idle connection pool | Upstream only | How long before closing an idle connection in the pool (reuse) |

**Key distinction:** `read_timeout` is NOT a "total response timeout" — it resets after each chunk. A slow streaming response (HTTP/2 server-sent events, chunked JSON) will NOT timeout as long as individual chunks arrive within `read_timeout`. This is intentional for long-polling and SSE use cases.

### Configuration Pattern

```rust
let mut peer = HttpPeer::new(&upstream_addr, use_tls, sni);
peer.options.connection_timeout = Some(Duration::from_secs(5));  // TCP handshake
peer.options.total_connection_timeout = Some(Duration::from_secs(10)); // TCP + TLS
peer.options.read_timeout = Some(Duration::from_secs(30));  // Per-read
peer.options.write_timeout = Some(Duration::from_secs(10)); // Per-write
peer.options.idle_timeout = Some(Duration::from_secs(60));  // Pool reuse
```

### Sources & Credibility

- [Pingora Peer User Guide](https://github.com/cloudflare/pingora/blob/main/docs/user_guide/peer.md) (official Cloudflare docs) — defines timeout types precisely
- [Pingora Issue #506](https://github.com/cloudflare/pingora/issues/506) (maintainer discussion) — confirms `read_timeout` resets per-read
- [Pingora PR #539](https://github.com/cloudflare/pingora/pull/539) (merged fix) — addresses HTTP/1 client read timeout handling

---

## 2. Error Handling Hooks: `fail_to_connect()` vs `fail_to_proxy()`

### Pingora's Error Propagation Flow

```
upstream_peer()
   ↓ [connect fails]
fail_to_connect() [can mark retry & update context for failover]
   ↓
error_while_proxy() [can mark retry after request partially sent]
   ↓
fail_to_proxy() [catch-all: sends error page, returns FailToProxy { error_code, can_reuse_downstream }]
```

### Key Semantics

| Hook | When Called | Safety | Retry Capability |
|------|-------------|--------|------------------|
| `fail_to_connect()` | Connection refused / timeout | **Safe for any HTTP method** (nothing sent upstream) | Call `e.set_retry(true)` to retry |
| `error_while_proxy()` | Error during request/response | **Unsafe for POST** (may have been partially sent) | Only retry GET-like idempotents |
| `fail_to_proxy()` | Final catch-all for any error | Final decision point | No retry; render error page |

### Implementation for FR-039 (KISS Approach)

Our current `fail_to_proxy()` in `proxy.rs:498` already maps errors to HTTP status codes. To add 503 for timeout/connection failure:

```rust
fn error_to_status(e: &pingora_core::Error) -> u16 {
    use pingora_core::{ErrorSource, ErrorType};
    if let ErrorType::HTTPStatus(code) = e.etype() {
        return *code;
    }
    match e.esource() {
        ErrorSource::Upstream => 502,  // ← Currently 502 for all upstream errors
        // ...
    }
}
```

**Change needed:** Distinguish timeout/connection errors (→ 503) from normal upstream errors (→ 502).

Error inspection pattern:

```rust
fn error_to_status(e: &pingora_core::Error) -> u16 {
    match e.etype() {
        ErrorType::ConnectTimeout | ErrorType::ReadTimeout | ErrorType::WriteTimeout => 503,
        ErrorType::ConnectProxyFailure | ErrorType::ConnectRefused => 503,
        // ... other upstream errors → 502
    }
}
```

**Disable retry on timeout:** In `fail_to_connect()`, do NOT call `e.set_retry(true)` for timeout errors. Return immediately to `fail_to_proxy()`.

### Sources

- [Pingora Failover User Guide](https://github.com/cloudflare/pingora/blob/main/docs/user_guide/failover.md) (official; defines fail_to_connect/error_while_proxy phases)
- [Pingora Error Handling User Guide](https://github.com/cloudflare/pingora/blob/main/docs/user_guide/errors.md) (official; error types and semantics)
- Project code: `crates/gateway/src/proxy.rs:200–247` (current upstream_peer & fail_to_proxy implementation)

---

## 3. Circuit Breaker: Do We Need It?

### Pingora's Native Circuit Breaker Status

**None.** Pingora has no built-in circuit breaker state machine. [Issue #420](https://github.com/cloudflare/pingora/issues/420) is a feature request (not yet implemented).

### YAGNI Analysis: Is It Needed for FR-039?

**No, not for MVP.** FR-039 only mandates "return 503 instead of hanging." A simple approach suffices:

1. **Set `connection_timeout` = 5s, `read_timeout` = 30s** on all peers
2. **Trap timeout/connection errors in `fail_to_proxy()`** → return 503
3. **Done.** The connection pool naturally expires idle connections; Pingora won't queue indefinitely.

**When you'd add circuit breaker (future, not now):**
- Track N consecutive failures per upstream in a `DashMap<UpstreamAddr, FailureCount>`
- After 5 consecutive failures, fast-fail (return 503 immediately without trying to connect)
- Half-open state: every 10th request attempts connection; if success, reset failure count
- **Trade-off:** Adds 100 LOC + per-request overhead (hash lookup). Not KISS for current scope.

### Comparison: Envoy vs HAProxy

**Envoy (industry standard):**
- Full circuit breaker: Open/Half-Open/Closed state machine
- Per-cluster connection limit (default 1024)
- Per-cluster request limit (default unlimited)
- Outlier detection: auto-eject hosts after 5 consecutive 5xx responses
- [Envoy Circuit Breaker Docs](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/circuit_breaking)

**HAProxy:**
- Simple health checks: `fall 3` (mark down after 3 failures), `rise 2` (mark up after 2 successes)
- No formal "circuit breaker" state machine; just binary up/down
- Faster failover but less nuance

**Our approach (KISS for FR-039):** Timeouts + error mapping. If we need sophistication later, we can wrap a `CircuitBreakerState` enum around the context, but **not for this phase**.

---

## 4. HTTP/2 and HTTP/3 Implications

### Stream vs Connection Timeouts

Pingora's `read_timeout` / `write_timeout` are **connection-level**, not stream-level.

| Protocol | Implications |
|----------|-------------|
| HTTP/1.1 | One stream per connection; read_timeout applies to entire request/response |
| HTTP/2 | Multiple streams multiplexed on one connection; timeout applies to **socket operations**, not individual streams. If stream A stalls while stream B sends data, stream A does NOT timeout (one stream's data arrival resets the timer for the whole connection) |
| HTTP/3 (QUIC) | Streams multiplex on one connection; same per-connection timeout semantics |

**For FR-039:** This is NOT a problem. We want "backend unresponsive" to mean "the whole upstream connection is stalled," which manifests as no I/O progress. A single stalled stream is rare; usually it means network is bad or server is wedged.

**Gotcha:** If your upstream speaks HTTP/2 and one stream stalls while another sends data, the stalled stream WON'T trigger the connection-level timeout. Workaround: set `idle_timeout` to catch cases where the connection is alive but no meaningful I/O happens for N seconds.

### Sources

- [Pingora Issue #563](https://github.com/cloudflare/pingora/issues/563) — Open feature request for HTTP/2 idle timeout (not yet available)
- [Pingora Issue #558](https://github.com/cloudflare/pingora/issues/558) — Known issue with HTTP/2 stream cancellation
- [RFC 9114 - HTTP/3](https://httpwg.org/specs/rfc9114.html) — Stream timeout semantics in QUIC

---

## 5. Production Gotchas

### False Positives: SSE, WebSocket, Long-Poll

**Risk:** If you set `read_timeout=5s`, a slow client uploading a large request body will hit timeout and break.

**Mitigation:** Distinguish between **upstream** timeouts (where we set the deadline) and **downstream** timeouts (where clients control speed).

- **Upstream read_timeout:** Only matters AFTER we've sent the request and are waiting for response. Safe for any response type (streaming JSON, SSE, WebSocket upgrade).
- **Downstream client timeout:** Handled by separate logic; Pingora has `client_header_timeout` and `client_body_timeout` (defaults ~60s).

**Whitelist for long-running requests:** No whitelist needed. The timeout only triggers if the upstream doesn't send ANY bytes for `read_timeout` seconds. SSE streams send periodic heartbeats (newlines or keepalives), so they won't timeout.

**WebSocket upgrade:** Use `keep-alive` on the connection, not stream-level timeout. Pingora's `idle_timeout` is the right lever.

### Slow Response Body Streaming

**Scenario:** Backend sends `Content-Length: 1MB` but transmits it slowly (10 KB/sec = 100 seconds).

**What happens:** Each 10 KB chunk arrives within `read_timeout`, so no timeout. ✓ Correct.

**Stalled response:** Backend sends 100 KB then stalls forever. After `read_timeout` (e.g., 30s), no new bytes arrive. Pingora times out. ✓ Correct.

**TLS handshake counted:** `total_connection_timeout` includes the full TLS handshake. If upstream TLS is slow (revocation checks, OCSP stapling), the clock includes that time. Use `total_connection_timeout > connection_timeout` to account for TLS overhead.

### DNS Resolution Timeout

**Issue:** Pingora doesn't expose a separate DNS timeout in the public API. DNS is handled by the OS resolver (system `/etc/resolv.conf`).

**Implication:** If DNS is slow, the client sees latency, but it's NOT part of `connection_timeout`. To add a DNS timeout:

1. **Resolve upstream address outside Pingora** (in `upstream_peer()`), using a DNS library with explicit timeout
2. **Pass resolved IP + SNI to `HttpPeer`** (avoid re-resolving on every request)
3. **Set `connection_timeout` to cover TCP handshake only** (DNS already timed out upstream)

**KISS approach for FR-039:** Don't add DNS timeout now. Use Pingora's default resolver. If DNS becomes a bottleneck in prod, add explicit resolution + caching later.

### Sources

- [Pingora PR #539](https://github.com/cloudflare/pingora/pull/539) — Timeout semantics for HTTP/1 body streaming
- [Pingora Issue #447](https://github.com/cloudflare/pingora/issues/447) — Downstream timeout configuration (separate from upstream)
- [Pingora Issue #506](https://github.com/cloudflare/pingora/issues/506) — Clarification on read_timeout resets per-read

---

## 6. Test Strategy (Without Docker)

### Mock Slow Upstream Pattern

Use **`tokio::net::TcpListener` + immediate accept + sleep**:

```rust
#[tokio::test]
async fn test_upstream_read_timeout() {
    // Start a slow upstream on localhost:9999
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        // Never send response; client timeout triggers after read_timeout
        tokio::time::sleep(Duration::from_secs(60)).await;
        let _ = socket.shutdown().await;
    });
    
    // Configure peer with 1-second read timeout
    let mut peer = HttpPeer::new(&format!("{}", addr), false, "localhost");
    peer.options.read_timeout = Some(Duration::from_millis(500));
    
    // Attempt to request; should timeout
    let result = /* ping upstream */;
    assert!(matches!(result, Err(pingora_core::Error { etype: ErrorType::ReadTimeout, .. })));
}
```

### Connection Refused Pattern

```rust
#[tokio::test]
async fn test_upstream_connection_refused() {
    let addr = "127.0.0.1:1".parse().unwrap(); // Port 1 (refused)
    let peer = HttpPeer::new(&addr, false, "localhost");
    // Attempt to request; should fail immediately with ConnectRefused
}
```

### Avoid Flakiness

- **Bind to `127.0.0.1` only** (never `0.0.0.0`; avoids IPv6 surprises)
- **Use OS-assigned ephemeral ports** (`bind("127.0.0.1:0")`) to avoid conflicts
- **Don't set timeouts < 100ms** in CI; latency jitter causes flakes. Use 500ms–1s for tests.
- **Use `#[tokio::test]` with `#[tokio::test(flavor = "multi_thread")]`** for realistic concurrent load

### Sources

- Pingora doesn't mandate Docker for unit tests; we can use in-process tokio servers
- Recommendation: Keep unit tests in `crates/gateway/tests/*.rs` (existing pattern); no external dependencies needed

---

## 7. Recommended Implementation for FR-039

### Phase 1 (KISS — 1 day)

1. **In `crates/gateway/src/proxy.rs::upstream_peer()`**, set timeouts on HttpPeer:
   - `connection_timeout = 5s` (TCP handshake)
   - `total_connection_timeout = 10s` (includes TLS)
   - `read_timeout = 30s` (per-read operation)
   - `write_timeout = 10s` (per-write operation)

2. **In `error_to_status()`**, map timeout/connection errors to 503:
   ```rust
   ErrorType::ConnectTimeout | ErrorType::ReadTimeout => 503,
   ErrorType::ConnectProxyFailure | ErrorType::ConnectRefused => 503,
   ```

3. **In `fail_to_connect()` (if it exists), disable retry for timeout:**
   ```rust
   // Don't call e.set_retry(true) for timeout errors
   // Let them fall through to fail_to_proxy()
   ```

4. **Test:** 5 unit tests covering connection timeout, read timeout, connection refused, 502 (normal upstream error), and successful request.

### Phase 2 (If Needed — TBD)

- Add optional circuit breaker: track consecutive failures per upstream
- Add per-tier configurable timeouts (via `HostConfig`)
- Add metrics: timeouts per upstream, failure count

---

## Unresolved Questions

1. **Does mini-waf currently have a `fail_to_connect()` hook?** If not, we only customize `fail_to_proxy()`. Need to check `ProxyHttp` trait implementation.

2. **What's the current timeout configuration in `gateway/lb.rs`?** The requirements say "health checks" are implemented; are there already timeouts set, or do we start from scratch?

3. **Per-tier timeout granularity:** Should CRITICAL tier have aggressive timeouts (3s) while CATCH-ALL is lenient (30s)? Or single global policy? (Recommend global for MVP, per-tier later.)

4. **Metrics/alerting:** Should we log every 503 due to timeout, or only aggregate? (Recommend: log at `warn!` level with upstream address + error type.)

5. **DNS timeout:** Should we add explicit DNS resolution with timeout, or rely on OS resolver? (Recommend: defer to Phase 2.)

---

## References

### Official Pingora Documentation
- [Peer Configuration](https://github.com/cloudflare/pingora/blob/main/docs/user_guide/peer.md)
- [Failover & Retry](https://github.com/cloudflare/pingora/blob/main/docs/user_guide/failover.md)
- [Error Handling](https://github.com/cloudflare/pingora/blob/main/docs/user_guide/errors.md)

### Pingora Issues (Community Discussions)
- [#420 — Circuit Breaker](https://github.com/cloudflare/pingora/issues/420) (feature request, not implemented)
- [#506 — Stream Timeout Clarification](https://github.com/cloudflare/pingora/issues/506)
- [#539 — HTTP/1 Client Read Timeout Fix](https://github.com/cloudflare/pingora/pull/539)
- [#563 — HTTP/2 Idle Timeout Request](https://github.com/cloudflare/pingora/issues/563)

### Comparison References
- [Envoy Circuit Breaker](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/circuit_breaking)
- [HAProxy Health Checks](https://www.haproxy.com/)

### Project Code
- `crates/gateway/src/proxy.rs` — ProxyHttp implementation, current error handling
- `crates/gateway/src/lb.rs` — Load balancer (check for existing timeout config)
- `analysis/requirements.md` — FR-039 specification

---

## Summary Table: What to Do vs. What NOT to Do

| Action | Do? | Reason |
|--------|-----|--------|
| Set `connection_timeout` on all peers | **YES** | Required for FR-039 |
| Set `read_timeout` on all peers | **YES** | Required for FR-039 |
| Implement circuit breaker state machine | **NO** | Not in FR-039 scope; YAGNI |
| Add per-stream timeout for HTTP/2 | **NO** | Pingora doesn't expose; connection-level is sufficient |
| Implement explicit DNS timeout | **NO** | Defer to Phase 2; use OS resolver |
| Log timeout errors at WARN level | **YES** | Operational visibility |
| Whitelist SSE/WebSocket from timeout | **NO** | Our timeouts are per-read, not per-request; SSE/WS safe |
| Map 503 for timeout/connection errors | **YES** | FR-039 mandate |
| Return 502 for normal upstream errors | **YES** | Distinction from timeouts |

