---
phase: 3
title: "Unit Tests with Tokio Mock Backends"
status: pending
priority: P0
effort: "4h"
dependencies: [2]
---

# Phase 3: Unit Tests

## Overview

Comprehensive test matrix in `crates/gateway/tests/circuit_breaker_timeouts.rs`. Mock backends via `tokio::net::TcpListener` (no Docker required). Cover 10 ACs from `plan.md` + edge cases. Target: ≥ 90% line+branch coverage on `error_to_status()` + new `fail_to_connect()` + `upstream_peer()` timeout-setting path.

## Requirements

**Functional test matrix:**

| # | Scenario | Mock behavior | Expected status | Timing |
|---|---------|---------------|-----------------|--------|
| T1 | Backend accept + hang (no response) | accept; sleep 60s; close | 503 | ≤ `read_timeout + 200ms` |
| T2 | Backend connection refused | port 1 (closed) | 503 | ≤ `connect_timeout + 200ms` |
| T3 | TLS handshake hang | accept TCP; never speak TLS | 503 | ≤ `total_connection_timeout + 200ms` |
| T4 | Backend 500 Internal Server Error | accept; reply HTTP 500 | 502 (NOT 503) | < 100ms |
| T5 | Backend healthy 200 OK | accept; reply HTTP 200 "ok" | 200 | < 100ms |
| T6 | Streaming chunks every 100ms | accept; reply 200 + 5 chunks @ 100ms each | 200 | ≤ 1s |
| T7 | Slow body (1 chunk every read_timeout-50ms) | reply chunks just under timeout | 200 | bounded |
| T8 | Hot-reload mid-flight | swap HostConfig timeouts; next request uses new | new timeouts apply | n/a |
| T9 | Retry-After header on 503 | T1 scenario | `retry-after: 5` present | n/a |
| T10 | `error_to_status` pure-fn matrix | call with synthetic Errors | maps correctly | n/a |

**Property-tested invariants** (proptest, if low-hanging):
- For any `ErrorType` variant `v`, `error_to_status(v)` returns a 3-digit status code in [400, 599] or 0
- Transport-error subset always returns 503
- App-error subset (HTTPStatus(500), HTTPStatus(404), etc.) returns its embedded code

**Non-functional:**
- Tests run in ≤ 30s total (use 500ms test timeouts, not production 5s/30s)
- No flakiness on slow CI: bind to `127.0.0.1:0` (OS-assigned port), ≥ 500ms slack
- Per-test isolation: each test owns its mock listener; no shared state

## Architecture

### Test File Structure

```rust
// crates/gateway/tests/circuit_breaker_timeouts.rs

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

mod helpers {
    /// Spawn a TCP listener that accepts once and runs the given handler.
    /// Returns the bound SocketAddr immediately.
    pub async fn mock_backend<F, Fut>(handler: F) -> SocketAddr
    where
        F: FnOnce(tokio::net::TcpStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    { ... }

    /// Build a `HostConfig` with FR-039 timeouts scaled for tests
    /// (connect=500ms, total=1s, read=1s, write=500ms, idle=2s).
    pub fn test_host_config(remote_addr: SocketAddr) -> waf_common::HostConfig { ... }

    /// Build a minimal `WafProxy` wired to a single mock backend.
    pub fn test_proxy(hc: HostConfig) -> Arc<WafProxy> { ... }

    /// Drive a single HTTP/1.1 request through the proxy and return
    /// `(status_code, headers, elapsed)`.
    pub async fn send_request_through_proxy(...) -> (u16, HeaderMap, Duration) { ... }
}

#[tokio::test(flavor = "multi_thread")]
async fn t1_backend_hang_returns_503() {
    let addr = helpers::mock_backend(|mut s| async move {
        // Accept then hang.
        tokio::time::sleep(Duration::from_secs(10)).await;
        let _ = s.shutdown().await;
    }).await;

    let hc = helpers::test_host_config(addr);
    let proxy = helpers::test_proxy(hc);

    let (status, headers, elapsed) = helpers::send_request_through_proxy(proxy, "/").await;
    assert_eq!(status, 503);
    assert!(elapsed < Duration::from_millis(1500), "took {:?}", elapsed);
    assert_eq!(headers.get("retry-after").unwrap(), "5");
}

#[tokio::test]
async fn t2_connection_refused_returns_503() {
    // Bind + drop to get a port that's now closed.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);

    let hc = helpers::test_host_config(addr);
    let proxy = helpers::test_proxy(hc);
    let (status, _, elapsed) = helpers::send_request_through_proxy(proxy, "/").await;
    assert_eq!(status, 503);
    assert!(elapsed < Duration::from_millis(800));
}

// ... T3 — T10 follow the same shape ...

#[test]
fn t10_error_to_status_pure_matrix() {
    use pingora_core::{Error, ErrorType, ErrorSource};
    let cases: &[(ErrorType, u16)] = &[
        (ErrorType::ConnectTimedout, 503),
        (ErrorType::ReadTimedout, 503),
        (ErrorType::WriteTimedout, 503),
        (ErrorType::ConnectRefused, 503),
        (ErrorType::HTTPStatus(500), 500),
        (ErrorType::HTTPStatus(404), 404),
        // Upstream non-timeout → 502
        (ErrorType::InvalidHTTPHeader, 502), // adjust to real variant
    ];
    for (et, want) in cases {
        let e = Error::new(*et);
        // Need to set source for some cases; emulate as needed
        let got = gateway::proxy::error_to_status_for_test(&e);
        assert_eq!(got, *want, "for {et:?}");
    }
}
```

### Visibility shim for `error_to_status`

`error_to_status` is currently `fn` (module-private). To test pure-fn behavior (T10), expose via:

```rust
// In proxy.rs:
#[cfg(test)]
pub(crate) fn error_to_status_for_test(e: &pingora_core::Error) -> u16 {
    error_to_status(e)
}
```

OR move `error_to_status` to a new sibling module `circuit_breaker.rs` with `pub(crate)` visibility. Decide in implementation.

### Driving requests through the proxy

Two options, in order of preference:

**Option A (preferred): Direct `Session`-less unit test.**
- Hard to drive Pingora `ProxyHttp` without a full `Server` runtime.
- Test `error_to_status()` and `fail_to_connect()` as pure functions (T10).
- Test timeout application via inspecting `HttpPeer.options` after `upstream_peer()` call.

**Option B: In-process Pingora `Server`.**
- Spawn `pingora_proxy::http_proxy_service` on `127.0.0.1:0`.
- Send `reqwest` requests through that port.
- Higher fidelity but slower (~500ms boot).
- Use for T1–T9.

**Mixed strategy:** T10 = Option A; T1–T9 = Option B.

If Option B proves difficult (Pingora 0.8 Server requires more boilerplate), fall back to **Option C:** test `upstream_peer()` output (verify `HttpPeer.options.*_timeout` are set correctly) and rely on Phase 4 Docker e2e for end-to-end timeout enforcement.

## Related Code Files

**Create:**
- `crates/gateway/tests/circuit_breaker_timeouts.rs` — main test file
- `crates/gateway/tests/common/circuit_breaker_helpers.rs` (if shared with other tests)

**Modify:**
- `crates/gateway/src/proxy.rs` — add `#[cfg(test)] pub(crate)` test shim for `error_to_status` (if needed)
- `crates/gateway/Cargo.toml` — `[dev-dependencies]` add `reqwest = { version = "...", features = ["json"] }` if not already there

**Delete:** none

## Implementation Steps

1. Decide Option A vs B vs C (pick simplest that hits coverage goal).
2. Implement `helpers::mock_backend()` and `helpers::test_host_config()`.
3. Write T1, T2, T5 (happy + 2 timeout scenarios) first; iterate until green.
4. Add T3 (TLS hang) — requires rustls in test scope; if too heavy, mark `#[ignore]` and defer to Phase 4 Docker e2e.
5. Add T4, T6, T7, T8, T9.
6. Add T10 (pure-fn matrix) — fastest, exercises `error_to_status` branches directly.
7. Run `cargo test -p gateway --test circuit_breaker_timeouts`.
8. Measure coverage: `cargo llvm-cov -p gateway --tests --html --open` — verify ≥ 90% on `error_to_status` + new methods.

## Todo List

- [ ] Pick test mode (Option A/B/C) and document choice in implementation
- [ ] Implement test helpers (mock_backend, test_host_config, test_proxy)
- [ ] T1: hang → 503
- [ ] T2: refused → 503
- [ ] T3: TLS hang → 503 (or `#[ignore]` + Phase 4)
- [ ] T4: 500 → 502 (NOT 503)
- [ ] T5: healthy → 200
- [ ] T6: streaming chunks → 200
- [ ] T7: slow body → 200
- [ ] T8: hot-reload propagates new timeouts
- [ ] T9: Retry-After header on 503
- [ ] T10: error_to_status pure-fn matrix
- [ ] Coverage report ≥ 90% on FR-039 code
- [ ] `cargo test -p gateway` green
- [ ] All tests complete in ≤ 30s

## Success Criteria

- [ ] 10/10 tests pass (or 9/10 with T3 ignored + documented for Phase 4)
- [ ] Line+branch coverage ≥ 90% on FR-039 code (cargo-llvm-cov)
- [ ] No flakes across 10 consecutive runs (run locally before CI)
- [ ] Each test < 3s wall-clock
- [ ] `cargo clippy --tests -- -D warnings` clean

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Pingora 0.8 Server boot too slow / boilerplate-heavy | Fall back to Option A/C; defer end-to-end to Phase 4 |
| TLS hang test (T3) requires rustls setup → flaky | Mark `#[ignore]`; verify in Phase 4 Docker e2e instead |
| Coverage tool double-counts `#[cfg(test)]` shims | Exclude shim line via `// LCOV_EXCL_LINE` or refactor shim out of prod file |
| CI timing jitter causes false negatives (e.g., 500ms timeout vs 550ms latency) | Use ≥ 500ms slack; allow `elapsed < Duration::from_millis(1500)` for sub-1s timeouts |
| Pingora `Error` constructor API for synthetic errors | Use `pingora_core::Error::new_str(ErrorType::X, "test")`; verify in step 1 |
