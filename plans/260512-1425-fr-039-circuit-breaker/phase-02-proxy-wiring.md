---
phase: 2
title: "Apply Timeouts + Error Mapping in Proxy"
status: pending
priority: P0
effort: "3h"
dependencies: [1]
---

# Phase 2: Proxy Wiring

## Overview

Three surgical edits in `crates/gateway/src/proxy.rs`:
1. `upstream_peer()` — set `HttpPeer.options.*_timeout` from `HostConfig`
2. `error_to_status()` — map `ConnectTimeout` / `ReadTimeout` / `WriteTimeout` / `ConnectRefused` → 503 (instead of 502)
3. Add `fail_to_connect()` override that does NOT call `e.set_retry(true)` (prevents hang-via-retry)

Plus one edit in `ErrorPageFactory::render` to emit `Retry-After: 5` header on 503.

## Requirements

**Functional:**
- HttpPeer in `upstream_peer()` carries all 5 timeouts from active `HostConfig`
- `error_to_status()` distinguishes transport errors (→503) from app errors (→502)
- `fail_to_connect()` returns immediately on timeout (no retry)
- 503 responses carry `Retry-After: {upstream_circuit_503_retry_after_s}` header
- Existing behaviors preserved: `fail-closed missing ctx → 503`, access-list block, WAF-decision block

**Non-functional:**
- Zero allocation on hot path (timeouts read from `Arc<HostConfig>`)
- No `.unwrap()` / `.expect()` in production code (per Iron Rule #1)
- Tracing: log timeout events at `warn!` with `upstream_addr` + error type

## Architecture

### Edit 1: `upstream_peer()` (around line 242)

```rust
async fn upstream_peer(&self, session: &mut Session, ctx: &mut GatewayCtx)
    -> pingora_core::Result<Box<HttpPeer>>
{
    // ... existing host_config resolution (lines 200-241) ...

    let mut peer = HttpPeer::new(
        &upstream_addr,
        use_tls,
        host_config.remote_host.clone(),
    );

    // FR-039: apply per-host upstream timeouts.
    peer.options.connection_timeout = Some(
        Duration::from_millis(host_config.upstream_connect_timeout_ms)
    );
    peer.options.total_connection_timeout = Some(
        Duration::from_millis(host_config.upstream_total_connection_timeout_ms)
    );
    peer.options.read_timeout = Some(
        Duration::from_millis(host_config.upstream_read_timeout_ms)
    );
    peer.options.write_timeout = Some(
        Duration::from_millis(host_config.upstream_write_timeout_ms)
    );
    peer.options.idle_timeout = Some(
        Duration::from_millis(host_config.upstream_idle_timeout_ms)
    );

    info!("Proxying {} → {} (timeouts: c={}ms r={}ms)",
        host_header, upstream_addr,
        host_config.upstream_connect_timeout_ms,
        host_config.upstream_read_timeout_ms,
    );
    Ok(Box::new(peer))
}
```

**Verification step:** Before editing, run `cargo doc -p pingora-core --open` (or grep pingora source: `grep -rn 'connection_timeout' ~/.cargo/registry/src/*/pingora-core-0.8*`) to confirm exact field path. Research §1 indicates `peer.options.{name}` — verify.

### Edit 2: `error_to_status()` (around line 140)

```rust
fn error_to_status(e: &pingora_core::Error) -> u16 {
    use pingora_core::{ErrorSource, ErrorType};
    if let ErrorType::HTTPStatus(code) = e.etype() {
        return *code;
    }
    // FR-039: transport-layer failures → 503 (not 502)
    if matches!(
        e.etype(),
        ErrorType::ConnectTimedout
        | ErrorType::ReadTimedout
        | ErrorType::WriteTimedout
        | ErrorType::ConnectRefused
        | ErrorType::ConnectError
        | ErrorType::ConnectProxyFailure
    ) {
        return 503;
    }
    match e.esource() {
        ErrorSource::Upstream => 502,
        ErrorSource::Downstream => match e.etype() {
            ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed => 0,
            _ => 400,
        },
        ErrorSource::Internal | ErrorSource::Unset => 500,
    }
}
```

**Verification step:** Pingora `ErrorType` exact variants vary by version. Run `grep -rn 'pub enum ErrorType' ~/.cargo/registry/src/*/pingora-core-0.8*` and adjust variant names. If variants like `ConnectTimedout` don't exist, fall back to inspecting `e.cause()` or `format!("{e:?}")` string-match (last-resort).

### Edit 3: `fail_to_connect()` override (NEW method on impl)

```rust
fn fail_to_connect(
    &self,
    _session: &mut Session,
    _peer: &HttpPeer,
    _ctx: &mut Self::CTX,
    e: Box<pingora_core::Error>,
) -> Box<pingora_core::Error> {
    // FR-039: never retry on timeout/refused. Bubble up to fail_to_proxy()
    // immediately so we render 503 fast (the whole point of FR-039).
    // (Default Pingora behavior already doesn't retry; we make it explicit.)
    warn!(
        upstream = ?_peer.address(),
        err = ?e.etype(),
        "FR-039: upstream connect failed; returning 503 (no retry)"
    );
    e
}
```

### Edit 4: `ErrorPageFactory::render` — add Retry-After for 503

```rust
// crates/gateway/src/error_page/error_page_factory.rs
pub fn render(status: u16, accept: Option<&str>) -> pingora_core::Result<(ResponseHeader, Bytes)> {
    let mut header = ResponseHeader::build(status, None)?;
    header.insert_header("content-type", content_type_for(accept))?;
    if status == 503 {
        // FR-039: client/proxy retry hint.
        header.insert_header("retry-after", "5")?;
    }
    let body = body_for(status, accept);
    Ok((header, body))
}
```

(If the caller already passes Retry-After elsewhere, skip Edit 4 — verify by reading `error_page_factory.rs` first.)

## Related Code Files

**Create:** none
**Modify:**
- `crates/gateway/src/proxy.rs` — Edits 1, 2, 3 above
- `crates/gateway/src/error_page/error_page_factory.rs` — Edit 4

**Delete:** none

## Implementation Steps

1. **Verify Pingora API:** `grep -rn 'pub enum ErrorType\|connection_timeout\|read_timeout' ~/.cargo/registry/src/index.crates.io-*/pingora-core-0.8*/src/`. Confirm field names + variant names. If different from research, adjust Edits 1/2.
2. **Edit 1 (upstream_peer):** Add 5 `peer.options.*_timeout = Some(Duration::from_millis(...))` lines after `HttpPeer::new()`. Use existing `info!` macro; do NOT log full request URL.
3. **Edit 2 (error_to_status):** Add `if matches!(...)` block before existing `match e.esource()`.
4. **Edit 3 (fail_to_connect):** Add new method on `impl ProxyHttp for WafProxy`. Single `warn!` log + return `e` unchanged.
5. **Edit 4 (Retry-After):** Confirm 503 needs this; add `if status == 503` branch.
6. **Hot-reload check:** `host_config` comes from `HostRouter::resolve()` which already returns `Arc<HostConfig>` swapped via ArcSwap → no extra work.
7. **Compile:** `cargo check -p gateway` → must pass.
8. **Lint:** `cargo clippy -p gateway --all-targets -- -D warnings`.
9. **Fmt:** `cargo fmt --all`.

## Todo List

- [ ] Verify Pingora 0.8 `HttpPeer.options.*` field names (cargo doc / grep)
- [ ] Verify `ErrorType` variants (ConnectTimedout vs ConnectTimeout naming)
- [ ] Edit 1: apply 5 timeouts in `upstream_peer()`
- [ ] Edit 2: extend `error_to_status()` with transport-error → 503 mapping
- [ ] Edit 3: add `fail_to_connect()` override with no-retry behavior
- [ ] Edit 4: add `Retry-After: 5` to 503 in ErrorPageFactory
- [ ] `cargo check -p gateway` clean
- [ ] `cargo clippy -p gateway --all-targets -- -D warnings` clean
- [ ] `cargo fmt --all --check` clean

## Success Criteria

- [ ] Code compiles without warnings
- [ ] Existing `gateway` tests still pass (`cargo test -p gateway --lib`)
- [ ] No new `.unwrap()` / `.expect()` introduced (Iron Rule #1)
- [ ] All HttpPeer constructions in `upstream_peer()` carry timeouts
- [ ] `error_to_status()` has explicit transport-vs-app-error branch

## Risk Assessment

| Risk | Mitigation |
|------|-----------|
| Pingora 0.8 `HttpPeer.options` field name differs (e.g., `connection_timeout` vs `connect_timeout`) | Pre-verify via cargo doc / grep registry source (step 1) |
| `ErrorType::ConnectTimedout` not a variant — different spelling | Pre-verify via grep; use `matches!` with actual variant names |
| `fail_to_connect()` signature mismatch with pingora-proxy 0.8 | Check trait def: `grep -rn 'fn fail_to_connect' ~/.cargo/registry/src/*/pingora-proxy-0.8*` |
| Pingora wraps low-level error so `e.etype()` returns generic — can't match transport-specific | Fall back to `e.esource() == Upstream && format!("{e:?}").contains("Timed out")` heuristic; or check `e.cause()` chain |
| ErrorPageFactory already renders Retry-After differently | Read file first; if no-op, skip Edit 4 |

## Security Considerations

- 503 body uses existing `ErrorPageFactory` — no upstream details leak (already safe).
- `tracing::warn!` log includes `upstream.address` but **not** full request URL → no PII leak.
- `Retry-After: 5` prevents thundering herd on recovery (clients/proxies obey).

## Modularization Note

If `proxy.rs` exceeds 200 LOC growth (per CLAUDE.md modularization rule), extract `error_to_status()` + `fail_to_connect()` body into `crates/gateway/src/circuit_breaker.rs` (new file). Decide in Phase 2 implementation; do NOT pre-extract.
