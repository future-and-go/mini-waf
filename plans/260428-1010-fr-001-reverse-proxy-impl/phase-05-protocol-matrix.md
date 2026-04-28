# Phase 05 — Protocol Matrix (H1/H2/H3/WS)

## Context Links
- Design doc §4.4
- Existing: `crates/gateway/src/http3.rs` (HTTP/3 listener)
- ACs: AC-08, AC-09, AC-10, AC-11, AC-22 (no-bypass invariant under all protocols)

## Overview
- **Priority:** P1 (proves end-to-end transparency for non-H1 protocols)
- **Status:** pending
- **Description:** Verify every listener (H1, h2c, h2-TLS, H3/QUIC, WebSocket upgrade) routes through the **same** `Arc<WafProxy>` filter chain. Add per-protocol counter tagging. Ensure WS handshake is inspected; frames pass through (handshake-only inspection per Q1 default).

## Key Insights
- H1 + H2 share a single Pingora `HttpServer` listener via ALPN — no separate proxy impl. Verify the binary's `main` registers ALPN h2.
- H3 uses a separate listener stack (`http3.rs`) — must invoke the same `WafProxy::request_filter` logic. If `http3.rs` has its own request handling, refactor to delegate.
- WebSocket: Pingora forwards Upgrade requests; the handshake **request** flows through `request_filter` like any HTTP/1.1 request. Frames are bidirectional bytes after upgrade — not inspected. Document this scope decision.
- AC-22 invariant: `request_counter` increment must equal request count regardless of protocol. Add per-protocol labels for observability.

## Requirements
**Functional**
- Single `Arc<WafProxy>` shared by H1/H2/H3 listeners.
- WS handshake passes through `request_filter`; counter increments; backend receives upgrade.
- Per-protocol counter labels: `request_counter_h1`, `_h2`, `_h3`, `_ws` (atomic u64s on `WafProxy`).

**Non-Functional**
- No protocol-specific code in `proxy.rs` filter logic — all in listener wiring.

## Architecture
**Pattern application**
- *Registry*: a `ListenerRegistry::register(proto, listener)` ensures every listener takes `Arc<WafProxy>`. Compile-time guarantee via constructor signature: any new listener type can't be added without an `Arc<WafProxy>` parameter. (No runtime registry data structure — just a code convention enforced by struct fields.)

**Data flow**
```
H1/H2 listener  ─┐
H3 listener      ├──► Arc<WafProxy>::request_filter ──► chain ──► upstream
WS upgrade req  ─┘
```

## Related Code Files
**Modify**
- `crates/gateway/src/http3.rs` — confirm or refactor to call `WafProxy` filter chain
- `crates/gateway/src/lib.rs` — re-export listener wiring
- `crates/prx-waf/src/main.rs` (or equivalent binary entry) — verify ALPN h2 registration
- `crates/gateway/src/proxy.rs` — add per-protocol counters; tag in `request_filter` based on session protocol
- `crates/gateway/src/context.rs` — add `protocol: Protocol` enum

**Create**
- `crates/gateway/src/protocol-tag.rs` — `enum Protocol { H1, H2, H3, Websocket }` + detection from session

## Implementation Steps
1. Define `Protocol` enum + detect from `Session` (use Pingora session digest / version / `Upgrade` header).
2. Tag `GatewayCtx.protocol` in `request_filter`.
3. Increment per-protocol counter in addition to global (existing `request_counter`).
4. Audit `http3.rs`: confirm that the H3 request-handling path constructs a Pingora-compatible session and calls `WafProxy` filters. If divergent, refactor to a shared trait (extract a thin `WafGateway` trait if needed). **Do not** duplicate filter logic.
5. Verify ALPN: search `main.rs` for `add_tls_with_settings` / `set_alpn_protos` — assert `h2` + `http/1.1` advertised. Add startup log line.
6. WS path: add explicit test asserting `request_filter` ran for an `Upgrade: websocket` request, and `Upgrade` header survived to backend (phase-02 hop-by-hop must preserve).
7. Integration tests in `tests/fr001_protocols.rs`: 4 clients (`reqwest` h1, `reqwest` h2, `reqwest` h3 if feature, `tokio-tungstenite` WS) → assert per-protocol counter increment.

## Todo List
- [ ] `Protocol` enum + detection
- [ ] Per-protocol counters
- [ ] Audit & align `http3.rs` request-handling
- [ ] Verify ALPN registration in main
- [ ] WS handshake test
- [ ] H3 integration test (gated behind cargo feature `h3-tests`)
- [ ] Per-protocol counter assertion test

## Success Criteria
- AC-08: H1 client → counter_h1 == 1.
- AC-09: H2 client (h2c + h2-TLS) → counter_h2 == 2.
- AC-10: H3 client → counter_h3 == 1 (or test marked `#[ignore]` with documented reason if H3 client tooling unavailable in CI).
- AC-11: WS client connects, sends frame, receives echo; counter_ws == 1.
- AC-22: across all protocols, total counter increments == request count, zero `Ok(false)` bypass paths reachable.

## Risk Assessment
| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| `http3.rs` runs an independent request path bypassing filters | H | H | Audit first thing in this phase; if true, refactor before any other phase-05 work |
| H3 testing requires QUIC client unavailable on CI | M | M | Feature-gate the integration test; cover unit-level via mocked session |
| WS frame inspection requested mid-phase | L | M | Document scope = handshake-only; defer frame inspection to follow-up FR |

## Security Considerations
- Per-protocol counters are observability — must not leak protocol distribution in headers (info leak).
- Confirm H3 0-RTT data also flows through `request_filter` (anti-replay implications). If 0-RTT enabled, document.

## Next Steps
- Phase 06: write the integration tests this phase implies.
