# Phase 03 — Capture Layer (TLS ClientHello + H2 Frames) + Fixtures

**Status:** pending | **Priority:** P0 | **Effort:** M | **Blocked by:** phase-01, phase-02

## Context

Implement actual capture wiring: ClientHello bytes → `RawCapture::tls`, H2 frames → `RawCapture::h2`. Per-connection slot bridges TLS/h2 layer to HTTP request stage.

## Requirements

### Functional
- `TlsCapture` impls `ClientHelloInspector`; stores raw bytes + parsed cipher list, extensions list, supported_groups, signature_algorithms, ALPN, SNI in `ConnCtx`
- `H2FrameTap` impls `H2FrameInspector`; appends SETTINGS values, WINDOW_UPDATE size, PRIORITY tree entries, pseudo-header order to `ConnCtx`
- `ConnCtx` keyed by connection id; freed on connection drop
- HTTP request filter retrieves `RawCapture` for current conn, attaches to request ctx

### Non-functional
- ClientHello parse <50µs; h2 frame append <30µs
- Zero allocation in hot path beyond initial capture buffer

## Files

**Created/finalized:**
- `crates/waf-engine/src/device_fp/capture/tls.rs`
- `crates/waf-engine/src/device_fp/capture/h2.rs`
- `crates/waf-engine/src/device_fp/capture/conn_ctx.rs`
- `tests/fixtures/clienthellos/` — golden ClientHello bytes from Chrome 121, Firefox 124, Safari 17, curl 8, curl-impersonate-chrome, Go net/http, Python requests
- `tests/fixtures/h2-frames/` — raw frame byte streams per client

**Modified:**
- `crates/gateway/src/proxy.rs` — register inspectors w/ Pingora at startup, attach `RawCapture` to request ctx in early filter

## Steps

1. Implement `TlsCapture` w/ rustls `ClientHello` ref parsing — extract cipher_suites, extensions order, supported_groups, signature_algorithms, ALPN, SNI
2. Implement `H2FrameTap` capturing SETTINGS frame values, WINDOW_UPDATE delta, PRIORITY frame stream/dependency/weight, HEADERS pseudo-header order until END_HEADERS on stream 1
3. Implement `ConnCtx` w/ slab-keyed `DashMap<ConnId, Arc<Mutex<RawCapture>>>` + `Drop` cleanup
4. Wire registration in `gateway/proxy.rs::startup`
5. Capture real fixtures: run a test rustls server, drive handshakes from each client, dump ClientHello bytes; same for h2 SETTINGS via h2 server tap
6. Parse fixtures in tests; assert deterministic field extraction
7. Bench: criterion on parse path

## Todos

- [ ] `TlsCapture` rustls ClientHello field extraction
- [ ] `H2FrameTap` frame capture w/ END_HEADERS detach
- [ ] `ConnCtx` slab + Drop cleanup
- [ ] Gateway startup registration
- [ ] Capture 7 client ClientHello fixtures
- [ ] Capture 7 client h2 frame fixtures
- [ ] Unit tests parsing each fixture
- [ ] Criterion bench `tls_capture_parse`, `h2_frame_append`
- [ ] Confirm <50µs / <30µs targets

## Success Criteria

- All 7 fixture clients parse to expected RawCapture deterministically
- Bench meets latency targets
- `cargo clippy ... -D warnings` clean
- Connection drop frees ConnCtx (heap-trace test)

## Risks

- Rustls API gives borrowed ClientHello — must clone bytes, not retain ref → unit-test lifetime
- h2 crate frame types may not expose all fields → may need crate-level patch (escalate to phase-01 if so)

## Next

Phase 04 — fingerprint algorithms consume `RawCapture`.
