# Phase 01 — Pingora Patch: ClientHello + H2 Frame Hooks

**Status:** pending | **Priority:** P0 | **Effort:** M | **Blocks:** all subsequent phases

## Context

Pingora terminates TLS and owns the h2 stack. To capture JA3/JA4 ClientHello bytes and Akamai-style h2 frames, we need extension points it doesn't provide upstream. This phase produces a pinned patch.

## Requirements

### Functional
- Expose `set_client_hello_inspector(Arc<dyn ClientHelloInspector>)` invoked synchronously during rustls/boring handshake; receives raw ClientHello bytes + parsed extensions list
- Expose `set_h2_frame_inspector(Arc<dyn H2FrameInspector>)` invoked per-frame for SETTINGS, WINDOW_UPDATE, PRIORITY, HEADERS until first END_HEADERS, then auto-detach
- Hooks store raw capture into a per-connection slot (slab keyed by conn id) readable by the HTTP request filter stage
- No behavior change when hooks unset (default = `None`)

### Non-functional
- Hooks read-only on owned frame copies; do not mutate frame stream
- Synchronous hook callbacks (no `.await`); callers wrap heavy work in spawned tasks if needed
- Patch isolated to a single branch; rebase SOP documented

## Architecture

```
Cargo.toml
└── pingora = { git = "https://github.com/<org>/pingora", branch = "mini-waf/device-fp-hooks", rev = "<sha>" }

waf-engine/src/device_fp/capture/
├── client_hello_inspector.rs   # impls Pingora trait
└── h2_frame_inspector.rs       # impls Pingora trait
```

## Files

**Patched (Pingora fork):**
- `pingora-core/src/listeners/tls.rs` — add inspector field + invocation
- `pingora-core/src/protocols/http/v2/server.rs` — add frame inspector hook
- New trait file: `pingora-core/src/protocols/inspector.rs`

**Created (this repo):**
- `crates/waf-engine/src/device_fp/capture/client_hello_inspector.rs`
- `crates/waf-engine/src/device_fp/capture/h2_frame_inspector.rs`
- `crates/waf-engine/src/device_fp/capture/conn_ctx.rs` (per-conn raw capture slot)

**Modified:**
- `Cargo.toml` (workspace root) — add `[patch.crates-io]` or git dep for pingora
- `docs/system-architecture.md` — patch upgrade SOP

## Steps

1. Fork `cloudflare/pingora` to org repo; create branch `mini-waf/device-fp-hooks`
2. Add `ClientHelloInspector` trait + `H2FrameInspector` trait in new `pingora-core/src/protocols/inspector.rs`
3. Add `inspector: Option<Arc<dyn ClientHelloInspector>>` to TLS listener config; invoke in rustls `accept` callback before handshake completes
4. Add `inspector: Option<Arc<dyn H2FrameInspector>>` to h2 server; tap frames in dispatch loop, detach after END_HEADERS on stream 1
5. Build pingora locally; run pingora's own tests — must pass unchanged
6. Pin in our `Cargo.toml` via git dep w/ explicit `rev = "<sha>"`
7. Implement no-op inspector wrappers in `device_fp/capture/` to validate wiring
8. Add CI job: build pingora fork from rev + run pingora conformance suite

## Todos

- [ ] Fork pingora repo to org
- [ ] Create branch + add inspector traits
- [ ] Wire ClientHello inspector in TLS listener
- [ ] Wire H2 frame inspector in h2 server
- [ ] Run pingora upstream tests (unchanged behavior)
- [ ] Pin via git rev in Cargo.toml
- [ ] Add no-op inspector wrappers in waf-engine
- [ ] CI job for pingora fork build + conformance
- [ ] Document rebase/upgrade SOP in `docs/system-architecture.md`

## Success Criteria

- `cargo build --release` succeeds with pinned pingora fork
- Pingora upstream conformance tests pass against the fork
- No-op inspectors compile and link; default behavior unchanged
- Setting an inspector and making a TLS handshake invokes the callback (proven by integration smoke test)

## Risks

- Pingora upstream changes break rebase → mitigate w/ pinned rev + conformance CI
- License: pingora is Apache-2.0 — fork must preserve LICENSE/NOTICE
- Async safety: hook must not block executor — callbacks store bytes in `Arc<Mutex<...>>` slot, real work happens elsewhere

## Security

- Inspector reads raw bytes — must clone and never mutate frame stream
- Per-connection slot freed on connection drop (use `Drop` impl)

## Next

Phase 02 — module skeleton can begin once inspector traits compile, even before hook integration is fully tested.
