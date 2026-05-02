# Phase 01 — FR-010 Device Fingerprinting (Option B) — Completion Report

**Date:** 2026-05-02
**Branch:** feat/fr-010
**Plan:** plans/260501-2005-fr010-device-fingerprinting/

## Outcome

Phase 01 done w/ scope re-cut. Original phase: "fork pingora + patch rustls accept + patch h2 dispatch". Code reading found pingora uses high-level rustls/h2 APIs that hide the bytes we need — three-crate fork rejected. Pivoted to **Option B: L4 byte tap**.

## Strategy (Option B)

Transparent stream-tap adapter wraps `AsyncRead + AsyncWrite + Unpin` streams; fans inbound bytes to a `ByteTap` callback. Pre-TLS for ClientHello (plaintext on wire), post-TLS for h2 frames. Parsing in waf-engine via `tls-parser` + hand-rolled h2 frame walker (Phase 03). Pingora delta = 2 files.

## Changes

**Vendored fork:** `cloudflare/pingora` rev `1476e7a` (0.8.0+53) → `vendor/pingora/` (gitignored).

**Cargo wiring (root `Cargo.toml`):**
- `[patch.crates-io]` redirects `pingora* = "0.8"` to vendored paths
- `workspace.exclude = ["vendor/pingora"]` — preserves pingora's own workspace inheritance

**Pingora patch (additive):**
- new: `vendor/pingora/pingora-core/src/protocols/inspector.rs` (~140 lines):
  - `trait ClientHelloInspector`, `trait H2FrameInspector`, `enum H2FrameSnapshot`
  - `trait ByteTap`, `struct InspectStream<S>` (AsyncRead/AsyncWrite passthrough + tap)
- edit: `protocols/mod.rs` — `pub mod inspector;` (1 line)

**waf-engine:**
- `crates/waf-engine/Cargo.toml` — `pingora-core = { workspace = true }`
- `src/device_fp/{mod.rs, capture/{mod.rs, client_hello_inspector.rs, h2_frame_inspector.rs, conn_ctx.rs}}` — no-op inspectors + `ConnCtx`/`RawCapture` skeleton
- `src/lib.rs` — `pub mod device_fp;`

## Verification

- `cargo check --workspace --all-targets` ✅ (12.6s)
- `cargo fmt --all -- --check` ✅
- `cargo clippy -p waf-engine --all-targets -- -D warnings` ✅
- `cargo test -p waf-engine device_fp` ✅ — 6/6 unit tests pass

## Deferred to Phase 03

- Insert `InspectStream` into pingora's L4 accept loop (may need 1 small additional pingora patch)
- Real `tls-parser` ClientHello extraction
- h2 frame walker (SETTINGS / WINDOW_UPDATE / PRIORITY / HEADERS until END_HEADERS)
- Per-connection registry (DashMap<ConnId, ConnCtx>)
- Integration smoke test: real handshake → inspector callback

## Open Questions

- Push 2-file pingora patch upstream (Cloudflare PR) or keep as private fork? Local for now; revisit after Phase 03.
- `H2FrameSnapshot` variants — add CONTINUATION/PRIORITY_UPDATE before Phase 03 fixes the parser shape?
- Phase 03 may need an additional pingora hook (`wrap_accepted_stream`) to insert `InspectStream` before TLS termination — design call deferred to that phase.

**Status:** DONE
