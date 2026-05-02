# Phase 01 — Pingora Inspector Primitives (Option B)

**Status:** completed | **Priority:** P0 | **Effort:** S (revised from M) | **Blocks:** all subsequent phases

## Context

Pingora terminates TLS and owns the h2 stack. To capture JA3/JA4 ClientHello bytes and Akamai-style h2 frames, we need extension points it doesn't provide upstream.

## Strategy Pivot — Option B (L4 byte tap)

Original phase plan called for hooks **inside** rustls's accept callback and **inside** the h2 frame dispatch loop. Code inspection of pingora 0.8 showed:

- `vendor/pingora/pingora-core/src/listeners/tls/rustls/mod.rs:81` uses the **high-level** `RusTlsAcceptor::accept()` API which hides ClientHello bytes.
- `protocols/http/v2/server.rs` delegates to the `h2` crate, which exposes typed events, not raw frames.

Patching three crates (pingora + rustls + h2) was rejected as unsustainable. **Adopted approach:** transparent stream-tap adapter wrapping `AsyncRead + AsyncWrite + Unpin` streams; fans inbound bytes to a `ByteTap` callback. Inserted at L4 (pre-TLS) for ClientHello and at the post-TLS boundary for h2 frames in Phase 03. Parsing happens in `waf-engine` using `tls-parser` + a hand-rolled h2 frame walker.

Net pingora source delta: **two files** (one new module, one `pub mod` line in `protocols/mod.rs`).

## Vendoring

`cloudflare/pingora` cloned to `vendor/pingora/` (rev `1476e7a`, 0.8.0+53). Wired via `[patch.crates-io]` + `exclude = ["vendor/pingora"]` in workspace `Cargo.toml`. `vendor/` ignored by git.

## Deliverables (this phase)

**Pingora fork (added):**
- `vendor/pingora/pingora-core/src/protocols/inspector.rs` — new module:
  - `trait ClientHelloInspector { fn on_client_hello(&self, raw: &[u8]); }`
  - `trait H2FrameInspector { fn on_frame(&self, frame: &H2FrameSnapshot<'_>); }`
  - `enum H2FrameSnapshot<'a>` — Settings/WindowUpdate/Priority/Headers variants
  - `trait ByteTap { fn on_bytes(&self, chunk: &[u8]) -> bool; }`
  - `struct InspectStream<S>` — `AsyncRead + AsyncWrite` passthrough; fans inbound bytes to `ByteTap`; auto-detaches on `false` return
- `vendor/pingora/pingora-core/src/protocols/mod.rs` — add `pub mod inspector;`

**waf-engine (added):**
- `crates/waf-engine/src/device_fp/mod.rs`
- `crates/waf-engine/src/device_fp/capture/mod.rs`
- `crates/waf-engine/src/device_fp/capture/client_hello_inspector.rs` — `NoopClientHelloInspector`
- `crates/waf-engine/src/device_fp/capture/h2_frame_inspector.rs` — `NoopH2FrameInspector`
- `crates/waf-engine/src/device_fp/capture/conn_ctx.rs` — `ConnCtx` + `RawCapture` (parking_lot::Mutex slot)
- `crates/waf-engine/Cargo.toml` — `pingora-core = { workspace = true }`
- `crates/waf-engine/src/lib.rs` — `pub mod device_fp;`

**Cargo / repo:**
- Root `Cargo.toml` — `[patch.crates-io]` redirect + `workspace.exclude`
- `.gitignore` — `/vendor`

## Deferred to Phase 03

Phase 01 ships **primitives only**. Wiring `InspectStream` into pingora's listener loop (pre-TLS for ClientHello, post-TLS for h2 frames), real `tls-parser` integration, h2 frame walker, and the per-conn registry are Phase 03's "Capture layer (TLS + h2) + fixtures" work.

## Verification

- `cargo check --workspace --all-targets` ✅
- `cargo fmt --all -- --check` ✅
- `cargo clippy -p waf-engine --all-targets -- -D warnings` ✅
- `cargo test -p waf-engine device_fp` ✅ — 6 unit tests pass

## Todos

- [x] Vendor pingora to `vendor/pingora`
- [x] `[patch.crates-io]` + `workspace.exclude` for pingora-*
- [x] `.gitignore /vendor`
- [x] Add inspector traits + `H2FrameSnapshot` enum
- [x] Add `InspectStream` adapter + `ByteTap`
- [x] No-op inspector wrappers in waf-engine
- [x] `ConnCtx` skeleton
- [x] `cargo check / fmt / clippy / test` green
- [ ] (Phase 03) Wire `InspectStream` into pingora L4 listener
- [ ] (Phase 03) `tls-parser` ClientHello extraction
- [ ] (Phase 03) h2 frame walker
- [ ] (Phase 03) Integration smoke test: real handshake invokes callback

## Risks (resolved this phase)

- Three-crate fork burden → **avoided** by Option B; pingora delta is 2 files
- ClientHello access in rustls high-level API → **avoided** by tapping bytes pre-TLS
- h2 crate raw frame access → **avoided** by tapping bytes post-TLS, parsing ourselves

## Risks (remaining for Phase 03)

- L4 listener integration may require a small additional pingora patch to expose a `wrap_accepted_stream` hook before TLS — to be assessed in Phase 03
- License: pingora is Apache-2.0 — vendored copy preserves LICENSE/NOTICE; no upstream contribution required for fork

## Open Questions

- Do we want to push the 2-file pingora patch upstream (Cloudflare PR) or maintain it as a private fork? Local for now; reassess after Phase 03 proves the design.
- Whether `H2FrameSnapshot` should evolve to include CONTINUATION/PRIORITY_UPDATE before Phase 03 finalizes the parser.
