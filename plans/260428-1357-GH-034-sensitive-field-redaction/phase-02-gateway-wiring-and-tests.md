# Phase 02 — Gateway Wiring + Integration Tests

**Goal:** Wire the FR-034 redactor into `WafProxy` exactly mirroring AC-17. Compose with AC-17 in `response_body_filter`. Verify with integration tests in a new `crates/gateway/tests/` directory and a docker build/test pass.

**Status:** todo
**Depends on:** Phase 01 — `CompiledRedactor`, `BodyRedactState`, `apply_redact_chunk`, `is_json_content_type` must be exported from `gateway::filters`.

## Files Touched

| File | Change |
|------|--------|
| `crates/gateway/src/context.rs` | Add `body_redact: BodyRedactState` field to `GatewayCtx` (one line) |
| `crates/gateway/src/proxy.rs` | Add `body_redact_cache` field to `WafProxy`; init in `new()`; add `resolve_redactor` method; extend `response_filter` (decision); extend `response_body_filter` (apply BEFORE AC-17) |
| `crates/gateway/tests/response_json_field_redactor_integration.rs` | **NEW** — integration tests covering decision logic, multi-chunk EOS, cap overflow, AC-17 composition |

No changes to `waf-common`, no new TOML, no docs (Phase 03).

## 1. `GatewayCtx` Extension

`crates/gateway/src/context.rs`, append after the AC-17 `body_mask` field at line 27:

```rust
    /// FR-034: streaming state for the JSON field redactor. Composes with
    /// `body_mask` — when both are enabled, `body_redact` runs first and the
    /// AC-17 mask runs over the redacted output (see `proxy::response_body_filter`).
    pub body_redact: filters::response_json_field_redactor::BodyRedactState,
```

(Use the full path or import `BodyRedactState` at the top of `context.rs`. Match the existing import style — AC-17's `BodyMaskState` is imported at the top of the file.)

`#[derive(Default)]` on `GatewayCtx` keeps working — `BodyRedactState: Default` is from Phase 01.

## 2. `WafProxy` Field + Cache + Resolver

`crates/gateway/src/proxy.rs`, mirror AC-17's `body_mask_cache` (line 56-58) and `resolve_mask` (line 81-93):

### 2.1 Field

After `body_mask_cache` at line 58:

```rust
    /// FR-034: per-host compiled redactor cache, keyed by `Arc<HostConfig>`
    /// pointer identity. Built lazily on first JSON response; survives until
    /// config reload swaps the host's `Arc<HostConfig>`.
    pub body_redact_cache: Arc<DashMap<usize, Arc<CompiledRedactor>>>,
```

### 2.2 Init in `WafProxy::new`

After `body_mask_cache: Arc::new(DashMap::new()),` at line 74:

```rust
            body_redact_cache: Arc::new(DashMap::new()),
```

### 2.3 Resolver Method

After `resolve_mask` (after line 93):

```rust
    /// FR-034 — resolve (and lazily compile) the JSON redactor for a host.
    /// Mirror of `resolve_mask` for AC-17.
    fn resolve_redactor(&self, hc: &Arc<HostConfig>) -> Arc<CompiledRedactor> {
        let key = Arc::as_ptr(hc) as usize;
        if let Some(existing) = self.body_redact_cache.get(&key) {
            return Arc::clone(&existing);
        }
        let compiled = Arc::new(CompiledRedactor::build(hc));
        self.body_redact_cache.insert(key, Arc::clone(&compiled));
        compiled
    }
```

### 2.4 Imports (top of `proxy.rs`)

Add `CompiledRedactor` to the existing `crate::filters::` import list (around line 21 where `CompiledMask, apply_body_mask_chunk` is imported):

```rust
use crate::filters::{
    apply_body_mask_chunk,
    apply_redact_chunk,
    is_json_content_type,
    CompiledMask,
    CompiledRedactor,
    // ... existing filter struct imports unchanged
};
```

## 3. Decision in `response_filter`

`crates/gateway/src/proxy.rs:325-366` — extend after the existing AC-17 decision block at line 354. Place the FR-034 block AFTER AC-17's so we can read AC-17's Content-Length-drop side effect:

```rust
    // FR-034: decide whether JSON redaction will run for this response.
    //
    // Conditions (all must hold):
    //   * identity Content-Encoding (already-computed `identity` boolean above)
    //   * Content-Type is application/json or application/*+json
    //   * Compiled redactor is non-noop for this host
    let redactor = self.resolve_redactor(hc);
    if identity && !redactor.is_noop() {
        let ct_is_json = upstream_response
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(is_json_content_type);
        if ct_is_json {
            ctx.body_redact.enabled = true;
            // Content-Length will mismatch after redaction — drop it (AC-17 may
            // already have done so; remove_header is idempotent).
            let _ = upstream_response.remove_header("content-length");
        }
    } else if !redactor.is_noop() && !identity {
        // Operator visibility — silent-leak surface (red-team M1 carry-over).
        debug!("json-redact: skipping non-identity content-encoding");
    }
```

(`identity` boolean is the same one AC-17 computes at line 346-353 — reuse it. If easier, factor that computation into a single `let identity = ...;` binding above the AC-17 block; both sites use it.)

## 4. Apply in `response_body_filter`

`crates/gateway/src/proxy.rs:368-387` — replace the body of the existing `response_body_filter`:

```rust
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Option<Duration>>
    where
        Self::CTX: Send + Sync,
    {
        let Some(hc) = &ctx.host_config else {
            return Ok(None);
        };

        // FR-034 first: when buffering, sets *body = None so AC-17 sees nothing.
        // On EOS (or cap), emits redacted full body in *body — AC-17 then runs
        // over it as a single chunk + EOS.
        if ctx.body_redact.enabled {
            let redactor = self.resolve_redactor(hc);
            apply_redact_chunk(&mut ctx.body_redact, &redactor, body, end_of_stream);
        }

        // AC-17 (existing behaviour, unchanged).
        if ctx.body_mask.enabled {
            let compiled = self.resolve_mask(hc);
            apply_body_mask_chunk(&mut ctx.body_mask, &compiled, body, end_of_stream);
        }

        Ok(None)
    }
```

The pre-existing `if !ctx.body_mask.enabled { return Ok(None); }` early-out is removed because we now have two filters and need to enter the function body always (still cheap when both flags are false).

## 5. Integration Tests

Create directory + file: `crates/gateway/tests/response_json_field_redactor_integration.rs`.

The directory does NOT exist on `origin/main` — confirmed (red-team M6 carry-over). This is the first integration test for the gateway crate; sets a precedent.

### Strategy

`pingora_proxy::Session` is not constructible outside Pingora easily. Two viable layers:

1. **Filter-API tests** — call `apply_redact_chunk` directly on a fabricated `BodyRedactState` + `Arc<CompiledRedactor>` + `Option<Bytes>` chunks. Verifies streaming, cap, EOS, AC-17 composition (chain `apply_redact_chunk` → `apply_body_mask_chunk` and assert the AC-17 mask saw the redacted bytes).
2. **End-to-end Pingora test** — spin a real `pingora_core::server` against a `tiny_http`/`hyper` upstream. Heavier; defer unless filter-API tests prove insufficient.

**Phase 02 ships layer (1) only.** Layer (2) deferred to a follow-up if real-world bugs surface.

### Test Cases (≥ 6, layer-1)

| # | Setup | Input chunks (eos pattern) | Expected `*body` after final call |
|---|-------|----------------------------|-----------------------------------|
| 1 | redactor noop (all bools off, no extras) | `{"card_number":"4111"}` (eos=true) | identical bytes (apply_chunk no-op since `is_noop()` — verify via `state.done` stays false) |
| 2 | redact_pci=true, single chunk | `{"card_number":"4111","name":"alice"}` (eos=true) | `card_number` masked, `name` preserved |
| 3 | redact_pci=true, 3-chunk delivery | chunk1 `{"a":"x","b":`, chunk2 `"y","cvv":`, chunk3 `"123"}` with eos=false,false,true | first two calls: `*body=None`, `state.done=false`. Third call: `*body=Some(redacted)` with `cvv` masked, `state.done=true`, byte-length of final = `serde_json::to_vec(redacted).len()` (NOT sum of chunk lengths) |
| 4 | redact_pci=true, body > max_bytes | 300 KiB JSON containing `card_number`, `redact_max_bytes=262144` | accumulated buffer + chunk drained back into `*body` untouched, `state.done=true`, exactly one warn-log |
| 5 | redact_pci=true, malformed JSON | `{not json` (eos=true) | identical bytes (`redact_bytes` returns None → caller forwards original) |
| 6 | AC-17 composition: redact_pci=true + internal_patterns=["10\\.0\\.\\d+\\.\\d+"] | `{"card_number":"4111","internal_ip":"10.0.0.5","note":"called 10.0.0.7"}` delivered single chunk eos=true | After both filters: `card_number` masked AND both `10.0.0.5` and `10.0.0.7` masked by AC-17. Order: redact first, AC-17 second — verify by inspecting final bytes contain neither raw card number nor raw IPs |
| 7 | redact disabled (`state.enabled=false`) | any input | `apply_redact_chunk` is a no-op; `*body` untouched |

Each test:
- Constructs an `Arc<HostConfig>` with the relevant fields.
- Builds `Arc<CompiledRedactor>` via `CompiledRedactor::build(&hc)`.
- Initializes `BodyRedactState::default()`.
- (For test 6) also builds `Arc<CompiledMask>` via `CompiledMask::build(...)` and `BodyMaskState::default()`.
- Calls `apply_redact_chunk` (then `apply_body_mask_chunk` for test 6) per chunk.
- Asserts on `*body` and state flags.

### Test-File Skeleton

```rust
//! FR-034 — integration tests for `apply_redact_chunk` and its composition
//! with the AC-17 body-mask filter.
//!
//! No real Pingora session: tests exercise the filter API directly. End-to-end
//! tests over a live Pingora instance are deferred (see plan phase-02 §5).

use std::sync::Arc;

use bytes::Bytes;
use gateway::filters::{
    apply_body_mask_chunk, apply_redact_chunk, BodyMaskState, BodyRedactState, CompiledMask,
    CompiledRedactor,
};
use waf_common::HostConfig;

fn host_with_pci() -> HostConfig {
    let mut hc = HostConfig::default();
    hc.redact_pci = true;
    hc
}

#[test]
fn case_2_single_chunk_pci() {
    // ... etc
}
```

(Public visibility note — `BodyMaskState` and `BodyRedactState` need to be re-exported from `gateway::filters` for integration tests to access them. Verify the `pub use` line in `filters/mod.rs` from Phase 01 covers both. AC-17's `BodyMaskState` may currently be only `pub` in `context.rs` — if so, also re-export from `filters/mod.rs`.)

## 6. Docker-Based Build & Test

Run the same dev-container recipe as Phase 01, this time covering the full workspace:

```bash
podman run --rm \
  -v "$PWD":/work:Z \
  -v "$PWD/.cargo-cache":/usr/local/cargo/registry:Z \
  -v "$PWD/.cargo-target":/work/target:Z \
  -w /work \
  docker.io/rust:1.86-slim-bookworm \
  bash -c "apt-get update -qq && apt-get install -qq -y --no-install-recommends pkg-config libssl-dev clang cmake \
    && cargo fmt --all -- --check \
    && cargo clippy --workspace --all-targets --all-features -- -D warnings \
    && cargo test --workspace \
    && cargo build --release"
```

**Gate:** all four commands must succeed before Phase 03.

If `--release` is too slow on the dev machine, drop it from this gate and run only `cargo build` (debug). Production release build will run in CI / Phase 03 anyway.

## Pre-Edit Impact Check (gitnexus)

Before editing `proxy.rs`:

```
gitnexus_impact({target: "WafProxy", direction: "upstream"})
gitnexus_impact({target: "GatewayCtx", direction: "upstream"})
gitnexus_impact({target: "response_body_filter", direction: "upstream"})
```

Proxy is the request-path hot module. Verify no surprise consumers before extending the struct. If risk = HIGH, pause and report.

## Success Criteria

- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean (containerised).
- `cargo test --workspace` green (containerised) — all existing tests + 7 new integration tests pass.
- `cargo build --release` (containerised) green.
- With every `redact_*` field at default (false): zero behaviour change for all hosts (verified by AC-17 / existing integration tests passing unchanged).
- With `redact_pci=true`: a JSON response with `card_number` is masked, an HTML response is untouched, a gzipped JSON response is untouched (and `tracing::debug!` logged).
- AC-17 composition: a response with both an internal-IP pattern AND a `card_number` field has both redacted in the final bytes.

## Out of Scope (Phase 02)

- TOML default config — Phase 03.
- Docs sync — Phase 03.
- End-to-end Pingora-driven integration tests — deferred (filter-API layer-1 tests cover the riskiest paths).
- Metrics / Prometheus exposition — out of plan.
- Per-route policy — out of plan.
