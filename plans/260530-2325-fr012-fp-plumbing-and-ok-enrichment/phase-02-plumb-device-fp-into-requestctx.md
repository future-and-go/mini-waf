---
phase: 2
title: "Plumb device_fp into RequestCtx"
status: done
priority: P1
effort: "4-6h"
dependencies: [1]
---

# Phase 2: Plumb device_fp into RequestCtx

## Overview

With `FpKey` now living in `waf-common` (phase-01):
1. Add `device_fp: Option<Arc<FpKey>>` to `RequestCtx`, populate from gateway after device-fp resolution, consume in `TxVelocityCheck::check()` — closes `check.rs:55` TODO.
2. **(Red-team C1)** Also add `tx_velocity_token: Option<TxEventToken>` — set by `TxVelocityCheck::check()` after `record()`, consumed by `TxVelocityCheck::on_request_complete()` for race-free slot flipping.
3. **(Red-team C5)** Add `impl Default for RequestCtx`. With 164 struct-literal call sites workspace-wide, the only sane way to absorb this field-add (and future ones) is one canonical Default that test fixtures spread via `..Default::default()`.
4. **(Red-team C7)** Change `SessionIdent::Fingerprint(FpKey)` → `SessionIdent::Fingerprint { fp: FpKey, ip: IpAddr }`. Shared CDN fingerprints (browser JA3 behind CloudFront, etc.) cannot bucket thousands of victims under one identity. The `peer_ip` widens the key just enough to break cohort poisoning while keeping the legit "same device on same network" tracking intact.

## Requirements

- **Functional**:
  - `RequestCtx.device_fp` is `Some` when device-fp pipeline resolved a non-empty `FpKey`; `None` otherwise.
  - `TxVelocityCheck::check()` passes `ctx.device_fp.as_deref()` to `extract_session_key()`.
  - A request without `SESSIONID` cookie but with a populated `FpKey` is now tracked under `SessionIdent::Fingerprint`.
- **Non-functional**:
  - Zero allocations on the hot path beyond the existing `Arc::clone`.
  - `RequestCtx::clone()` cost unchanged in O(1) terms (`Option<Arc<_>>` is one pointer + tag).

## Architecture

```
proxy.rs::request_filter
  ├─ device_fp_detector.process(...)  →  ctx.device_identity = Some(DeviceIdentity { key: Arc<FpKey>, .. })
  ├─ RequestCtxBuilder::new(...)
  │    .with_host_config(...)
  │    .with_tier_registry(...)
  │    .with_device_fp(ctx.device_identity.as_ref().map(|d| Arc::clone(&d.key)))   ← NEW
  │    .build()
  └─ ctx.request_ctx = Some(built)

waf-engine::WafEngine.evaluate(ctx)
  └─ TxVelocityCheck.check(ctx)
       └─ extract_session_key(ctx, &snapshot.session_cookie, ctx.device_fp.as_deref())
                                                                    ───── line 55 TODO closed ─────
```

## Related Code Files

- **Modify** `crates/waf-common/src/types.rs` — add `pub device_fp: Option<Arc<FpKey>>` field to `RequestCtx`. Update all in-crate constructors / `Default` impls.
- **Modify** `crates/gateway/src/ctx_builder/request_ctx_builder.rs` — add `with_device_fp(Option<Arc<FpKey>>) -> Self` setter; thread into the built struct.
- **Modify** `crates/gateway/src/proxy.rs:551` — chain `.with_device_fp(ctx.device_identity.as_ref().map(|d| Arc::clone(&d.key)))` on the builder.
- **Modify** `crates/waf-engine/src/checks/tx_velocity/check.rs:55-56` — replace `None` with `ctx.device_fp.as_deref()` and delete the `TODO: FR-010 …` line.
- **Modify** every `RequestCtx { … }` struct-literal in tests across the workspace — add `device_fp: None`. Grep gate below catches them.

## TDD Steps

### Step 2.1 — failing test: TxVelocityCheck records via fp when cookie absent

Add to `crates/waf-engine/src/checks/tx_velocity/check.rs` `mod tests`:

```rust
#[test]
fn cookie_absent_but_fp_present_records_event() {
    use crate::device_fp::types::{FingerprintValue, FpKey};
    use std::sync::Arc;

    let cfg = cfg_enabled(
        "SID",
        &[RoleRule { role: EndpointRole::Withdrawal, path: "^/api/withdraw".to_string() }],
    );
    let store = Arc::new(TxStore::new(Arc::clone(&cfg)));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let mut ctx = ctx_with_path_and_cookie("/api/withdraw", "SID", "");
    ctx.cookies.clear();
    ctx.device_fp = Some(Arc::new(FpKey {
        ja3: Some(FingerprintValue::new("ja3-x")),
        ..FpKey::default()
    }));

    assert!(check.check(&ctx).is_none(), "signal-only");
    assert_eq!(store.len(), 1, "fp fallback should have recorded the event");
}

#[test]
fn empty_fp_and_no_cookie_skips_recording() {
    let cfg = cfg_enabled(
        "SID",
        &[RoleRule { role: EndpointRole::Login, path: "^/api/login$".to_string() }],
    );
    let store = Arc::new(TxStore::new(Arc::clone(&cfg)));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let mut ctx = ctx_with_path_and_cookie("/api/login", "SID", "");
    ctx.cookies.clear();
    ctx.device_fp = Some(Arc::new(FpKey::default()));  // empty key
    assert!(check.check(&ctx).is_none());
    assert!(store.is_empty(), "empty fp must not bucket all anon traffic under one key");
}
```

Run: `cargo test -p waf-engine tx_velocity::check::tests::cookie_absent_but_fp_present_records_event`. **Expected: fails to compile** (`device_fp` field unknown).

### Step 2.2 — add the field to RequestCtx + Default impl

In `crates/waf-common/src/types.rs`:

1. After the `cookies` field, add two new fields:
   ```rust
   /// Resolved device fingerprint key (FR-010) when the device-fp pipeline
   /// produced a non-empty key. `None` when device-fp is disabled, the
   /// observation produced no fingerprint values, or the request was built
   /// before device-fp resolution. Consumed by FR-012 `TxVelocityCheck` to
   /// fall back from cookie to fingerprint as the session identity.
   pub device_fp: Option<Arc<FpKey>>,

   /// Token returned by `TxStore::record()` so `TxStore::set_outcome()` can
   /// flip the exact event slot at response time without a role-walk race.
   /// Populated by `TxVelocityCheck::check()`; consumed by
   /// `TxVelocityCheck::on_request_complete()`. Opaque to other checks.
   pub tx_velocity_token: Option<waf_common_tx::TxEventToken>,
   ```

   The `TxEventToken` type lives in `waf-common` (added in Phase 3, Step 3.0) so `RequestCtx` does not need a `waf-engine` dependency.

2. **(Red-team C5)** Add a `Default` impl:
   ```rust
   impl Default for RequestCtx {
       fn default() -> Self {
           Self {
               req_id: String::new(),
               client_ip: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
               client_port: 0,
               method: String::new(),
               host: String::new(),
               port: 0,
               path: String::new(),
               query: String::new(),
               headers: HashMap::new(),
               body_preview: Bytes::new(),
               content_length: 0,
               is_tls: false,
               host_config: Arc::new(HostConfig::default()),
               geo: None,
               tier: Tier::CatchAll,
               tier_policy: Arc::new(TierPolicy::default()),
               cookies: HashMap::new(),
               device_fp: None,
               tx_velocity_token: None,
           }
       }
   }
   ```

   With `Default`, test fixtures collapse from 19-field struct literals to:
   ```rust
   RequestCtx {
       path: "/api/withdraw".into(),
       cookies: hm,
       ..Default::default()
   }
   ```

3. **(Red-team C7)** In `crates/waf-engine/src/checks/tx_velocity/session_key.rs`, change the `SessionIdent` enum and key extractor:
   ```rust
   pub enum SessionIdent {
       Cookie(String),
       Fingerprint { fp: FpKey, ip: IpAddr },   // was: Fingerprint(FpKey)
   }

   pub fn extract_session_key(
       ctx: &RequestCtx,
       cookie_name: &str,
       fp: Option<&FpKey>,
       peer_ip: IpAddr,   // new param
   ) -> Option<SessionKey> { ... }
   ```
   Call site in `check.rs` becomes:
   ```rust
   extract_session_key(ctx, &snapshot.session_cookie, ctx.device_fp.as_deref(), ctx.client_ip)
   ```
   Update existing `session_key.rs` tests — `SessionIdent::Fingerprint(fp)` → `SessionIdent::Fingerprint { fp, ip }`. Cookie-wins path is unchanged.

### Step 2.3 — update the gateway builder

In `crates/gateway/src/ctx_builder/request_ctx_builder.rs`:

1. Add field `device_fp: Option<Arc<FpKey>>` to the builder struct, initialised to `None` in `new()`.
2. Add method:
   ```rust
   #[must_use]
   pub fn with_device_fp(mut self, fp: Option<Arc<FpKey>>) -> Self {
       self.device_fp = fp;
       self
   }
   ```
3. Thread `self.device_fp` into the built `RequestCtx` in `build()`.

### Step 2.4 — wire from proxy.rs

In `crates/gateway/src/proxy.rs` around line 551 (request_ctx construction):

```rust
let mut builder = RequestCtxBuilder::new(session, self.trust_proxy_headers, &self.trusted_proxies)
    .with_host_config(host_config);
if let Some(reg) = &self.tier_registry {
    builder = builder.with_tier_registry(reg);
}
// FR-012 close TODO — propagate resolved FpKey into RequestCtx so
// TxVelocityCheck can fall back from cookie to fingerprint.
builder = builder.with_device_fp(
    ctx.device_identity
        .as_ref()
        .filter(|d| !d.key.is_empty())
        .map(|d| Arc::clone(&d.key)),
);
let mut built = builder.build();
```

The `.filter(|d| !d.key.is_empty())` is critical — empty `FpKey` must not become a tracked identity (matches `behavior_record.rs:29-30` semantics).

### Step 2.5 — close the TODO

In `crates/waf-engine/src/checks/tx_velocity/check.rs:54-56`:

```rust
// BEFORE
// Extract session identity (cookie preferred, then fingerprint).
// TODO: FR-010 integration — pass actual FpKey when device_fp is wired.
let key = extract_session_key(ctx, &snapshot.session_cookie, None)?;

// AFTER
// Extract session identity (cookie preferred, then fingerprint).
let key = extract_session_key(ctx, &snapshot.session_cookie, ctx.device_fp.as_deref())?;
```

### Step 2.6 — sweep test fixtures

**(Red-team C5 — corrected estimate)** `grep -rn "RequestCtx {" crates/ --include="*.rs" | wc -l` returns **164 hits across 72 files**, not "30-50". Distribution:

- `crates/waf-engine/` — recorder tests, integration tests, benches (`risk_anomaly.rs`, `rule_eval.rs`, `sql_injection.rs`)
- `crates/gateway/` — `fr018_brute_force_dispatch.rs`, `proxy_waf_response_writer.rs`, `waf_observability_headers.rs`, `tests/common/mod.rs`, `tests/ddos_scenarios/mod.rs`, `tests/support/owasp_helpers.rs`
- `crates/waf-api/`, `crates/prx-waf/` — handler tests, server fixtures
- `crates/waf-common/` — type-level tests

**Two strategies, applied in this order:**

1. **`..Default::default()` migration** — for fixtures that don't care about every field. `cargo check --workspace` after Step 2.2 will compile-error on every missing field. Add `..Default::default()` to all literals that don't exhaustively set all 19 fields. This collapses most of the 164 sites to a one-line spread.
2. **Field-by-field** — for fixtures that genuinely set every field (rare; ~5-10 sites). Add `device_fp: None, tx_velocity_token: None,`.

Discovery command:
```bash
grep -rn "RequestCtx {" crates/ --include="*.rs" \
    | grep -v "/target/" \
    | cut -d: -f1 | sort -u
```

Each site falls into one of two buckets — `cargo check` is the authoritative check.

### Step 2.7 — make tests pass

```bash
cargo check --workspace
cargo test -p waf-engine tx_velocity
cargo test -p gateway
cargo test --workspace
```

## Success Criteria

- [ ] Both new `tx_velocity` tests pass.
- [ ] `cargo check --workspace` clean (catches any missed `RequestCtx` literal).
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `grep -n "TODO: FR-010" crates/waf-engine/src/checks/tx_velocity/check.rs` returns empty.
- [ ] `cargo test --workspace` passes — no regressions in `device_fp`, `behavior`, `brute_force`, or other consumers of `RequestCtx`.
- [ ] No `.unwrap()` introduced (Iron Rule #1).

## Risk Assessment

| Risk | Mitigation |
|---|---|
| `RequestCtx` struct literal in some integration test file is missed | `cargo check --workspace` is total — compile error pinpoints every site. `..Default::default()` migration absorbs most of them. |
| `Default` impl encodes wrong default for a field (e.g. wrong tier policy) | One-time review; all callers were already passing the same defaults via copy-paste. |
| `device_identity.key` is `Arc<FpKey>` but empty when only UA-only providers fired (`proxy.rs:524`) | `.filter(|d| !d.key.is_empty())` guard. Empty key never enters `RequestCtx`. |
| FR-010 hot path allocates a new `Arc` per request | NO — `Arc::clone` is a refcount bump. `DeviceIdentity.key` is already `Arc<FpKey>`. |
| Test fixtures default-construct `RequestCtx` somewhere (no struct literal) | Grep for `Default::default()` and `RequestCtx::default()` — if any, add a `Default` impl on `RequestCtx` that sets `device_fp: None`. Currently no `Default` impl exists; this is fine. |

## Notes

After this phase, the `check.rs:55` TODO is fully closed. The `check.rs:60` deferred-ok comment is still present — phase-03 closes it.
