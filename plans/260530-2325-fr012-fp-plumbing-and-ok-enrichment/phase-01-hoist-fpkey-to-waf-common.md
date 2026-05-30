---
phase: 1
title: "Hoist FpKey to waf-common"
status: done
priority: P2
effort: "1-2h"
dependencies: []
---

# Phase 1: Hoist FpKey to waf-common

## Overview

`RequestCtx` lives in `waf-common`. `FpKey` lives in `waf-engine::device_fp::types`. `waf-common` is the leaf crate and **cannot** depend on `waf-engine`. Before we can add `device_fp: Option<Arc<FpKey>>` to `RequestCtx` (phase-02), `FpKey` (and its only dependency `FingerprintValue`) must move into `waf-common`.

This is a **mechanical move + re-export** — zero behavior change. Done as a discrete phase so phase-02 can land cleanly without entangled type churn.

## Requirements

- **Functional**: `FpKey` and `FingerprintValue` types accessible from `waf_common::FpKey` (and back-compat from `waf_engine::device_fp::types::FpKey`).
- **Non-functional**: No new dependencies pulled into `waf-common`. `serde` is already in `waf-common` so the existing `#[derive(Serialize, Deserialize)]` keeps compiling.

## Architecture

```
BEFORE                                      AFTER
─────────                                   ──────
waf-common::types  (no fp)                  waf-common::types::{FpKey, FingerprintValue}
                                                          ↑
waf-engine::device_fp::types                waf-engine::device_fp::types
  ├─ FingerprintValue (defn)                  ├─ pub use waf_common::FingerprintValue;
  ├─ FpKey (defn)                             ├─ pub use waf_common::FpKey;
  ├─ DeviceCtx<'a>                            ├─ DeviceCtx<'a>          (unchanged)
  ├─ Observation                              ├─ Observation            (unchanged)
  ├─ IdentityRecord                           ├─ IdentityRecord         (unchanged)
  └─ DeviceIdentity                           └─ DeviceIdentity         (unchanged)
```

`DeviceCtx`, `Observation`, `IdentityRecord`, `DeviceIdentity` stay in `waf-engine` — they pull in engine-internal types (`Signal`, `ConnCtx`, `DeviceDerived`) and have no business in the leaf crate.

## Related Code Files

- **Modify** `crates/waf-common/src/types.rs` — paste in `FingerprintValue` + `FpKey` defs near `GeoIpInfo`.
- **Modify** `crates/waf-common/src/lib.rs` — re-export `pub use types::{FpKey, FingerprintValue};` if other types are re-exported there (mirror existing pattern).
- **Modify** `crates/waf-engine/src/device_fp/types.rs:21-56` — delete the two defs, replace with `pub use waf_common::{FpKey, FingerprintValue};`.
- **Read for context** `crates/waf-engine/src/device_fp/mod.rs` — public re-exports must continue to surface `FpKey` / `FingerprintValue` at the `waf_engine::device_fp::FpKey` path used by `gateway` and tests.

## TDD Steps

### Step 1.1 — write the failing test (waf-common)

Add to `crates/waf-common/src/types.rs` `#[cfg(test)] mod tests`:

```rust
#[test]
fn fp_key_is_reachable_from_waf_common() {
    // Compile-time guard — if this file doesn't host FpKey, the test won't compile.
    let _: FpKey = FpKey::default();
    let _: FingerprintValue = FingerprintValue::new("ja3-xxx");
}

#[test]
fn fp_key_is_empty_matches_pre_move_semantics() {
    assert!(FpKey::default().is_empty());
    let with_ja3 = FpKey { ja3: Some(FingerprintValue::new("x")), ..FpKey::default() };
    assert!(!with_ja3.is_empty());
}
```

Run: `cargo test -p waf-common`. **Expected: fails to compile** (`FpKey` not in scope).

### Step 1.2 — move the types

1. Cut `FingerprintValue` (struct + impl) and `FpKey` (struct + impl) from `crates/waf-engine/src/device_fp/types.rs:21-56`.
2. Paste into `crates/waf-common/src/types.rs` immediately after `GeoIpInfo` (line ~17). Imports needed: `serde::{Deserialize, Serialize}` (already in scope at top of file).

   **(Red-team C12 — derive list MUST be preserved verbatim — `Hash` is load-bearing for `DashMap<SessionKey, ActorTx>` keying.)**

   ```rust
   #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
   pub struct FingerprintValue(pub String);

   #[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
   pub struct FpKey {
       pub ja3: Option<FingerprintValue>,
       pub ja4: Option<FingerprintValue>,
       pub h2_akamai: Option<FingerprintValue>,
   }
   ```

   Copy the existing `impl FingerprintValue` and `impl FpKey` blocks verbatim.

3. In `crates/waf-engine/src/device_fp/types.rs`, replace the deleted block with:
   ```rust
   pub use waf_common::{FingerprintValue, FpKey};
   ```
   **Leave the `use crate::device_fp::capture::ConnCtx; use crate::device_fp::signal::Signal;` lines intact** — `DeviceCtx<'a>` and `DeviceIdentity` still live in this file and still need them.
4. Re-export from `waf-common` lib root if `types::*` is not already glob-exported — check `crates/waf-common/src/lib.rs` first; mirror what's done for `GeoIpInfo` / `RequestCtx`.

### Step 1.3 — make the test pass + sweep call sites

Run from workspace root:

```bash
cargo check -p waf-common
cargo check -p waf-engine
cargo check -p gateway
cargo check --workspace
```

If any imports break, they are using a non-canonical path. Standardize on:
- Inside `waf-engine`: keep `use crate::device_fp::types::FpKey;` (works via re-export)
- Inside `gateway` / consumers: keep `use waf_engine::device_fp::FpKey;` (works via existing `device_fp/mod.rs` re-export)

Do NOT mass-rewrite imports unless they fail.

### Step 1.4 — run the existing test suite

```bash
cargo test -p waf-common
cargo test -p waf-engine --lib device_fp
cargo test -p waf-engine --lib checks::tx_velocity
```

All existing tests must keep passing — this is a no-behavior-change move.

## Success Criteria

- [ ] `cargo test -p waf-common` passes both new tests
- [ ] `cargo check --workspace` clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `grep -rn "pub struct FpKey\|pub struct FingerprintValue" crates/` returns exactly ONE definition site (`crates/waf-common/src/types.rs`)
- [ ] **(Red-team C25)** Positive compile-check fixture passes: `use waf_common::FpKey; use waf_common::FingerprintValue;` resolves at the lib root (not just `waf_common::types::FpKey`) — confirms `lib.rs` re-export is correct.
- [ ] `grep -n "Hash" crates/waf-common/src/types.rs` shows `Hash` in BOTH `FpKey` and `FingerprintValue` derive lists.
- [ ] `cargo test -p waf-engine --lib` passes unchanged (no test rewrites required this phase)
- [ ] No new dependency added to `crates/waf-common/Cargo.toml`

## Risk Assessment

| Risk | Mitigation |
|---|---|
| `serde` derive feature not enabled in `waf-common` for these types | `waf-common` already derives `Serialize`/`Deserialize` for `GeoIpInfo`; same feature set. Verified before edit. |
| External crate (admin UI, integration test) imports from old path | `pub use` shim in old location keeps all paths working. Verified by `cargo check --workspace`. |
| Hidden cyclic dep (waf-common → waf-engine via re-export?) | Only `waf-engine` re-exports from `waf-common`, never the reverse. Cycle impossible. |

## Notes

This phase is a pure refactor — no test in `tx_velocity` changes. The two failing-compile guards in `waf-common::types::tests` are the only new tests.
