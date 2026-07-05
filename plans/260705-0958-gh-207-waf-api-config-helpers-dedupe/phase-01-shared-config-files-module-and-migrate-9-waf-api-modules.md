---
phase: 1
title: "Shared config_files module and migrate 9 waf-api modules"
status: pending
effort: "3h"
---

# Phase 1: Shared config_files module and migrate 9 waf-api modules

## Overview

Collapse the byte-identical `resolve_path` (×9) and the atomic tmp-write-rename
(×10, counting `geo_api::write_rules`) into one private
`crates/waf-api/src/config_files.rs`. Pure dedupe — no handler, contract, or
config-file-shape change. Per-module read semantics are intentionally preserved,
not unified (see Key Decisions in plan.md).

## Requirements

- Behavior-preserving: every `resolve_path(state, rel)` result identical to today
  (walk `state.main_config_file` up two parents, fallback to `rel`; geo keeps its
  hardcoded `"configs/geo-rules.yaml"` default branch value).
- Atomic-write behavior identical: `create_dir_all(parent)` → serialize →
  `path.with_extension("yaml.tmp")` → `tokio::fs::write` → `tokio::fs::rename`.
- Error variants preserved per module (Internal for IO/serialize; challenge keeps
  `BadRequest` on parse; relay/ddos/tx_velocity keep their `Internal` parse text).
- `tls.rs` unchanged (documented out-of-scope: sync `std::fs`, PEM + `chmod 600`).

## Files to create / modify

- Create: `crates/waf-api/src/config_files.rs`
- Register: `crates/waf-api/src/lib.rs` — add `mod config_files;` (private crate
  module; verify placement against existing `mod` list).
- Modify (delete local `resolve_path` + local atomic writer, import shared):
  - `crates/waf-api/src/risk_api.rs` (`resolve_path:21`, `read_yaml_opt:35`,
    `write_yaml:40`) — NOTE: coordinate with GH-196 Phase 3 which rewrites this
    file's GET/PUT; migrate the helpers only.
  - `crates/waf-api/src/tier_policies_api.rs` (`:14`, `read_yaml_opt:28`, `write_yaml:33`)
  - `crates/waf-api/src/access_lists_api.rs` (`:18`, `read_yaml_opt:32`, `write_yaml:37`)
  - `crates/waf-api/src/device_fp_api.rs` (`:15`, `read_yaml_opt:29`, `write_yaml:34`)
  - `crates/waf-api/src/challenge_api.rs` (`:17`, `write_yaml:38`) — keep local
    `read_yaml` (BadRequest-on-parse), migrate `resolve_path` + `write_yaml`.
  - `crates/waf-api/src/relay_api.rs` (`:16`) — migrate `resolve_path`; replace the
    two inline atomic writes (`get`/`put` ~`:58`) with `write_yaml_str`.
  - `crates/waf-api/src/ddos_api.rs` (`:37`) — migrate `resolve_path`; inline write
    (~`:80`) → `write_yaml_str`.
  - `crates/waf-api/src/tx_velocity_api.rs` (`:25`) — migrate `resolve_path`; inline
    write (~`:84`) → `write_yaml_str` (keep the pre-write validation ordering).
  - `crates/waf-api/src/geo_api.rs` (`rules_path:20`, `write_rules:46`) —
    `rules_path` → `resolve_path(state, "configs/geo-rules.yaml")`; `write_rules`
    body → `write_yaml(path, &json!({"rules": rules}))`; `read_rules` → call
    `read_yaml_opt(path)` then `.get("rules").and_then(as_array)` (preserve
    `vec![]` fallback).

## config_files.rs public surface (crate-private)

```rust
use crate::error::ApiError;          // confirm ApiError path
use crate::state::AppState;          // confirm AppState path
use serde_json::Value;
use std::path::{Path, PathBuf};

pub(crate) fn resolve_path(state: &AppState, relative: &str) -> PathBuf { /* verbatim */ }

pub(crate) async fn read_yaml_opt(path: &Path) -> Option<Value> {
    let raw = tokio::fs::read_to_string(path).await.ok()?;
    serde_yaml::from_str::<Value>(&raw).ok()
}

/// Atomic: create parent, write `.yaml.tmp`, rename over `path`.
pub(crate) async fn write_yaml_str(path: &Path, contents: &str) -> Result<(), ApiError> { /* the shared core */ }

pub(crate) async fn write_yaml(path: &Path, value: &Value) -> Result<(), ApiError> {
    let s = serde_yaml::to_string(value).map_err(/* Internal */)?;
    write_yaml_str(path, &s).await
}
```

Confirm `ApiError` variant names and `AppState.main_config_file` type by reading
`crates/waf-api/src/error.rs` and `crates/waf-api/src/state.rs` before writing.

## Implementation Steps

1. Read `error.rs`, `state.rs`, and one representative module fully (risk_api or
   tier_policies_api) to lock the exact `resolve_path` body and error variants.
2. Write `config_files.rs`; register `mod config_files;` in `lib.rs`.
3. Migrate the 4 uniform Value modules (risk, tier_policies, access_lists,
   device_fp): delete local `resolve_path`/`read_yaml_opt`/`write_yaml`, add
   `use crate::config_files::{resolve_path, read_yaml_opt, write_yaml};`.
4. Migrate challenge (keep local `read_yaml`), relay/ddos/tx_velocity (typed
   writers → `write_yaml_str`), geo (`rules_path`, `write_rules`, `read_rules`).
5. Remove now-orphaned imports (`serde_yaml`, `tokio::fs`) only where fully unused.
6. `cargo build -p waf-api` → `cargo clippy -p waf-api` → fix orphans.

## Tests / Validation

- Baseline: `cargo test -p waf-api` green on HEAD before edits (capture list).
- After: `cargo test -p waf-api` — same tests green, no new/removed cases.
- `cargo build -p waf-api`, `cargo clippy -p waf-api --all-targets` clean.
- Manual spot-check: a GET then PUT round-trip test for one migrated module
  (e.g. tier-policies) still writes `<name>.yaml` atomically (tmp file gone,
  content unchanged shape).

## Risks & Rollback

- **Risk (Low/Med):** `geo_api.rs` also edited by GH-197. Mitigation: touch only
  `rules_path`/`write_rules`/`read_rules`; whoever lands second rebases the swap.
- **Risk (Low):** challenge/relay/ddos/tx_velocity error text drift. Mitigation:
  keep their serialize/parse error strings local; only the atomic write is shared.
- **Rollback:** revert the phase commit; each module's local helpers were pure
  copies, so restoration is mechanical and leaves no state behind.

## Success Criteria

- [ ] `config_files.rs` exists; `resolve_path` + atomic writer defined exactly once.
- [ ] All 9 modules import the shared helpers; no duplicate `fn resolve_path` /
      `rules_path` / inline tmp+rename remains in waf-api (grep-clean, except tls.rs).
- [ ] `tls.rs` untouched.
- [ ] `cargo test -p waf-api` green (same set before/after); build + clippy clean.
