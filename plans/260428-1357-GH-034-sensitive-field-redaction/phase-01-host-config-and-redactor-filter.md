# Phase 01 — HostConfig Fields + Redactor Filter (logic + tests)

**Goal:** Land the per-host config fields and the pure redactor logic. **No** WafProxy wiring, **no** Pingora hook changes. Compilable + clippy-clean + 19 unit tests pass before Phase 02 starts.

**Status:** todo
**Mirrors:** AC-17 `gateway::filters::response_body_mask_filter` (study `crates/gateway/src/filters/response_body_mask_filter.rs:1-80` for the pattern; FR-034 follows it 1:1).

## Files Touched

| File | Change |
|------|--------|
| `crates/waf-common/src/types.rs` | Add 10 fields to `HostConfig` (6 family bools + extras + mask + cap + case-flag); add 2 `default_*` helpers; extend `impl Default for HostConfig` |
| `crates/gateway/src/filters/response_json_field_redactor.rs` | **NEW** — `CompiledRedactor`, family const tables, recursive walker, `apply_chunk` API, 19 unit tests |
| `crates/gateway/src/filters/mod.rs` | Add `pub mod response_json_field_redactor;` and `pub use response_json_field_redactor::{CompiledRedactor, apply_chunk as apply_redact_chunk};` |
| `crates/gateway/Cargo.toml` | Add `serde_json = { workspace = true }` if missing (gateway crate may not have it yet — verify) |

No changes to `proxy.rs`, `context.rs`, or any TOML in this phase.

## 1. `HostConfig` Field Additions

Append AFTER the existing AC-17 fields (`internal_patterns`, `mask_token`, `body_mask_max_bytes`) at `crates/waf-common/src/types.rs:188`:

```rust
    /// FR-034: PCI-DSS payment-card field family. When true, JSON values whose
    /// keys are in the PCI catalog (`card_number`, `cvv`, `pin`, `expiration_date`,
    /// the `cc_*` and `creditcard` aliases) are replaced with `redact_mask_token`
    /// in identity-encoded JSON response bodies. Default off — explicit opt-in.
    #[serde(default)]
    pub redact_pci: bool,
    /// FR-034: Banking field family (`bank_account`, `account_number`,
    /// `routing_number`, `iban`, `bic`, `swift_code`). Default off.
    #[serde(default)]
    pub redact_banking: bool,
    /// FR-034: Identity field family (`ssn`, `tax_id`, `passport_number`,
    /// `driver_license`, `national_id`). Default off.
    #[serde(default)]
    pub redact_identity: bool,
    /// FR-034: Secret / credential field family (`password`, `token`,
    /// `api_key`, `secret`, `client_secret`, `refresh_token`, `access_token`,
    /// `private_key`). Default off.
    #[serde(default)]
    pub redact_secrets: bool,
    /// FR-034: PII field family (`email`, `phone_number`, `dob`,
    /// `mother_maiden_name`). Default off — high false-positive surface in
    /// legitimate user-listing APIs.
    #[serde(default)]
    pub redact_pii: bool,
    /// FR-034: PHI field family (`patient_id`, `medical_record_number`,
    /// `insurance_id`, `health_record`). Default off — HIPAA scope only.
    #[serde(default)]
    pub redact_phi: bool,
    /// FR-034: Operator-supplied additional field names. Extends every active
    /// family. Case-folded at compile time when `redact_case_insensitive=true`.
    #[serde(default)]
    pub redact_extra_fields: Vec<String>,
    /// FR-034: Replacement token written in place of every matched JSON field
    /// value. Distinct from AC-17 `mask_token` to keep the two redaction
    /// surfaces independently observable in logs / responses.
    #[serde(default = "default_redact_mask_token")]
    pub redact_mask_token: String,
    /// FR-034: Hard ceiling on bytes buffered per response. Beyond this,
    /// the response is forwarded unredacted with a single `tracing::warn!`.
    #[serde(default = "default_redact_max_bytes")]
    pub redact_max_bytes: u64,
    /// FR-034: Match field names case-insensitively. Default true — HTTP/JSON
    /// convention. Switch to false only if your backend deliberately
    /// distinguishes `cardNumber` from `CardNumber`.
    #[serde(default = "default_true")]
    pub redact_case_insensitive: bool,
```

Add helper functions next to the AC-17 helpers (`default_mask_token`, `default_body_mask_max_bytes` around line 198):

```rust
fn default_redact_mask_token() -> String {
    "***REDACTED***".to_string()
}

const fn default_redact_max_bytes() -> u64 {
    256 * 1024
}

const fn default_true() -> bool {
    true
}
```

Extend `impl Default for HostConfig` (around line 206) — add the new fields to the struct literal:

```rust
            redact_pci: false,
            redact_banking: false,
            redact_identity: false,
            redact_secrets: false,
            redact_pii: false,
            redact_phi: false,
            redact_extra_fields: Vec::new(),
            redact_mask_token: default_redact_mask_token(),
            redact_max_bytes: default_redact_max_bytes(),
            redact_case_insensitive: true,
```

**No breaking changes:** existing TOMLs / DB rows lacking these fields parse via `#[serde(default)]`.

**`#[allow(clippy::struct_excessive_bools)]` already on `HostConfig`** at line 141 — the 6 new bools are covered.

## 2. New Filter Module

Create `crates/gateway/src/filters/response_json_field_redactor.rs`. Total budget ≤ 350 LOC including tests; if it grows beyond, split into `response_json_field_redactor/{mod.rs, families.rs, walker.rs}` per the plan's note.

### 2.1 Module Header

```rust
//! FR-034 — JSON response-body sensitive-field redactor.
//!
//! Mirrors the AC-17 body-mask filter (sibling file
//! `response_body_mask_filter.rs`): per-host compiled config cached on
//! `WafProxy`, streaming chunk-by-chunk via `response_body_filter`. Difference
//! from AC-17: AC-17 does *byte-level regex value masking*; FR-034 buffers
//! the full body, parses JSON, and redacts values whose KEYS are in a
//! configured catalog. Composes with AC-17 — see `WafProxy::response_body_filter`.
//!
//! Detection cases (field-name catalogs per family) are hard-coded; activation
//! is per-host via `HostConfig::redact_*` fields.
//!
//! Skip conditions (decided in `proxy::response_filter`):
//! * Content-Encoding != identity / absent
//! * Content-Type not application/json or application/*+json
//! * `CompiledRedactor::is_noop()` (every family off + zero extras)
//!
//! Failure mode: fail-open (forward original on cap overflow / malformed JSON
//! / parse error). Single `tracing::warn!` per occurrence.
```

### 2.2 Family Const Tables

```rust
// All entries lower-case so `case_insensitive` mode is one HashMap lookup.

const PCI_FIELDS: &[&str] = &[
    "card_number", "cardnumber", "credit_card", "creditcard",
    "cc_number", "ccnumber", "cvv", "cvc", "cvv2",
    "expiration_date", "exp_date", "pin",
];
const BANKING_FIELDS: &[&str] = &[
    "bank_account", "bankaccount", "account_number", "accountnumber",
    "routing_number", "iban", "bic", "swift_code",
];
const IDENTITY_FIELDS: &[&str] = &[
    "ssn", "social_security_number", "tax_id",
    "passport_number", "driver_license", "national_id",
];
const SECRET_FIELDS: &[&str] = &[
    "password", "api_key", "apikey", "secret", "client_secret",
    "token", "auth_token", "access_token", "refresh_token", "private_key",
];
const PII_FIELDS: &[&str] = &[
    "phone_number", "phonenumber", "email", "email_address",
    "dob", "date_of_birth", "mother_maiden_name",
];
const PHI_FIELDS: &[&str] = &[
    "patient_id", "medical_record_number", "insurance_id", "health_record",
];
```

### 2.3 `CompiledRedactor`

```rust
use std::collections::HashSet;
use std::sync::Arc;

use bytes::Bytes;
use waf_common::HostConfig;

/// Compiled per-host redactor. Built once per `Arc<HostConfig>`, cached on the
/// proxy keyed by pointer identity (same pattern as `CompiledMask`).
pub struct CompiledRedactor {
    /// Active field-name set after applying family toggles + extras +
    /// case-folding. `None` when redactor is a noop.
    pub fields: Option<HashSet<String>>,
    /// Replacement token bytes (UTF-8 of `HostConfig::redact_mask_token`).
    pub mask: Bytes,
    /// Hard cap on buffered bytes per response.
    pub max_bytes: u64,
    /// Whether matches are case-insensitive.
    pub case_insensitive: bool,
}

impl CompiledRedactor {
    /// Build from a `HostConfig`. Returns a redactor that may be a no-op.
    pub fn build(hc: &HostConfig) -> Self {
        let mut set: HashSet<String> = HashSet::new();
        let mut push = |slice: &[&str]| {
            for f in slice {
                if hc.redact_case_insensitive {
                    set.insert((*f).to_ascii_lowercase());
                } else {
                    set.insert((*f).to_string());
                }
            }
        };
        if hc.redact_pci      { push(PCI_FIELDS); }
        if hc.redact_banking  { push(BANKING_FIELDS); }
        if hc.redact_identity { push(IDENTITY_FIELDS); }
        if hc.redact_secrets  { push(SECRET_FIELDS); }
        if hc.redact_pii      { push(PII_FIELDS); }
        if hc.redact_phi      { push(PHI_FIELDS); }
        for f in &hc.redact_extra_fields {
            let key = if hc.redact_case_insensitive {
                f.to_ascii_lowercase()
            } else {
                f.clone()
            };
            set.insert(key);
        }

        let fields = if set.is_empty() { None } else { Some(set) };
        Self {
            fields,
            mask: Bytes::copy_from_slice(hc.redact_mask_token.as_bytes()),
            max_bytes: hc.redact_max_bytes,
            case_insensitive: hc.redact_case_insensitive,
        }
    }

    /// `true` when there is nothing to do (no families on, no extras).
    pub const fn is_noop(&self) -> bool {
        self.fields.is_none()
    }

    /// Returns Some(new bytes) on successful redaction. `None` if input
    /// wasn't valid JSON or no field matched (caller forwards original — cheaper
    /// than re-serialising the parsed value).
    pub fn redact_bytes(&self, input: &[u8]) -> Option<Vec<u8>> {
        let Some(fields) = self.fields.as_ref() else {
            return None;
        };
        let mut value: serde_json::Value = serde_json::from_slice(input).ok()?;
        let mut hits: usize = 0;
        let mask_str = std::str::from_utf8(&self.mask).ok()?;
        walk(&mut value, fields, mask_str, self.case_insensitive, &mut hits);
        if hits == 0 {
            return None;
        }
        serde_json::to_vec(&value).ok()
    }
}

fn walk(
    v: &mut serde_json::Value,
    fields: &HashSet<String>,
    mask: &str,
    case_insensitive: bool,
    hits: &mut usize,
) {
    use serde_json::Value::{Array, Object};
    match v {
        Object(map) => {
            // Collect keys first to avoid double-borrowing during mutation.
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                let lookup = if case_insensitive { k.to_ascii_lowercase() } else { k.clone() };
                if fields.contains(&lookup) {
                    if let Some(slot) = map.get_mut(&k) {
                        *slot = serde_json::Value::String(mask.to_string());
                        *hits += 1;
                    }
                } else if let Some(child) = map.get_mut(&k) {
                    walk(child, fields, mask, case_insensitive, hits);
                }
            }
        }
        Array(arr) => {
            for item in arr {
                walk(item, fields, mask, case_insensitive, hits);
            }
        }
        _ => {}
    }
}

/// Content-type acceptance — JSON only.
pub fn is_json_content_type(ct: &str) -> bool {
    let lower = ct.to_ascii_lowercase();
    let primary = lower.split(';').next().unwrap_or("").trim();
    primary == "application/json"
        || primary == "application/problem+json"
        || (primary.starts_with("application/") && primary.ends_with("+json"))
}
```

### 2.4 Streaming `BodyRedactState` + `apply_chunk`

Mirrors `apply_body_mask_chunk` from AC-17 (signature shape, `body.take()` semantics, `state.processed` cap-counter, `tracing::warn!` once-only).

```rust
use bytes::BytesMut;

/// Per-response state for the streaming JSON redactor (FR-034).
///
/// `enabled` is decided in `WafProxy::response_filter` once Content-Encoding
/// AND Content-Type are known. Compressed / non-JSON / noop bypass.
#[derive(Default)]
pub struct BodyRedactState {
    /// Whether redaction should run for this response.
    pub enabled: bool,
    /// Buffered body bytes pending parse on EOS or cap.
    pub buffer: BytesMut,
    /// Total bytes accumulated so far. Reaching `max_bytes` triggers fail-open.
    pub processed: u64,
    /// `true` once redaction emitted (success or fail-open). Idempotency guard.
    pub done: bool,
    /// `true` once cap-overflow was logged (avoid spamming).
    pub overflow_logged: bool,
}

/// Apply the redactor to one chunk. Buffers chunks until EOS or cap, then
/// parses + redacts + emits the full body in `*body`. While buffering,
/// `*body` is set to `None` so downstream filters (notably AC-17) see nothing.
pub fn apply_chunk(
    state: &mut BodyRedactState,
    compiled: &Arc<CompiledRedactor>,
    body: &mut Option<Bytes>,
    eos: bool,
) {
    if !state.enabled || compiled.is_noop() || state.done {
        return;
    }

    // 1. Append the chunk; track byte budget.
    if let Some(chunk) = body.take() {
        state.processed = state.processed.saturating_add(chunk.len() as u64);
        if state.processed > compiled.max_bytes {
            // Cap exceeded — fail-open: forward accumulated buffer + this chunk untouched.
            if !state.overflow_logged {
                tracing::warn!(
                    processed = state.processed,
                    limit = compiled.max_bytes,
                    "json-redact: byte ceiling reached, forwarding remainder unchanged"
                );
                state.overflow_logged = true;
            }
            let drained = std::mem::take(&mut state.buffer);
            let mut joined = BytesMut::with_capacity(drained.len() + chunk.len());
            joined.extend_from_slice(&drained);
            joined.extend_from_slice(&chunk);
            *body = Some(joined.freeze());
            state.done = true;
            return;
        }
        state.buffer.extend_from_slice(&chunk);
    }

    // 2. Flush when EOS — also flush if processed hit the cap (defensive
    //    against EOS never firing; mirror red-team M4).
    let cap_hit = state.processed >= compiled.max_bytes;
    if !eos && !cap_hit {
        return;
    }

    // 3. Parse + redact, fail-open on error.
    let buffered = std::mem::take(&mut state.buffer);
    state.done = true;

    let final_bytes: Bytes = match compiled.redact_bytes(&buffered) {
        Some(redacted) => Bytes::from(redacted),
        None => buffered.freeze(),
    };
    *body = Some(final_bytes);
}
```

### 2.5 Tests (`#[cfg(test)] mod tests` at end of file, ≥ 19 cases)

| # | Test name | Verifies |
|---|-----------|----------|
| 1 | `noop_when_no_families_on` | `is_noop()` true when all bools false + empty extras |
| 2 | `is_noop_with_families_off_but_extras` | `is_noop()` false when extras non-empty even if all bools false |
| 3 | `pci_field_masked_at_root` | `{"card_number":"4111..."}` → `{"card_number":"***REDACTED***"}` |
| 4 | `nested_object_field_masked` | `{"a":{"ssn":"x"}}` masked at depth 1 |
| 5 | `array_of_objects_field_masked` | `[{"token":"a"},{"token":"b"}]` both masked |
| 6 | `top_level_array_walked` | `[1,{"pin":2},3]` → `pin` masked, scalars untouched |
| 7 | `non_object_root_string_returns_none` | `redact_bytes("\"hello\"")` returns `None` |
| 8 | `case_insensitive_match` | `{"CardNumber":"x"}` masked when `redact_case_insensitive=true` |
| 9 | `case_sensitive_no_match` | `{"CardNumber":"x"}` NOT masked when `redact_case_insensitive=false` |
| 10 | `non_matching_field_untouched` | `{"name":"alice"}` returns `None` (no match) |
| 11 | `mixed_match_and_skip` | `{"name":"a","ssn":"b"}` only `ssn` masked, `name` preserved |
| 12 | `pii_off_keeps_email` | with `redact_pii=false`, `email` not masked |
| 13 | `pii_on_masks_email` | with `redact_pii=true`, `email` masked |
| 14 | `extra_fields_extends_set` | `redact_extra_fields=["mrn"]` → `{"mrn":"x"}` masked |
| 15 | `mask_collapses_nested_value` | `{"secret":{"deep":1}}` → `secret` becomes string `"***REDACTED***"` |
| 16 | `malformed_json_returns_none` | `b"{not json"` → None |
| 17 | `null_or_number_value_masked` | `{"password":null}` and `{"pin":1234}` both masked to string |
| 18 | `is_json_content_type_variants` | `application/json`, `application/json; charset=utf-8`, `application/vnd.api+json` accepted; `text/html`, `text/event-stream`, `application/x-ndjson`, `application/xml` rejected |
| 19 | `apply_chunk_buffers_then_emits_on_eos` | feed 3 chunks of a JSON object (eos=false,false,true); after final call `*body` is `Some(redacted)` and `state.done=true` |
| 20 | `apply_chunk_cap_overflow_drains_unredacted` | feed enough bytes to exceed `max_bytes` mid-stream; verify accumulated buffer is drained back into `*body`, `state.done=true`, warn-log emitted once |
| 21 | `apply_chunk_disabled_is_noop` | `state.enabled=false` → `body` untouched across calls |

(21 tests > "≥ 19" target; one extra each on the streaming + cap paths since those are the riskiest.)

## 3. `filters/mod.rs` Update

Append after the existing `response_body_mask_filter` line:

```rust
pub mod response_json_field_redactor;
// ...
pub use response_json_field_redactor::{BodyRedactState, CompiledRedactor, apply_chunk as apply_redact_chunk, is_json_content_type};
```

## 4. `Cargo.toml` Verification

```bash
grep "serde_json" /Users/admin/lab/mini-waf-feat-2/crates/gateway/Cargo.toml
```

If missing, add under `[dependencies]`:
```toml
serde_json = { workspace = true }
```

`bytes`, `tracing` already present (used by AC-17).

## Build Verification (gate before Phase 02)

All inside the dev container (per project rule: no local `cargo`):

```bash
podman run --rm \
  -v "$PWD":/work:Z \
  -v "$PWD/.cargo-cache":/usr/local/cargo/registry:Z \
  -v "$PWD/.cargo-target":/work/target:Z \
  -w /work \
  docker.io/rust:1.86-slim-bookworm \
  bash -c "apt-get update -qq && apt-get install -qq -y --no-install-recommends pkg-config libssl-dev clang cmake \
    && cargo fmt --all -- --check \
    && cargo clippy -p waf-common -p gateway --all-targets --all-features -- -D warnings \
    && cargo test -p waf-common -p gateway --lib filters::response_json_field_redactor::"
```

All three must be clean. **Do not start Phase 02 if any test fails or clippy emits warnings.**

If the dev-container recipe hangs on `apt-get update` (corporate proxy / offline), fall back to `docker-compose up --build` and run the test inside the running container — note the slowdown and continue.

## Pre-Edit Impact Check

Run before editing:

```
gitnexus_impact({target: "HostConfig", direction: "upstream"})
gitnexus_impact({target: "filters", direction: "upstream"})
```

`HostConfig` is a public boundary type used by gateway, storage, API. Adding fields with `#[serde(default)]` is safe but verify the report. If risk = HIGH, pause and report to user.

## Modularization Note

If the filter file approaches 350 LOC during writing, split:
- `response_json_field_redactor/mod.rs` — public API + `apply_chunk`
- `response_json_field_redactor/families.rs` — const tables only
- `response_json_field_redactor/walker.rs` — `walk` recursive function

Don't pre-split — wait for the threshold.

## Success Criteria

- All 21 unit tests pass.
- `cargo clippy -p waf-common -p gateway --all-targets --all-features -- -D warnings` clean (no new warnings; existing warning baseline preserved).
- `cargo fmt` clean.
- `CompiledRedactor`, `BodyRedactState`, `apply_redact_chunk`, `is_json_content_type` exported from `crates/gateway/src/filters/mod.rs`.
- Existing AC-17 tests (`filters::response_body_mask_filter::*`) still pass — touching `HostConfig` mustn't regress them.
- No changes outside the listed files.

## Out of Scope (Phase 01)

- No `proxy.rs` edits.
- No `context.rs` edits.
- No `WafProxy` field additions.
- No TOML / docs updates.
- No integration tests (Phase 02).
- No streaming-with-AC-17 composition test (Phase 02).
