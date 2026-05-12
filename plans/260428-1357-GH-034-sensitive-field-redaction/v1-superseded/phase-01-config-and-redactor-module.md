# Phase 01 — Config Types + BodyRedactor Module (no wiring)

**Goal:** Land all the data structures and the pure redaction logic. **No** gateway changes, **no** Pingora hook wiring. Compilable in isolation; future phases depend on these symbols.

**Status:** todo

## Files Touched

| File | Change |
|------|--------|
| `crates/waf-common/src/config.rs` | Add `BodyRedactorConfig`; add `body_redactor: BodyRedactorConfig` field to `OutboundConfig` |
| `crates/waf-engine/src/outbound/mod.rs` | Add `pub mod body_redactor;` and `pub use body_redactor::BodyRedactor;` |
| `crates/waf-engine/src/outbound/body_redactor.rs` | **NEW** — const family tables, `BodyRedactor` struct, redaction logic, unit tests |
| `crates/waf-engine/src/lib.rs` | Re-export: `pub use outbound::BodyRedactor;` |

No changes to `gateway/` in this phase.

## 1. `BodyRedactorConfig` (in `waf-common::config`)

```rust
/// FR-034 — sensitive-field redaction in JSON response bodies.
///
/// Detection cases (field-name catalogs per family) live in
/// `waf-engine::outbound::body_redactor`. This struct only decides which
/// families are active and lets the operator extend them.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BodyRedactorConfig {
    /// Master toggle for this redactor (independent of [outbound] master toggle
    /// is intentional: operators may want headers without body or vice versa).
    #[serde(default)]
    pub enabled: bool,

    /// Per-family activation. All default ON when redactor is enabled,
    /// EXCEPT `redact_pii` and `redact_phi` which default OFF (high
    /// false-positive surface in legitimate APIs).
    #[serde(default = "default_true")]
    pub redact_pci: bool,
    #[serde(default = "default_true")]
    pub redact_banking: bool,
    #[serde(default = "default_true")]
    pub redact_identity: bool,
    #[serde(default = "default_true")]
    pub redact_secrets: bool,
    #[serde(default)]
    pub redact_pii: bool,
    #[serde(default)]
    pub redact_phi: bool,

    /// Operator-supplied additional field names. Extends every active family.
    /// Stored case-folded at load if `case_sensitive == false`.
    #[serde(default)]
    pub extra_fields: Vec<String>,

    /// Match field names case-insensitively. Default true (HTTP/JSON convention).
    #[serde(default = "default_true")]
    pub case_insensitive: bool,

    /// Hard cap on buffered body bytes per request. Over cap → fail-open + warn.
    /// Default 256 KiB.
    #[serde(default = "default_body_cap")]
    pub body_size_cap_bytes: usize,
}

fn default_true() -> bool { true }
fn default_body_cap() -> usize { 256 * 1024 }

impl Default for BodyRedactorConfig {
    fn default() -> Self {
        Self {
            enabled: false,           // master OFF by default — preserve existing behaviour
            redact_pci: true,
            redact_banking: true,
            redact_identity: true,
            redact_secrets: true,
            redact_pii: false,
            redact_phi: false,
            extra_fields: Vec::new(),
            case_insensitive: true,
            body_size_cap_bytes: 256 * 1024,
        }
    }
}
```

Add to existing `OutboundConfig`:

```rust
pub struct OutboundConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub headers: HeaderFilterConfig,
    #[serde(default)]                          // NEW
    pub body_redactor: BodyRedactorConfig,     // NEW
}
```

**No breaking changes:** existing TOMLs without `[outbound.body_redactor]` parse via `#[serde(default)]`.

## 2. `body_redactor.rs` Module

### Family const tables (verbatim from plan.md)

```rust
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

All entries are **lowercase** so `case_insensitive` mode is one comparison.

### `BodyRedactor` struct

```rust
pub struct BodyRedactor {
    fields: HashSet<String>,    // active set, post case-fold if case_insensitive
    case_insensitive: bool,
    body_cap: usize,
    mask: &'static str,         // hard-coded "***REDACTED***" — not config in v1
}

impl BodyRedactor {
    pub fn from_config(cfg: &BodyRedactorConfig) -> Option<Arc<Self>> {
        if !cfg.enabled { return None; }
        let mut set: HashSet<String> = HashSet::new();
        let mut push = |slice: &[&str]| {
            for f in slice { set.insert(if cfg.case_insensitive { f.to_ascii_lowercase() } else { (*f).to_string() }); }
        };
        if cfg.redact_pci      { push(PCI_FIELDS); }
        if cfg.redact_banking  { push(BANKING_FIELDS); }
        if cfg.redact_identity { push(IDENTITY_FIELDS); }
        if cfg.redact_secrets  { push(SECRET_FIELDS); }
        if cfg.redact_pii      { push(PII_FIELDS); }
        if cfg.redact_phi      { push(PHI_FIELDS); }
        for f in &cfg.extra_fields {
            set.insert(if cfg.case_insensitive { f.to_ascii_lowercase() } else { f.clone() });
        }
        if set.is_empty() { return None; }   // every family off → no-op redactor
        Some(Arc::new(Self {
            fields: set,
            case_insensitive: cfg.case_insensitive,
            body_cap: cfg.body_size_cap_bytes,
            mask: "***REDACTED***",
        }))
    }

    /// Hard cap exposed to the gateway — caller buffers up to this many bytes.
    pub fn body_cap(&self) -> usize { self.body_cap }

    /// Returns Some(new bytes) on successful redaction, None if input
    /// wasn't valid JSON or no field matched (caller forwards original).
    pub fn redact_bytes(&self, input: &[u8]) -> Option<Vec<u8>> {
        let mut value: serde_json::Value = serde_json::from_slice(input).ok()?;
        let mut hits: usize = 0;
        self.walk(&mut value, &mut hits);
        if hits == 0 { return None; }   // signal caller to forward original (cheaper)
        serde_json::to_vec(&value).ok()
    }

    fn walk(&self, v: &mut serde_json::Value, hits: &mut usize) {
        use serde_json::Value::*;
        match v {
            Object(map) => {
                let keys: Vec<String> = map.keys().cloned().collect();
                for k in keys {
                    let lookup = if self.case_insensitive { k.to_ascii_lowercase() } else { k.clone() };
                    if self.fields.contains(&lookup) {
                        if let Some(slot) = map.get_mut(&k) {
                            *slot = String(self.mask.to_string());
                            *hits += 1;
                        }
                    } else if let Some(child) = map.get_mut(&k) {
                        self.walk(child, hits);
                    }
                }
            }
            Array(arr) => for item in arr { self.walk(item, hits); }
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
}
```

### Unit Tests (≥ 18, in same file under `#[cfg(test)] mod tests`)

| # | Test | Verifies |
|---|------|----------|
| 1 | `redactor_disabled_returns_none` | `from_config` with `enabled=false` → `None` |
| 2 | `all_families_off_returns_none` | enabled=true but every family false and no extras → `None` |
| 3 | `pci_field_masked_at_root` | `{"card_number":"4111..."}` masked |
| 4 | `nested_object_field_masked` | `{"a":{"ssn":"x"}}` masked |
| 5 | `array_of_objects_field_masked` | `[{"token":"x"},{"token":"y"}]` both masked |
| 6 | `top_level_array_walked` | top-level JSON array walked without crash |
| 7 | `non_object_root_string` | input `"hello"` returns None (no field match) |
| 8 | `case_insensitive_match` | `{"CardNumber":"x"}` masked when `case_insensitive=true` |
| 9 | `case_sensitive_no_match` | `{"CardNumber":"x"}` NOT masked when `case_insensitive=false` |
| 10 | `non_matching_field_untouched` | `{"name":"alice"}` returns None |
| 11 | `mixed_match_and_skip` | `{"name":"a","ssn":"b"}` only ssn masked, name preserved |
| 12 | `pii_off_keeps_email` | with redact_pii=false, `email` not masked |
| 13 | `pii_on_masks_email` | with redact_pii=true, `email` masked |
| 14 | `extra_fields_extends_set` | `extra_fields=["mrn"]` → `{"mrn":"x"}` masked |
| 15 | `mask_collapses_nested_value` | `{"secret":{"deep":1}}` → `secret` becomes string `"***REDACTED***"` |
| 16 | `malformed_json_returns_none` | `b"{not json"` → None |
| 17 | `null_or_number_value_masked` | `{"password":null}` and `{"pin":1234}` both masked to string |
| 18 | `is_json_content_type_variants` | `application/json`, `application/json; charset=utf-8`, `application/vnd.api+json` accepted; `text/html`, `text/event-stream`, `application/x-ndjson` rejected |
| 19 | `body_cap_default_256kib` | `BodyRedactor::body_cap()` returns 262144 with default config |

## Build Verification (gate before Phase 02)

```bash
cargo fmt --all -- --check
cargo clippy -p waf-common -p waf-engine --all-targets -- -D warnings
cargo test -p waf-engine outbound::body_redactor::
```

All three must be clean. **Do not** start Phase 02 if any test fails or clippy emits warnings.

## Modularization Note

`body_redactor.rs` will end at ~250–280 lines including tests. If it grows past 300 LOC during Phase 03, split:
- `body_redactor/mod.rs` — struct + public API
- `body_redactor/families.rs` — const tables only
- `body_redactor/walker.rs` — recursive walker

Don't pre-split — wait until threshold is hit.

## Pre-Edit Impact Check

Before editing each file in this phase, run:
```
gitnexus_impact({target: "OutboundConfig", direction: "upstream"})
gitnexus_impact({target: "outbound", direction: "upstream"})
```
Report blast radius before touching `OutboundConfig` (it's the public outbound config struct used by gateway and engine — adding a field is safe, but verify no FFI / serialiser surprises).

## Success Criteria

- All 19 unit tests pass.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` clean.
- `cargo fmt` clean.
- `BodyRedactor` exported from `waf_engine` crate root.
- Existing FR-035 tests (`outbound::header_filter::*`) still pass — touching `OutboundConfig` mustn't regress them.

## Out of Scope (Phase 01)

- No `gateway/` changes.
- No TOML default config (Phase 03).
- No Pingora hook (Phase 02).
- No integration tests (Phase 03).
- No streaming / chunked / compression handling (only `redact_bytes(&[u8])` here).
