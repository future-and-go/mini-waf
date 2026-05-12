//! FR-034 — JSON response-body sensitive-field redactor.
//!
//! Mirrors the AC-17 body-mask filter (sibling
//! [`response_body_mask_filter`](super::response_body_mask_filter)): per-host
//! compiled config cached on `WafProxy`, dispatched from
//! `response_body_filter`.
//!
//! Key difference from AC-17: AC-17 does *byte-level regex value masking*;
//! FR-034 buffers the full body, parses JSON, and redacts values whose KEYS
//! are in a configured catalog. Composes with AC-17 — see
//! `WafProxy::response_body_filter`. When FR-034 is buffering, it sets
//! `*body = None` so the AC-17 mask filter sees nothing; on EOS (or cap),
//! FR-034 emits the full redacted body and AC-17 then runs over it.
//!
//! Detection cases (field-name catalogs per family) are hard-coded in
//! `families` consts below; activation is per-host via `HostConfig::redact_*`
//! fields.
//!
//! Skip conditions (decided in `proxy::response_filter`):
//! * Content-Encoding != identity / absent
//! * Content-Type not application/json or application/*+json
//! * `CompiledRedactor::is_noop()` (every family off + zero extras)
//!
//! Failure mode: fail-open (forward original bytes on cap overflow,
//! malformed JSON, or serde error). One `tracing::warn!` per occurrence.

use std::collections::HashSet;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use waf_common::HostConfig;

// ── Family catalogs (lower-case; lookup is one HashMap probe in case-insensitive mode)

const PCI_FIELDS: &[&str] = &[
    "card_number",
    "cardnumber",
    "credit_card",
    "creditcard",
    "cc_number",
    "ccnumber",
    "cvv",
    "cvc",
    "cvv2",
    "expiration_date",
    "exp_date",
    "pin",
];

const BANKING_FIELDS: &[&str] = &[
    "bank_account",
    "bankaccount",
    "account_number",
    "accountnumber",
    "routing_number",
    "iban",
    "bic",
    "swift_code",
];

const IDENTITY_FIELDS: &[&str] = &[
    "ssn",
    "social_security_number",
    "tax_id",
    "passport_number",
    "driver_license",
    "national_id",
];

const SECRET_FIELDS: &[&str] = &[
    "password",
    "api_key",
    "apikey",
    "secret",
    "client_secret",
    "token",
    "auth_token",
    "access_token",
    "refresh_token",
    "private_key",
];

const PII_FIELDS: &[&str] = &[
    "phone_number",
    "phonenumber",
    "email",
    "email_address",
    "dob",
    "date_of_birth",
    "mother_maiden_name",
];

const PHI_FIELDS: &[&str] = &["patient_id", "medical_record_number", "insurance_id", "health_record"];

/// Compiled per-host redactor. Built once per `Arc<HostConfig>`, cached on
/// the proxy keyed by `Arc::as_ptr` identity (same pattern as
/// [`super::CompiledMask`]).
pub struct CompiledRedactor {
    /// Active field-name set after applying family toggles + extras +
    /// case-folding. `None` when the redactor is a no-op (every family off
    /// and no extras).
    pub fields: Option<HashSet<String>>,
    /// Replacement token bytes (UTF-8 of `HostConfig::redact_mask_token`).
    pub mask: Bytes,
    /// Hard cap on buffered bytes per response.
    pub max_bytes: u64,
    /// Whether matches are case-insensitive (default `true`).
    pub case_insensitive: bool,
}

impl CompiledRedactor {
    /// Build a redactor from a host config. The result may be a no-op (when
    /// every family toggle is off and `redact_extra_fields` is empty).
    pub fn build(hc: &HostConfig) -> Self {
        let mut set: HashSet<String> = HashSet::new();
        let push = |slice: &[&str], set: &mut HashSet<String>| {
            for f in slice {
                if hc.redact_case_insensitive {
                    set.insert((*f).to_ascii_lowercase());
                } else {
                    set.insert((*f).to_string());
                }
            }
        };
        if hc.redact_pci {
            push(PCI_FIELDS, &mut set);
        }
        if hc.redact_banking {
            push(BANKING_FIELDS, &mut set);
        }
        if hc.redact_identity {
            push(IDENTITY_FIELDS, &mut set);
        }
        if hc.redact_secrets {
            push(SECRET_FIELDS, &mut set);
        }
        if hc.redact_pii {
            push(PII_FIELDS, &mut set);
        }
        if hc.redact_phi {
            push(PHI_FIELDS, &mut set);
        }
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

    /// `true` when there is nothing to redact (no families on, no extras).
    pub const fn is_noop(&self) -> bool {
        self.fields.is_none()
    }

    /// Returns `Some(new_bytes)` on successful redaction. `None` if the input
    /// wasn't valid JSON, the mask wasn't valid UTF-8 (impossible given the
    /// `String` input), or no field matched — in those cases the caller
    /// forwards the original buffer (cheaper than re-serialising).
    pub fn redact_bytes(&self, input: &[u8]) -> Option<Vec<u8>> {
        let fields = self.fields.as_ref()?;
        let mut value: serde_json::Value = serde_json::from_slice(input).ok()?;
        let mask_str = std::str::from_utf8(&self.mask).ok()?;
        let mut hits: usize = 0;
        walk(&mut value, fields, mask_str, self.case_insensitive, &mut hits);
        if hits == 0 {
            return None;
        }
        serde_json::to_vec(&value).ok()
    }
}

/// Build the content-hash half of the redactor cache key.
///
/// Hashes every host-config field that influences `CompiledRedactor::build`.
/// Used by `WafProxy::resolve_redactor` so the cache is keyed by `(host_name,
/// content_hash)` instead of `Arc::as_ptr` — the allocator may reuse a freed
/// `Arc<HostConfig>` address for a new config, which would otherwise serve a
/// stale `CompiledRedactor` across hosts on config reload (BL-001).
pub fn redactor_config_hash(hc: &HostConfig) -> u64 {
    use std::hash::Hasher;
    use twox_hash::XxHash64;
    let mut h = XxHash64::with_seed(0);
    h.write_u8(u8::from(hc.redact_pci));
    h.write_u8(u8::from(hc.redact_banking));
    h.write_u8(u8::from(hc.redact_identity));
    h.write_u8(u8::from(hc.redact_secrets));
    h.write_u8(u8::from(hc.redact_pii));
    h.write_u8(u8::from(hc.redact_phi));
    h.write_u64(hc.redact_extra_fields.len() as u64);
    for f in &hc.redact_extra_fields {
        h.write_u64(f.len() as u64);
        h.write(f.as_bytes());
    }
    h.write_u64(hc.redact_mask_token.len() as u64);
    h.write(hc.redact_mask_token.as_bytes());
    h.write_u64(hc.redact_max_bytes);
    h.write_u8(u8::from(hc.redact_case_insensitive));
    h.finish()
}

/// Recursive walker. Replaces values whose KEYS match `fields` with
/// `mask` (as a JSON string). Walks nested objects and arrays.
fn walk(v: &mut serde_json::Value, fields: &HashSet<String>, mask: &str, case_insensitive: bool, hits: &mut usize) {
    use serde_json::Value::{Array, Object};
    match v {
        Object(map) => {
            // Collect keys first to avoid double-borrowing during mutation.
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                let lookup = if case_insensitive {
                    k.to_ascii_lowercase()
                } else {
                    k.clone()
                };
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
///
/// Accepts: `application/json`, `application/json; charset=utf-8`,
/// `application/problem+json`, `application/vnd.api+json`, etc.
/// Rejects: `text/html`, `text/event-stream`, `application/x-ndjson`,
/// `application/xml`.
pub fn is_json_content_type(ct: &str) -> bool {
    let lower = ct.to_ascii_lowercase();
    let primary = lower.split(';').next().unwrap_or("").trim();
    if primary == "application/json" || primary == "application/problem+json" {
        return true;
    }
    primary.starts_with("application/") && primary.ends_with("+json") && primary != "application/x-ndjson"
}

/// Per-response state for the streaming JSON redactor.
///
/// `enabled` is decided in `WafProxy::response_filter` once Content-Encoding
/// AND Content-Type are known. Compressed / non-JSON / noop bypass.
#[derive(Default)]
pub struct BodyRedactState {
    /// Whether redaction should run for this response.
    pub enabled: bool,
    /// Buffered body bytes pending parse on EOS or cap.
    pub buffer: BytesMut,
    /// Total bytes accumulated so far. Reaching `max_bytes` triggers
    /// fail-open.
    pub processed: u64,
    /// `true` once redaction emitted (success or fail-open). Idempotency
    /// guard against `end_of_stream` firing twice (Pingora GH#220).
    pub done: bool,
    /// `true` once cap-overflow was logged (avoid spamming).
    pub overflow_logged: bool,
}

/// Apply the redactor to one chunk.
///
/// Buffers chunks until EOS or cap, then parses + redacts + emits the full
/// body in `*body`. While buffering, `*body` is set to `None` so downstream
/// filters (notably the AC-17 mask) see nothing.
pub fn apply_chunk(state: &mut BodyRedactState, compiled: &Arc<CompiledRedactor>, body: &mut Option<Bytes>, eos: bool) {
    if !state.enabled || compiled.is_noop() || state.done {
        return;
    }

    // 1. Append the chunk; track byte budget.
    if let Some(chunk) = body.take() {
        let new_total = state.processed.saturating_add(chunk.len() as u64);
        if new_total > compiled.max_bytes {
            // Cap exceeded — fail-open: drain accumulated buffer + this chunk untouched.
            if !state.overflow_logged {
                tracing::warn!(
                    processed = new_total,
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
            state.processed = new_total;
            state.done = true;
            return;
        }
        state.processed = new_total;
        state.buffer.extend_from_slice(&chunk);
    }

    // 2. Flush on EOS (or defensively when processed reached the cap, even
    //    if EOS never fires — guards against unreliable end_of_stream).
    let cap_hit = state.processed >= compiled.max_bytes;
    if !eos && !cap_hit {
        return;
    }

    // 3. Parse + redact, fail-open on parse / serde error.
    let buffered = std::mem::take(&mut state.buffer);
    state.done = true;

    let final_bytes: Bytes = compiled
        .redact_bytes(&buffered)
        .map_or_else(|| buffered.freeze(), Bytes::from);
    *body = Some(final_bytes);
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)] // tests assert on serde_json::Value via index ops
mod tests {
    use super::*;

    fn host(pci: bool, pii: bool, extras: &[&str]) -> HostConfig {
        HostConfig {
            redact_pci: pci,
            redact_pii: pii,
            redact_extra_fields: extras.iter().map(|s| (*s).to_string()).collect(),
            ..HostConfig::default()
        }
    }

    fn compile(hc: &HostConfig) -> Arc<CompiledRedactor> {
        Arc::new(CompiledRedactor::build(hc))
    }

    #[test]
    fn noop_when_no_families_on() {
        let hc = HostConfig::default();
        let c = CompiledRedactor::build(&hc);
        assert!(c.is_noop());
    }

    #[test]
    fn is_noop_with_families_off_but_extras() {
        let hc = host(false, false, &["custom_field"]);
        let c = CompiledRedactor::build(&hc);
        assert!(!c.is_noop(), "extras alone must enable the redactor");
    }

    #[test]
    fn pci_field_masked_at_root() {
        let c = compile(&host(true, false, &[]));
        let out = c.redact_bytes(br#"{"card_number":"4111111111111111"}"#).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["card_number"], "***REDACTED***");
    }

    #[test]
    fn nested_object_field_masked() {
        let mut hc = host(false, false, &[]);
        hc.redact_identity = true;
        let c = compile(&hc);
        let out = c.redact_bytes(br#"{"a":{"ssn":"123-45-6789"}}"#).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["a"]["ssn"], "***REDACTED***");
    }

    #[test]
    fn array_of_objects_field_masked() {
        let mut hc = host(false, false, &[]);
        hc.redact_secrets = true;
        let c = compile(&hc);
        let out = c.redact_bytes(br#"[{"token":"a"},{"token":"b"}]"#).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v[0]["token"], "***REDACTED***");
        assert_eq!(v[1]["token"], "***REDACTED***");
    }

    #[test]
    fn top_level_array_walked() {
        let c = compile(&host(true, false, &[]));
        let out = c.redact_bytes(br#"[1,{"pin":2},3]"#).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v[0], 1);
        assert_eq!(v[1]["pin"], "***REDACTED***");
        assert_eq!(v[2], 3);
    }

    #[test]
    fn non_object_root_string_returns_none() {
        let c = compile(&host(true, false, &[]));
        assert!(c.redact_bytes(br#""hello""#).is_none());
    }

    #[test]
    fn case_insensitive_match() {
        let c = compile(&host(true, false, &[]));
        let out = c.redact_bytes(br#"{"CardNumber":"x","Cvv":"y"}"#).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["CardNumber"], "***REDACTED***");
        assert_eq!(v["Cvv"], "***REDACTED***");
    }

    #[test]
    fn case_sensitive_no_match() {
        let mut hc = host(true, false, &[]);
        hc.redact_case_insensitive = false;
        let c = compile(&hc);
        // CardNumber is mixed-case; catalog stores lower-case "card_number",
        // not "CardNumber". With case-sensitive matching it must NOT match.
        let result = c.redact_bytes(br#"{"CardNumber":"x"}"#);
        assert!(result.is_none(), "case-sensitive must miss CardNumber");
    }

    #[test]
    fn non_matching_field_untouched() {
        let c = compile(&host(true, false, &[]));
        assert!(c.redact_bytes(br#"{"name":"alice"}"#).is_none());
    }

    #[test]
    fn mixed_match_and_skip() {
        let mut hc = host(false, false, &[]);
        hc.redact_identity = true;
        let c = compile(&hc);
        let out = c.redact_bytes(br#"{"name":"a","ssn":"b"}"#).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["name"], "a");
        assert_eq!(v["ssn"], "***REDACTED***");
    }

    #[test]
    fn pii_off_keeps_email() {
        let c = compile(&host(false, false, &[]));
        // Family off → noop redactor.
        assert!(c.is_noop());
    }

    #[test]
    fn pii_on_masks_email() {
        let c = compile(&host(false, true, &[]));
        let out = c.redact_bytes(br#"{"email":"a@b.com"}"#).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["email"], "***REDACTED***");
    }

    #[test]
    fn extra_fields_extends_set() {
        let c = compile(&host(false, false, &["mrn"]));
        let out = c.redact_bytes(br#"{"mrn":"M-001"}"#).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["mrn"], "***REDACTED***");
    }

    #[test]
    fn mask_collapses_nested_value() {
        let mut hc = host(false, false, &[]);
        hc.redact_secrets = true;
        let c = compile(&hc);
        let out = c.redact_bytes(br#"{"secret":{"deep":1,"more":[1,2]}}"#).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["secret"], "***REDACTED***");
    }

    #[test]
    fn malformed_json_returns_none() {
        let c = compile(&host(true, false, &[]));
        assert!(c.redact_bytes(b"{not json").is_none());
    }

    #[test]
    fn null_or_number_value_masked() {
        let mut hc = host(false, false, &[]);
        hc.redact_secrets = true;
        let c = compile(&hc);
        let out = c.redact_bytes(br#"{"password":null}"#).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["password"], "***REDACTED***");

        let c2 = compile(&host(true, false, &[]));
        let out2 = c2.redact_bytes(br#"{"pin":1234}"#).unwrap();
        let v2: serde_json::Value = serde_json::from_slice(&out2).unwrap();
        assert_eq!(v2["pin"], "***REDACTED***");
    }

    #[test]
    fn is_json_content_type_variants() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("application/json; charset=utf-8"));
        assert!(is_json_content_type("application/problem+json"));
        assert!(is_json_content_type("application/vnd.api+json"));
        assert!(is_json_content_type("APPLICATION/JSON"));

        assert!(!is_json_content_type("text/html"));
        assert!(!is_json_content_type("text/event-stream"));
        assert!(!is_json_content_type("application/x-ndjson"));
        assert!(!is_json_content_type("application/xml"));
        assert!(!is_json_content_type(""));
    }

    #[test]
    fn apply_chunk_buffers_then_emits_on_eos() {
        let c = compile(&host(true, false, &[]));
        let mut state = BodyRedactState {
            enabled: true,
            ..Default::default()
        };

        // Three chunks of {"a":"x","b":"y","cvv":"123"}
        let mut chunk1: Option<Bytes> = Some(Bytes::from_static(br#"{"a":"x","b":"#));
        apply_chunk(&mut state, &c, &mut chunk1, false);
        assert!(chunk1.is_none(), "chunk1 must be swallowed");
        assert!(!state.done);

        let mut chunk2: Option<Bytes> = Some(Bytes::from_static(br#""y","cvv":"#));
        apply_chunk(&mut state, &c, &mut chunk2, false);
        assert!(chunk2.is_none(), "chunk2 must be swallowed");
        assert!(!state.done);

        let mut chunk3: Option<Bytes> = Some(Bytes::from_static(br#""123"}"#));
        apply_chunk(&mut state, &c, &mut chunk3, true);
        let final_bytes = chunk3.expect("EOS must emit final body");
        let v: serde_json::Value = serde_json::from_slice(&final_bytes).unwrap();
        assert_eq!(v["a"], "x");
        assert_eq!(v["b"], "y");
        assert_eq!(v["cvv"], "***REDACTED***");
        assert!(state.done);
    }

    #[test]
    fn apply_chunk_cap_overflow_drains_unredacted() {
        let mut hc = host(true, false, &[]);
        hc.redact_max_bytes = 32; // tiny cap
        let c = compile(&hc);
        let mut state = BodyRedactState {
            enabled: true,
            ..Default::default()
        };

        // First chunk fits.
        let mut chunk1: Option<Bytes> = Some(Bytes::from_static(br#"{"card_number":"4111""#));
        apply_chunk(&mut state, &c, &mut chunk1, false);
        assert!(chunk1.is_none());
        assert!(!state.done);

        // Second chunk pushes over the 32-byte cap.
        let mut chunk2: Option<Bytes> = Some(Bytes::from_static(br#","more":"data here way over"}"#));
        apply_chunk(&mut state, &c, &mut chunk2, true);
        let drained = chunk2.expect("over-cap must drain accumulated + chunk untouched");
        // Verify the drained bytes contain the original card number (NOT redacted).
        assert!(
            drained.windows(4).any(|w| w == b"4111"),
            "drained bytes must contain unredacted card number"
        );
        assert!(state.done);
        assert!(state.overflow_logged);
    }

    #[test]
    fn apply_chunk_disabled_is_noop() {
        let c = compile(&host(true, false, &[]));
        let mut state = BodyRedactState::default(); // enabled=false
        let original = Bytes::from_static(br#"{"card_number":"4111"}"#);
        let mut body: Option<Bytes> = Some(original.clone());
        apply_chunk(&mut state, &c, &mut body, true);
        assert_eq!(body.unwrap(), original);
        assert!(!state.done);
    }

    #[test]
    fn redactor_config_hash_distinguishes_each_field() {
        // BL-001 regression: every field that influences `CompiledRedactor::build`
        // must change the hash, so the cache cannot serve a stale compiled
        // redactor when an `Arc<HostConfig>` happens to land on a previously
        // freed address after a config reload.
        let base = HostConfig::default();
        let h0 = redactor_config_hash(&base);

        let mut h = base.clone();
        h.redact_pci = true;
        assert_ne!(h0, redactor_config_hash(&h), "redact_pci must change hash");
        let mut h = base.clone();
        h.redact_banking = true;
        assert_ne!(h0, redactor_config_hash(&h), "redact_banking must change hash");
        let mut h = base.clone();
        h.redact_identity = true;
        assert_ne!(h0, redactor_config_hash(&h), "redact_identity must change hash");
        let mut h = base.clone();
        h.redact_secrets = true;
        assert_ne!(h0, redactor_config_hash(&h), "redact_secrets must change hash");
        let mut h = base.clone();
        h.redact_pii = true;
        assert_ne!(h0, redactor_config_hash(&h), "redact_pii must change hash");
        let mut h = base.clone();
        h.redact_phi = true;
        assert_ne!(h0, redactor_config_hash(&h), "redact_phi must change hash");
        let mut h = base.clone();
        h.redact_extra_fields = vec!["foo".to_string()];
        assert_ne!(h0, redactor_config_hash(&h), "extra_fields must change hash");
        let mut h = base.clone();
        h.redact_mask_token = "<X>".to_string();
        assert_ne!(h0, redactor_config_hash(&h), "mask_token must change hash");
        let mut h = base.clone();
        h.redact_max_bytes = base.redact_max_bytes + 1;
        assert_ne!(h0, redactor_config_hash(&h), "max_bytes must change hash");
        let mut h = base.clone();
        h.redact_case_insensitive = !base.redact_case_insensitive;
        assert_ne!(h0, redactor_config_hash(&h), "case_insensitive must change hash");

        // Identical inputs must collide.
        assert_eq!(h0, redactor_config_hash(&HostConfig::default()));
    }
}
