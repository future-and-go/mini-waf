//! FR-034 — integration tests for `apply_redact_chunk` and its composition
//! with the AC-17 body-mask filter (`apply_body_mask_chunk`).
//!
//! Tests exercise the public filter API directly. End-to-end tests over a
//! live Pingora instance are deferred — see plan
//! `plans/260428-1357-GH-034-sensitive-field-redaction/phase-02-gateway-wiring-and-tests.md`.

#![allow(clippy::indexing_slicing)] // serde_json::Value tests assert via index

use std::sync::Arc;

use bytes::Bytes;
use gateway::context::BodyMaskState;
use gateway::filters::{
    CompiledMask, CompiledRedactor, apply_body_mask_chunk, apply_redact_chunk,
    response_json_field_redactor::BodyRedactState,
};
use waf_common::HostConfig;

fn host_with_pci() -> HostConfig {
    HostConfig {
        redact_pci: true,
        ..HostConfig::default()
    }
}

fn enabled_redact_state() -> BodyRedactState {
    BodyRedactState {
        enabled: true,
        ..Default::default()
    }
}

#[test]
fn case_1_redactor_noop_passes_through() {
    // No families on, no extras → noop redactor → state.enabled true is benign.
    let hc = HostConfig::default();
    let c = Arc::new(CompiledRedactor::build(&hc));
    let mut state = enabled_redact_state();

    let original = Bytes::from_static(br#"{"card_number":"4111"}"#);
    let mut body: Option<Bytes> = Some(original.clone());
    apply_redact_chunk(&mut state, &c, &mut body, true);

    assert!(c.is_noop());
    assert_eq!(body.unwrap(), original, "noop redactor must pass bytes through");
    assert!(!state.done, "noop must not flip done flag");
}

#[test]
fn case_2_single_chunk_pci_masked() {
    let c = Arc::new(CompiledRedactor::build(&host_with_pci()));
    let mut state = enabled_redact_state();

    let mut body: Option<Bytes> = Some(Bytes::from_static(br#"{"card_number":"4111","name":"alice"}"#));
    apply_redact_chunk(&mut state, &c, &mut body, true);

    let final_bytes = body.expect("EOS must emit final body");
    let v: serde_json::Value = serde_json::from_slice(&final_bytes).unwrap();
    assert_eq!(v["card_number"], "***REDACTED***");
    assert_eq!(v["name"], "alice");
    assert!(state.done);
}

#[test]
fn case_3_multi_chunk_eos_pattern() {
    let c = Arc::new(CompiledRedactor::build(&host_with_pci()));
    let mut state = enabled_redact_state();

    // Three chunks of {"a":"x","b":"y","cvv":"123"}
    let mut chunk1: Option<Bytes> = Some(Bytes::from_static(br#"{"a":"x","b":"#));
    apply_redact_chunk(&mut state, &c, &mut chunk1, false);
    assert!(chunk1.is_none(), "chunk1 must be swallowed");
    assert!(!state.done);

    let mut chunk2: Option<Bytes> = Some(Bytes::from_static(br#""y","cvv":"#));
    apply_redact_chunk(&mut state, &c, &mut chunk2, false);
    assert!(chunk2.is_none(), "chunk2 must be swallowed");
    assert!(!state.done);

    let mut chunk3: Option<Bytes> = Some(Bytes::from_static(br#""123"}"#));
    apply_redact_chunk(&mut state, &c, &mut chunk3, true);

    let final_bytes = chunk3.expect("EOS must emit final body");
    let v: serde_json::Value = serde_json::from_slice(&final_bytes).unwrap();
    assert_eq!(v["a"], "x");
    assert_eq!(v["b"], "y");
    assert_eq!(v["cvv"], "***REDACTED***");
    assert!(state.done);
    // Final byte length is independent of input chunk byte sum (mask differs in size).
    let parsed_len = serde_json::to_vec(&v).unwrap().len();
    assert_eq!(final_bytes.len(), parsed_len);
}

#[test]
fn case_4_cap_overflow_drains_unredacted() {
    let mut hc = host_with_pci();
    hc.redact_max_bytes = 32; // tiny cap
    let c = Arc::new(CompiledRedactor::build(&hc));
    let mut state = enabled_redact_state();

    let mut chunk1: Option<Bytes> = Some(Bytes::from_static(br#"{"card_number":"4111""#));
    apply_redact_chunk(&mut state, &c, &mut chunk1, false);
    assert!(chunk1.is_none());
    assert!(!state.done);

    // Second chunk pushes over the 32-byte cap.
    let mut chunk2: Option<Bytes> = Some(Bytes::from_static(br#","more":"data here way over"}"#));
    apply_redact_chunk(&mut state, &c, &mut chunk2, true);
    let drained = chunk2.expect("over-cap must drain accumulated + chunk untouched");
    assert!(
        drained.windows(4).any(|w| w == b"4111"),
        "drained bytes must contain unredacted card number"
    );
    assert!(state.done);
    assert!(state.overflow_logged);
}

#[test]
fn case_5_malformed_json_passes_through() {
    let c = Arc::new(CompiledRedactor::build(&host_with_pci()));
    let mut state = enabled_redact_state();

    let original = Bytes::from_static(b"{not json");
    let mut body: Option<Bytes> = Some(original.clone());
    apply_redact_chunk(&mut state, &c, &mut body, true);

    assert_eq!(body.unwrap(), original, "malformed JSON must be forwarded unchanged");
    assert!(state.done);
}

#[test]
fn case_6_redact_then_ac17_compose() {
    // FR-034 redacts card_number; AC-17 (regex over identity-encoded bytes)
    // masks 10.0.0.x patterns in the redacted output.
    let mut hc = host_with_pci();
    hc.internal_patterns = vec![r"10\.0\.\d+\.\d+".to_string()];
    hc.mask_token = "[redacted-ip]".to_string();
    let redactor = Arc::new(CompiledRedactor::build(&hc));
    let mask = Arc::new(CompiledMask::build(
        &hc.internal_patterns,
        &hc.mask_token,
        hc.body_mask_max_bytes,
    ));

    let mut redact_state = enabled_redact_state();
    let mut mask_state = BodyMaskState {
        enabled: true,
        ..Default::default()
    };

    let input = br#"{"card_number":"4111","internal_ip":"10.0.0.5","note":"called 10.0.0.7"}"#;
    let mut body: Option<Bytes> = Some(Bytes::from_static(input));

    // FR-034 first.
    apply_redact_chunk(&mut redact_state, &redactor, &mut body, true);
    assert!(redact_state.done);

    // AC-17 second — runs over redacted bytes.
    apply_body_mask_chunk(&mut mask_state, &mask, &mut body, true);

    let final_bytes = body.expect("AC-17 must emit final body");
    let needle = std::str::from_utf8(&final_bytes).unwrap();
    assert!(
        !needle.contains("4111"),
        "card_number must be redacted by FR-034: {needle}"
    );
    assert!(
        !needle.contains("10.0.0.5"),
        "internal_ip 10.0.0.5 must be masked by AC-17: {needle}"
    );
    assert!(
        !needle.contains("10.0.0.7"),
        "second IP 10.0.0.7 must be masked by AC-17: {needle}"
    );
    assert!(needle.contains("[redacted-ip]"));
    assert!(needle.contains("***REDACTED***"));
}

#[test]
fn case_7_disabled_state_is_noop() {
    let c = Arc::new(CompiledRedactor::build(&host_with_pci()));
    let mut state = BodyRedactState::default(); // enabled=false
    let original = Bytes::from_static(br#"{"card_number":"4111"}"#);
    let mut body: Option<Bytes> = Some(original.clone());
    apply_redact_chunk(&mut state, &c, &mut body, true);
    assert_eq!(body.unwrap(), original);
    assert!(!state.done);
}
