//! FR-033 — integration tests for the response-body content scanner.
//!
//! These exercise the function-level pipeline (decompress → scan → mask)
//! without binding to live Pingora. Live-Pingora E2E remains deferred to
//! FR-001 phase-06b per `crates/gateway/CLAUDE.md`.

use std::io::Write;
use std::sync::Arc;

use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use gateway::context::BodyScanState;
use gateway::filters::{CompiledScanner, DecoderChain, apply_body_scan_chunk, parse_encoding};
use waf_common::HostConfig;

fn run_chunk(state: &mut BodyScanState, scanner: &Arc<CompiledScanner>, chunk: &[u8], eos: bool) -> Vec<u8> {
    let mut body = if chunk.is_empty() {
        None
    } else {
        Some(Bytes::copy_from_slice(chunk))
    };
    apply_body_scan_chunk(state, scanner, &mut body, eos, "integration-host");
    body.map(|b| b.to_vec()).unwrap_or_default()
}

fn enabled_state() -> BodyScanState {
    BodyScanState {
        enabled: true,
        ..Default::default()
    }
}

fn enabled_state_with_decoder() -> BodyScanState {
    BodyScanState {
        enabled: true,
        decoder: Some(DecoderChain::new()),
        ..Default::default()
    }
}

fn gzip(payload: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    let _ = e.write_all(payload);
    e.finish().unwrap_or_default()
}

#[test]
fn integration_full_chain_redacts_python_traceback() {
    let scanner = Arc::new(CompiledScanner::build(1 << 20));
    let mut state = enabled_state();
    let body = b"500 Internal Error: Traceback (most recent call last)\n  File \"/app/main.py\", line 42, in handler\n    raise ValueError(boom)\n";
    let out = run_chunk(&mut state, &scanner, body, true);
    assert!(
        !out.windows(33).any(|w| w == b"Traceback (most recent call last)"),
        "Python traceback marker must be redacted"
    );
}

#[test]
fn integration_gzipped_response_decompressed_and_scanned() {
    let plaintext = b"key=AKIAFAKEFAKEFAKEFAKE more text";
    let gz = gzip(plaintext);
    let scanner = Arc::new(CompiledScanner::build(1 << 20));
    let mut state = enabled_state_with_decoder();
    let out = run_chunk(&mut state, &scanner, &gz, true);
    assert!(
        !out.windows(20).any(|w| w == b"AKIAFAKEFAKEFAKEFAKE"),
        "secret in gzipped body must be redacted post-decompression"
    );
}

#[test]
fn integration_send_assert_body_scan_state() {
    static_assertions::assert_impl_all!(BodyScanState: Send);
}

#[test]
fn integration_hostconfig_serde_roundtrip_preserves_body_scan_fields() {
    let hc = HostConfig {
        body_scan_enabled: true,
        body_scan_max_body_bytes: 2 << 20,
        ..HostConfig::default()
    };
    let toml_str = toml::to_string(&hc).expect("serialize");
    let parsed: HostConfig = toml::from_str(&toml_str).expect("deserialize");
    assert!(parsed.body_scan_enabled);
    assert_eq!(parsed.body_scan_max_body_bytes, 2 << 20);
}

#[test]
fn integration_hostconfig_roundtrip_default_remains_disabled() {
    let hc = HostConfig::default();
    let toml_str = toml::to_string(&hc).expect("serialize");
    let parsed: HostConfig = toml::from_str(&toml_str).expect("deserialize");
    assert!(!parsed.body_scan_enabled);
    assert_eq!(parsed.body_scan_max_body_bytes, 1 << 20);
}

#[test]
fn integration_unknown_encoding_zstd_skipped() {
    use gateway::filters::ResponseEncoding;
    assert_eq!(parse_encoding("zstd"), ResponseEncoding::Unsupported);
    assert_eq!(parse_encoding("br"), ResponseEncoding::Unsupported);
}
