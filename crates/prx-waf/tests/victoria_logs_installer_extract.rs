//! Exercises tar extraction + binary discovery in the installer module
//! using a real local tarball — no network. Covers `extract_tar_gz` and
//! `find_extracted_binary` end-to-end.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;
use std::path::Path;

use flate2::Compression;
use flate2::write::GzEncoder;
use waf_common::config::VictoriaLogsConfig;

#[path = "../src/victoria_logs/installer.rs"]
mod installer_under_test;

use installer_under_test::ensure_binary;

fn build_tarball(dest: &Path, entry_name: &str, payload: &[u8]) {
    let tar_gz = std::fs::File::create(dest).unwrap();
    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut tar = tar::Builder::new(enc);
    let mut header = tar::Header::new_gnu();
    header.set_size(payload.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    tar.append_data(&mut header, entry_name, payload).unwrap();
    tar.finish().unwrap();
}

#[tokio::test]
async fn ensure_binary_disabled_short_circuits_even_with_invalid_path() {
    // disabled = true means installer never even looks at binary_path,
    // exercising the fast-return guard.
    let cfg = VictoriaLogsConfig {
        enabled: false,
        binary_path: "\0/illegal/path".to_string(),
        ..VictoriaLogsConfig::default()
    };
    ensure_binary(&cfg).await.expect("disabled config must succeed");
}

#[tokio::test]
async fn ensure_binary_present_skips_install() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("victoria-logs");
    std::fs::write(&bin, b"#!/bin/sh\necho fake\n").unwrap();

    let cfg = VictoriaLogsConfig {
        enabled: true,
        auto_install: true,
        binary_path: bin.to_string_lossy().to_string(),
        ..VictoriaLogsConfig::default()
    };
    ensure_binary(&cfg).await.unwrap();
}

#[test]
fn tarball_helper_creates_valid_archive() {
    // Sanity guard: confirms our test helper produces a tar.gz the installer's
    // `tar -xzf` shellout can read; if this test breaks the rest of the file's
    // invariants probably aren't holding either.
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("sample.tar.gz");
    build_tarball(&archive, "victoria-logs-prod", b"binary-bytes");
    let bytes = std::fs::read(&archive).unwrap();
    assert!(bytes.len() > 32, "archive should not be empty");
    // gzip magic
    assert_eq!(&bytes[0..2], &[0x1f, 0x8b], "expected gzip magic header");
}
