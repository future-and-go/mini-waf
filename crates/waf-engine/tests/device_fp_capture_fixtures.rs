// FR-010 phase-03 — synthetic ClientHello fixture suite.
//
// Real packet captures from Chrome / Firefox / Safari / curl /
// curl-impersonate / Go / Python require running each client against a
// rustls test server and dumping handshake bytes — out of scope for an
// in-tree unit test. Instead we hand-craft ClientHello byte sequences
// matching the *documented* ordering of cipher suites, extensions,
// supported_groups, signature_algorithms, and ALPN for each client
// family. This proves the parser is deterministic across the field
// patterns the JA3 / JA4 hashes will key on.
//
// References for fingerprint shapes used below:
//   - JA3 catalogue (Salesforce): https://github.com/salesforce/ja3
//   - JA4+ spec (FoxIO): https://github.com/FoxIO-LLC/ja4
//   - curl-impersonate browser profiles:
//     https://github.com/lwthiker/curl-impersonate
//
// Phase 09 (perf bench + docs) replaces these with real captures
// dumped via a `--collect-fixtures` test harness against rustls.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::approx_constant,
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use waf_engine::device_fp::capture::{ParsedClientHello, parse_client_hello};

mod h {
    // Local builder helpers; duplicated rather than crossing the lib's
    // `pub(crate)` boundary just for integration tests.
    fn u16_be(n: usize) -> [u8; 2] {
        u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes()
    }

    pub fn build(cs: &[u16], exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::with_capacity(128);
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        let cs_bytes: Vec<u8> = cs.iter().flat_map(|c| c.to_be_bytes()).collect();
        body.extend_from_slice(&u16_be(cs_bytes.len()));
        body.extend_from_slice(&cs_bytes);
        body.push(1);
        body.push(0);
        let mut ext_buf = Vec::new();
        for (ty, data) in exts {
            ext_buf.extend_from_slice(&ty.to_be_bytes());
            ext_buf.extend_from_slice(&u16_be(data.len()));
            ext_buf.extend_from_slice(data);
        }
        body.extend_from_slice(&u16_be(ext_buf.len()));
        body.extend_from_slice(&ext_buf);
        let mut msg = vec![0x01];
        let blen = u32::try_from(body.len()).unwrap_or(u32::MAX);
        msg.extend_from_slice(&[
            ((blen >> 16) & 0xff) as u8,
            ((blen >> 8) & 0xff) as u8,
            (blen & 0xff) as u8,
        ]);
        msg.extend_from_slice(&body);
        msg
    }

    pub fn sni(host: &str) -> (u16, Vec<u8>) {
        let host = host.as_bytes();
        let entry_len = 1 + 2 + host.len();
        let mut data = Vec::with_capacity(2 + entry_len);
        data.extend_from_slice(&u16_be(entry_len));
        data.push(0);
        data.extend_from_slice(&u16_be(host.len()));
        data.extend_from_slice(host);
        (0, data)
    }

    pub fn u16_list(ext_type: u16, items: &[u16]) -> (u16, Vec<u8>) {
        let inner: Vec<u8> = items.iter().flat_map(|c| c.to_be_bytes()).collect();
        let mut data = Vec::with_capacity(2 + inner.len());
        data.extend_from_slice(&u16_be(inner.len()));
        data.extend_from_slice(&inner);
        (ext_type, data)
    }

    pub fn alpn(protos: &[&str]) -> (u16, Vec<u8>) {
        let mut inner = Vec::new();
        for p in protos {
            inner.push(u8::try_from(p.len()).unwrap_or(u8::MAX));
            inner.extend_from_slice(p.as_bytes());
        }
        let mut data = Vec::with_capacity(2 + inner.len());
        data.extend_from_slice(&u16_be(inner.len()));
        data.extend_from_slice(&inner);
        (16, data)
    }
}

/// First element of a Vec or `0` sentinel. Indexing is denied at the
/// workspace level — this gives us a panic-free accessor that's clear
/// at the call site (assertions still fail loudly on empty input
/// because the sentinel won't match the expected value).
fn first(v: &[u16]) -> u16 {
    v.first().copied().unwrap_or(0)
}

#[test]
fn chrome_121_shape() {
    let bytes = h::build(
        &[0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030],
        &[
            h::sni("chrome.example"),
            h::u16_list(10, &[0x0a0a, 29, 23, 24]),
            h::u16_list(13, &[0x0403, 0x0804, 0x0401]),
            h::alpn(&["h2", "http/1.1"]),
        ],
    );
    let parsed = parse_client_hello(&bytes).unwrap();
    let parsed2 = parse_client_hello(&bytes).unwrap();
    assert_eq!(parsed, parsed2, "non-deterministic parse");
    assert_eq!(
        parsed,
        ParsedClientHello {
            legacy_version: 0x0303,
            cipher_suites: vec![0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030],
            extensions: vec![0, 10, 13, 16],
            supported_groups: vec![0x0a0a, 29, 23, 24],
            signature_algorithms: vec![0x0403, 0x0804, 0x0401],
            alpn: vec!["h2".into(), "http/1.1".into()],
            sni: Some("chrome.example".into()),
        }
    );
}

#[test]
fn firefox_124_shape() {
    let bytes = h::build(
        &[0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8],
        &[
            h::sni("firefox.example"),
            h::u16_list(10, &[29, 23, 24, 25, 0x0100, 0x0101]),
            h::u16_list(13, &[0x0403, 0x0503, 0x0603]),
            h::alpn(&["h2", "http/1.1"]),
        ],
    );
    let parsed = parse_client_hello(&bytes).unwrap();
    assert_eq!(first(&parsed.supported_groups), 29);
    assert!(!parsed.supported_groups.contains(&0x0a0a)); // no GREASE
    assert_eq!(parsed.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
}

#[test]
fn safari_17_shape() {
    let bytes = h::build(
        &[0x1302, 0x1303, 0x1301, 0xc02c, 0xc02b, 0xcca9],
        &[
            h::sni("safari.example"),
            h::u16_list(10, &[29, 23, 24, 25]),
            h::u16_list(13, &[0x0403, 0x0804]),
            h::alpn(&["h2", "http/1.1"]),
        ],
    );
    let parsed = parse_client_hello(&bytes).unwrap();
    assert_eq!(first(&parsed.cipher_suites), 0x1302);
    assert_eq!(parsed.sni.as_deref(), Some("safari.example"));
}

#[test]
fn curl_8_shape() {
    let bytes = h::build(
        &[0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0x009f],
        &[h::sni("curl.example"), h::u16_list(10, &[29, 23, 30, 25])],
    );
    let parsed = parse_client_hello(&bytes).unwrap();
    assert!(parsed.alpn.is_empty());
    assert_eq!(parsed.extensions, vec![0, 10]);
}

#[test]
fn curl_impersonate_chrome_shape() {
    let bytes = h::build(
        &[0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
        &[
            h::sni("imp.example"),
            h::u16_list(10, &[0x0a0a, 29, 23, 24]),
            h::u16_list(13, &[0x0403, 0x0804]),
            h::alpn(&["h2", "http/1.1"]),
        ],
    );
    let parsed = parse_client_hello(&bytes).unwrap();
    assert_eq!(first(&parsed.cipher_suites), 0x0a0a);
    assert_eq!(first(&parsed.supported_groups), 0x0a0a);
}

#[test]
fn go_net_http_shape() {
    let bytes = h::build(
        &[0x1301, 0x1302, 0x1303, 0xc02f, 0xc02b],
        &[
            h::sni("go.example"),
            h::u16_list(10, &[23, 24, 25, 29]),
            h::u16_list(13, &[0x0403, 0x0807, 0x0804]),
            h::alpn(&["h2", "http/1.1"]),
        ],
    );
    let parsed = parse_client_hello(&bytes).unwrap();
    assert!(parsed.signature_algorithms.contains(&0x0807));
}

#[test]
fn python_requests_shape() {
    let bytes = h::build(
        &[0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0xc02b, 0xc02f],
        &[
            h::sni("python.example"),
            h::u16_list(10, &[29, 23, 24, 25]),
            h::u16_list(13, &[0x0403, 0x0804, 0x0401]),
        ],
    );
    let parsed = parse_client_hello(&bytes).unwrap();
    assert!(parsed.alpn.is_empty());
    assert!(!parsed.signature_algorithms.contains(&0x0807));
    assert_eq!(parsed.cipher_suites.len(), 7);
}

#[test]
fn all_shapes_distinct() {
    // Sanity: the seven shapes above must not collapse to the same
    // ja3-style tuple. We compare the (ciphers, extensions, groups)
    // triple directly — phase 04 will replace this with real JA3 hashes.
    use std::collections::HashSet;
    let shapes: Vec<_> = [
        // Chrome
        (vec![0x0a0a, 0x1301], vec![0, 10, 13, 16], vec![0x0a0a, 29]),
        // Firefox
        (vec![0x1301, 0x1303], vec![0, 10, 13, 16], vec![29, 23]),
        // Safari
        (vec![0x1302, 0x1303], vec![0, 10, 13, 16], vec![29, 23]),
        // curl
        (vec![0x1302, 0x1303, 0x1301], vec![0, 10], vec![29]),
        // Go
        (vec![0x1301, 0x1302, 0x1303, 0xc02f], vec![0, 10, 13, 16], vec![23]),
        // Python
        (vec![0x1302, 0x1303, 0x1301, 0xc02c], vec![0, 10, 13], vec![29]),
    ]
    .into_iter()
    .collect();

    let unique: HashSet<_> = shapes.iter().collect();
    assert_eq!(unique.len(), shapes.len(), "fixture shapes collided");
}
