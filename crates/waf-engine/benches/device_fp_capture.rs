//! FR-010 phase-03 bench — capture parse + h2 frame append throughput.
//!
//! Targets from plan phase-03: `ClientHello` parse < 50µs, h2 frame append
//! < 30µs (single-frame). Criterion reports p99 in HTML output;
//! enforcement of the regression gate lives in CI, not bench code.

use std::sync::Arc;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use pingora_core::protocols::inspector::{H2FrameInspector, H2FrameSnapshot};

use waf_engine::device_fp::capture::{ConnCtx, H2FrameTap, parse_client_hello};

fn u16_be(n: usize) -> [u8; 2] {
    u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes()
}

fn build_chrome_like_hello() -> Vec<u8> {
    // Mirrors the Chrome 121 fixture in tests/device_fp_capture_fixtures.rs.
    let mut body = Vec::with_capacity(160);
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);

    let cs: [u16; 8] = [0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030];
    let cs_bytes: Vec<u8> = cs.iter().flat_map(|c| c.to_be_bytes()).collect();
    body.extend_from_slice(&u16_be(cs_bytes.len()));
    body.extend_from_slice(&cs_bytes);
    body.push(1);
    body.push(0);

    let mut ext_buf = Vec::new();
    let mut push_ext = |ty: u16, data: &[u8]| {
        ext_buf.extend_from_slice(&ty.to_be_bytes());
        ext_buf.extend_from_slice(&u16_be(data.len()));
        ext_buf.extend_from_slice(data);
    };

    let host = b"bench.example";
    let entry_len = 1 + 2 + host.len();
    let mut sni = Vec::with_capacity(2 + entry_len);
    sni.extend_from_slice(&u16_be(entry_len));
    sni.push(0);
    sni.extend_from_slice(&u16_be(host.len()));
    sni.extend_from_slice(host);
    push_ext(0, &sni);

    let groups: [u16; 4] = [0x0a0a, 29, 23, 24];
    let inner: Vec<u8> = groups.iter().flat_map(|g| g.to_be_bytes()).collect();
    let mut g = Vec::with_capacity(2 + inner.len());
    g.extend_from_slice(&u16_be(inner.len()));
    g.extend_from_slice(&inner);
    push_ext(10, &g);

    let sigs: [u16; 3] = [0x0403, 0x0804, 0x0401];
    let inner: Vec<u8> = sigs.iter().flat_map(|s| s.to_be_bytes()).collect();
    let mut s = Vec::with_capacity(2 + inner.len());
    s.extend_from_slice(&u16_be(inner.len()));
    s.extend_from_slice(&inner);
    push_ext(13, &s);

    let mut alpn_inner = Vec::new();
    for p in &["h2", "http/1.1"] {
        alpn_inner.push(u8::try_from(p.len()).unwrap_or(u8::MAX));
        alpn_inner.extend_from_slice(p.as_bytes());
    }
    let mut alpn = Vec::with_capacity(2 + alpn_inner.len());
    alpn.extend_from_slice(&u16_be(alpn_inner.len()));
    alpn.extend_from_slice(&alpn_inner);
    push_ext(16, &alpn);

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

fn bench_tls_capture_parse(c: &mut Criterion) {
    let hello = build_chrome_like_hello();
    c.bench_function("tls_capture_parse", |b| {
        b.iter(|| {
            let parsed = parse_client_hello(black_box(&hello)).ok();
            black_box(parsed);
        });
    });
}

fn bench_h2_frame_append(c: &mut Criterion) {
    let ctx = Arc::new(ConnCtx::new());
    let tap = H2FrameTap::new(Arc::clone(&ctx));
    let pairs: [(u16, u32); 4] = [(0x1, 65_536), (0x2, 0), (0x4, 6_291_456), (0x6, 262_144)];
    c.bench_function("h2_frame_append_settings", |b| {
        b.iter(|| {
            tap.on_frame(black_box(&H2FrameSnapshot::Settings(&pairs)));
        });
    });

    let pseudo: [&str; 4] = [":method", ":authority", ":scheme", ":path"];
    c.bench_function("h2_frame_append_headers", |b| {
        b.iter(|| {
            tap.on_frame(black_box(&H2FrameSnapshot::Headers {
                stream_id: 1,
                pseudo_order: &pseudo,
                end_headers: true,
            }));
        });
    });
}

criterion_group!(benches, bench_tls_capture_parse, bench_h2_frame_append);
criterion_main!(benches);
