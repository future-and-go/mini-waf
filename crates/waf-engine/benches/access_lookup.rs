//! FR-008 phase-07 bench — IP/CIDR longest-prefix lookup.
//!
//! Target (brainstorm §7): p99 ≤ 2 µs at 10 000 v4 entries; v6 ≤ 4 µs.
//! Runs three sizes (1, 100, 10 000) for each address family so the regression
//! signal includes both the constant-factor floor and the high-fan-out tail.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use waf_engine::access::IpCidrTable;

const SIZES: [usize; 3] = [1, 100, 10_000];

fn build_v4(n: usize) -> IpCidrTable {
    let mut t = IpCidrTable::new();
    for i in 0..n {
        // Spread /24s over 10.0.0.0/8 — 65 536 unique prefixes available.
        let cidr = format!("10.{}.{}.0/24", (i / 256) % 256, i % 256);
        t.insert_str(&cidr).expect("v4 cidr inserts");
    }
    t
}

fn build_v6(n: usize) -> IpCidrTable {
    let mut t = IpCidrTable::new();
    for i in 0..n {
        // /48 prefixes inside 2001:db8::/32 documentation range. The third
        // hextet absorbs the 16-bit index; remaining hextets must be zero or
        // `IpNetwork` rejects the prefix as having host bits set.
        let cidr = format!("2001:db8:{:x}::/48", i & 0xffff);
        t.insert_str(&cidr).expect("v6 cidr inserts");
    }
    t
}

fn bench_v4(c: &mut Criterion) {
    let needle: IpAddr = "10.5.6.7".parse().unwrap();
    for n in SIZES {
        let table = build_v4(n);
        c.bench_function(&format!("access_lookup_v4_{n}"), |b| {
            b.iter(|| black_box(table.contains(black_box(needle))));
        });
    }
}

fn bench_v6(c: &mut Criterion) {
    let needle: IpAddr = "2001:db8:5:6::1".parse().unwrap();
    for n in SIZES {
        let table = build_v6(n);
        c.bench_function(&format!("access_lookup_v6_{n}"), |b| {
            b.iter(|| black_box(table.contains(black_box(needle))));
        });
    }
}

criterion_group!(benches, bench_v4, bench_v6);
criterion_main!(benches);
