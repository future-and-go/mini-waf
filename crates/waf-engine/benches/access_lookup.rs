//! FR-008 — Criterion benchmark for the access-list hot path.
//!
//! Measures `evaluate()` across four scenarios:
//!   - `blacklist_hit`  : IP in blacklist → Block
//!   - `whitelist_hit`  : IP in whitelist, FullBypass mode → BypassAll
//!   - `host_gate_miss` : host not in per-tier allowlist → Block (HostGate)
//!   - `no_match`       : none of the above → Continue
//!
//! The trie is built with 1 000 entries before the bench loop so `b.iter` only
//! measures the lookup, not the setup.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::semicolon_if_nothing_returned,
    clippy::doc_markdown
)]

use std::net::IpAddr;
use std::sync::Arc;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use waf_common::tier::Tier;
use waf_engine::access::{AccessLists, AccessRequestView};

// ── fixture builders ─────────────────────────────────────────────────────────

/// Build an `AccessLists` with:
///   - 1 000 blacklist /32 entries in 10.1.0.0/22
///   - 1 000 whitelist /32 entries in 10.2.0.0/22
///   - 100  host-gate entries for `Tier::Critical`
///   - `FullBypass` mode for `Tier::Medium`
fn build_lists() -> Arc<AccessLists> {
    let mut lines = vec!["version: 1".to_string(), "ip_blacklist:".to_string()];
    // 1 000 blacklist IPs: 10.1.{0..3}.{0..249}
    for b in 0u8..4 {
        for c in 0u8..250 {
            lines.push(format!("  - 10.1.{b}.{c}"));
        }
    }

    lines.push("ip_whitelist:".to_string());
    // 1 000 whitelist IPs: 10.2.{0..3}.{0..249}
    for b in 0u8..4 {
        for c in 0u8..250 {
            lines.push(format!("  - 10.2.{b}.{c}"));
        }
    }

    // 100 host-gate entries for Critical tier.
    lines.push("host_whitelist:".to_string());
    lines.push("  critical:".to_string());
    for i in 0u32..100 {
        lines.push(format!("    - host{i}.example.com"));
    }

    // FullBypass for Medium so the whitelist_hit bench exercises that path.
    lines.push("tier_whitelist_mode:".to_string());
    lines.push("  medium: full_bypass".to_string());

    let yaml = lines.join("\n");
    AccessLists::from_yaml_str(&yaml).expect("bench fixture yaml must parse")
}

fn view(ip: &str, host: &'static str, tier: Tier) -> AccessRequestView<'static> {
    AccessRequestView {
        client_ip: ip.parse::<IpAddr>().expect("bench ip parses"),
        host,
        tier,
    }
}

// ── bench functions ───────────────────────────────────────────────────────────

fn bench_blacklist_hit(c: &mut Criterion) {
    let lists = build_lists();
    let v = view("10.1.0.7", "anything.example.com", Tier::Medium);
    c.bench_function("access/blacklist_hit", |b| {
        b.iter(|| black_box(lists.evaluate(black_box(&v))))
    });
}

fn bench_whitelist_hit(c: &mut Criterion) {
    let lists = build_lists();
    // 10.2.x.x is in whitelist; Medium tier uses FullBypass → BypassAll.
    let v = view("10.2.0.7", "anything.example.com", Tier::Medium);
    c.bench_function("access/whitelist_hit", |b| {
        b.iter(|| black_box(lists.evaluate(black_box(&v))))
    });
}

fn bench_host_gate_miss(c: &mut Criterion) {
    let lists = build_lists();
    // Critical tier has host-gate; "unknown.example.com" is not in the list.
    let v = view("198.51.100.1", "unknown.example.com", Tier::Critical);
    c.bench_function("access/host_gate_miss", |b| {
        b.iter(|| black_box(lists.evaluate(black_box(&v))))
    });
}

fn bench_no_match_continue(c: &mut Criterion) {
    let lists = build_lists();
    // IP not in any list; Medium tier host-gate is disabled → Continue.
    let v = view("8.8.8.8", "public.example.com", Tier::Medium);
    c.bench_function("access/no_match_continue", |b| {
        b.iter(|| black_box(lists.evaluate(black_box(&v))))
    });
}

// ── criterion wiring ─────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_blacklist_hit,
    bench_whitelist_hit,
    bench_host_gate_miss,
    bench_no_match_continue
);
criterion_main!(benches);
