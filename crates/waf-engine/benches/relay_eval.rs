//! FR-007 phase-07 bench — RelayDetector::evaluate throughput.
//!
//! Workload: 4-hop XFF chain, all four providers (XffValidator,
//! ProxyChainAnalyzer, AsnClassifier(StaticDb hit), TorExitMatcher(10 IPs)).
//! StaticDb returns a fixed AsnRecord so the classifier exercises the
//! HashSet contains() + DatacenterSet branches, not just the early-return
//! `None` path EmptyAsnDb gives — that produced an unrealistically fast bench.
//! Criterion reports p99; the 50µs regression gate is enforced in CI nightly,
//! not in bench code itself.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use http::{HeaderMap, HeaderName, HeaderValue};
use waf_engine::relay::intel::{AsnDb, AsnRecord, DatacenterSet};
use waf_engine::relay::providers::asn_classifier::AsnClassifier;
use waf_engine::relay::providers::tor_exit::{TorExitMatcher, TorSet};
use waf_engine::relay::providers::{ProxyChainAnalyzer, XffValidator};
use waf_engine::relay::{ProviderRegistry, RelayConfig, RelayDetector};

/// Fixed-record ASN db: every lookup hits, so AsnClassifier walks the
/// DatacenterSet branches (matches what the 50µs gate is actually measuring).
struct StaticDb(AsnRecord);
impl AsnDb for StaticDb {
    fn lookup(&self, _ip: IpAddr) -> Option<AsnRecord> {
        Some(self.0.clone())
    }
    fn name(&self) -> &'static str {
        "bench_static"
    }
}

fn build_detector() -> RelayDetector {
    let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];

    let mut registry = ProviderRegistry::new();

    registry.register(Box::new(
        XffValidator::new(&["X-Forwarded-For".to_string()], trusted.clone()).unwrap(),
    ));
    registry.register(Box::new(
        ProxyChainAnalyzer::new(&["X-Forwarded-For".to_string()], trusted, 10).unwrap(),
    ));
    let mut dc = DatacenterSet::default();
    dc.asn_ids.insert(15169);
    let static_db = StaticDb(AsnRecord {
        asn: 7922,
        org: "COMCAST".into(),
    });
    registry.register(Box::new(AsnClassifier::new(Box::new(static_db), Arc::new(dc))));

    // Small TorSet: 10 IPs, none of which match the bench probe.
    let mut tor_ips = HashSet::new();
    for i in 0u8..10 {
        tor_ips.insert(IpAddr::V4(Ipv4Addr::new(198, 51, 100, i)));
    }
    registry.register(Box::new(TorExitMatcher::from_set(TorSet::new(tor_ips))));

    let cfg = RelayConfig::default();
    RelayDetector::new(Arc::new(cfg), registry)
}

fn build_headers() -> HeaderMap {
    // 4-hop XFF chain: 3 public hops + 1 trusted proxy (10.0.0.1).
    let mut h = HeaderMap::new();
    h.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_static("203.0.113.5, 1.2.3.4, 5.6.7.8, 10.0.0.1"),
    );
    h
}

fn bench_relay_eval(c: &mut Criterion) {
    let detector = build_detector();
    let headers = build_headers();
    let peer: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    c.bench_function("relay_eval_4hop", |b| {
        b.iter(|| {
            black_box(detector.evaluate(black_box(peer), black_box(&headers)));
        });
    });
}

criterion_group!(benches, bench_relay_eval);
criterion_main!(benches);
