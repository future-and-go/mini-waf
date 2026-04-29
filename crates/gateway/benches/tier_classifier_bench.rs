//! Criterion bench — tier classifier hot-path at 50 rules.
//!
//! Rule distribution: 25 path-prefix, 15 path-regex, 10 host-suffix.
//! Measures per-request `classify()` cost across 1000 pseudo-random paths.
//! Run with: `cargo bench -p gateway tier_classifier`

// Benches legitimately use unwrap/expect/indexing — allow them here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use gateway::tiered::tier_classifier::{RequestParts, TierClassifier};
use http::{HeaderMap, Method};
use waf_common::tier::{Tier, TierClassifierRule};
use waf_common::tier_match::{HostMatch, PathMatch};

const TIERS: [Tier; 4] = [Tier::Critical, Tier::High, Tier::Medium, Tier::CatchAll];

/// Build a classifier with 50 rules:
///
/// - idx 0..25  → path-prefix rules
/// - idx 25..40 → path-regex rules
/// - idx 40..50 → host-suffix rules
fn build_50_rule_classifier() -> TierClassifier {
    let mut rules: Vec<TierClassifierRule> = Vec::with_capacity(50);

    // 25 path-prefix rules
    for i in 0u32..25 {
        rules.push(TierClassifierRule {
            priority: 200 - i,
            tier: TIERS[(i as usize) % TIERS.len()],
            host: None,
            path: Some(PathMatch::Prefix {
                value: format!("/api/v{i}/resource"),
            }),
            method: None,
            headers: None,
        });
    }

    // 15 path-regex rules
    for i in 0u32..15 {
        rules.push(TierClassifierRule {
            priority: 100 - i,
            tier: TIERS[(i as usize) % TIERS.len()],
            host: None,
            path: Some(PathMatch::Regex {
                // Simple numeric-suffix pattern; each rule has a distinct prefix.
                value: format!(r"^/r{i}/\d+(/.*)?$"),
            }),
            method: None,
            headers: None,
        });
    }

    // 10 host-suffix rules
    for i in 0u32..10 {
        rules.push(TierClassifierRule {
            priority: 50 - i,
            tier: TIERS[(i as usize) % TIERS.len()],
            host: Some(HostMatch::Suffix {
                value: format!(".svc{i}.internal"),
            }),
            path: None,
            method: None,
            headers: None,
        });
    }

    TierClassifier::new(&rules, Tier::CatchAll).expect("bench rules must compile")
}

/// 1000 deterministic pseudo-random paths derived from index arithmetic.
fn build_request_paths() -> Vec<String> {
    (0u32..1000)
        .map(|i| match i % 5 {
            0 => format!("/api/v{}/resource/item", i % 30),
            1 => format!("/r{}/{}", i % 15, i * 7),
            2 => format!("/unknown/deep/path/{i}"),
            3 => format!("/static/asset-{i}.js"),
            _ => format!("/health/{i}"),
        })
        .collect()
}

fn classify_50_rules(c: &mut Criterion) {
    let classifier = build_50_rule_classifier();
    let paths = build_request_paths();
    let method = Method::GET;
    let headers = HeaderMap::new();

    c.bench_function("classify_50_rules", |b| {
        b.iter(|| {
            for path in &paths {
                let parts = RequestParts {
                    host: black_box("api.example.com"),
                    path: black_box(path.as_str()),
                    method: black_box(&method),
                    headers: black_box(&headers),
                };
                let _ = black_box(classifier.classify(&parts));
            }
        });
    });
}

criterion_group!(benches, classify_50_rules);
criterion_main!(benches);
