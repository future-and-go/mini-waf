//! FR-003 phase-05 bench — proves the pre-compilation perf claim.
//!
//! - `compiled` group: 100 mixed-operator rules pre-loaded into
//!   `CustomRulesEngine` (regex/CIDR compiled once at insert time).
//!   Hot path = `check()` only.
//! - `baseline` group: same rule set but compile-per-request (fresh engine
//!   built inside the timed loop). Establishes the un-cached cost.
//!
//! Target per brainstorm §7: compiled ≥ 5× faster than baseline.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::semicolon_if_nothing_returned
)]

use bytes::Bytes;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::collections::HashMap;
use std::sync::Arc;
use waf_common::{HostConfig, RequestCtx};
use waf_engine::CustomRulesEngine;
use waf_engine::rules::engine::{
    Condition, ConditionField, ConditionOp, ConditionValue, CustomRule, Operator, RuleAction,
};

const N_RULES: usize = 100;

fn make_rules() -> Vec<CustomRule> {
    let mut rules = Vec::with_capacity(N_RULES);
    for i in 0..N_RULES {
        // Mix: 50% regex, 25% wildcard, 15% cidr, 10% starts_with — covers the
        // expensive-to-compile operators.
        let cond = match i % 20 {
            0..=9 => Condition {
                field: ConditionField::Path,
                operator: Operator::Regex,
                value: ConditionValue::Str(format!(r"^/r{i}/\d+/[a-z]+$")),
            },
            10..=14 => Condition {
                field: ConditionField::Path,
                operator: Operator::Wildcard,
                value: ConditionValue::Str(format!("/w{i}/*/x")),
            },
            15..=17 => Condition {
                field: ConditionField::Ip,
                operator: Operator::CidrMatch,
                value: ConditionValue::Str(format!("10.{i}.0.0/16")),
            },
            _ => Condition {
                field: ConditionField::Path,
                operator: Operator::StartsWith,
                value: ConditionValue::Str(format!("/s{i}/")),
            },
        };
        rules.push(CustomRule {
            id: format!("r{i}"),
            host_code: "test".into(),
            name: format!("rule-{i}"),
            priority: i32::try_from(i).unwrap_or(i32::MAX),
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![cond],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
            match_tree: None,
        });
    }
    rules
}

fn make_ctx(path: &str) -> RequestCtx {
    let host_config = Arc::new(HostConfig {
        code: "test".into(),
        host: "example.com".into(),
        ..HostConfig::default()
    });
    RequestCtx {
        req_id: "bench".into(),
        client_ip: "192.168.1.1".parse().unwrap(),
        client_port: 12345,
        method: "GET".into(),
        host: "example.com".into(),
        port: 80,
        path: path.into(),
        query: String::new(),
        headers: HashMap::new(),
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config,
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: waf_common::RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
    }
}

fn bench_rule_eval_compiled(c: &mut Criterion) {
    let rules = make_rules();
    let engine = CustomRulesEngine::new();
    engine.load_host("test", rules);
    let ctx = make_ctx("/no/match/path");
    c.bench_function("rule_eval_compiled_100rules_miss", |b| {
        b.iter(|| {
            black_box(engine.check(black_box(&ctx)));
        });
    });
}

fn bench_rule_eval_baseline(c: &mut Criterion) {
    let rules = make_rules();
    let ctx = make_ctx("/no/match/path");
    c.bench_function("rule_eval_baseline_compile_per_call", |b| {
        b.iter(|| {
            // Rebuild engine each iteration → simulates the "no pre-compilation"
            // cost (regex/CIDR compiled per request).
            let engine = CustomRulesEngine::new();
            engine.load_host("test", rules.clone());
            black_box(engine.check(black_box(&ctx)));
        });
    });
}

criterion_group!(benches, bench_rule_eval_compiled, bench_rule_eval_baseline);
criterion_main!(benches);
