//! FR-003 acceptance suite — exercises the rule engine end-to-end through the
//! public API. One test per row of the AC matrix in the brainstorm; AC-8 is
//! parameterised across the 4-row truth table. Plus regression coverage for
//! legacy DB-rule shapes (flat AND/OR + cookie whole-header).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;

use waf_common::{HostConfig, RequestCtx, parse_cookie_header};
use waf_engine::CustomRulesEngine;
use waf_engine::rules::engine::{
    AndBranch, Condition, ConditionField, ConditionNode, ConditionOp, ConditionValue, CustomRule, NotBranch, Operator,
    OrBranch, RuleAction,
};

// ── Builders ─────────────────────────────────────────────────────────────────

struct CtxBuilder {
    ip: String,
    path: String,
    method: String,
    query: String,
    headers: HashMap<String, String>,
    body: Bytes,
    cookies: HashMap<String, String>,
}

impl CtxBuilder {
    fn new() -> Self {
        Self {
            ip: "1.2.3.4".into(),
            path: "/".into(),
            method: "GET".into(),
            query: String::new(),
            headers: HashMap::new(),
            body: Bytes::new(),
            cookies: HashMap::new(),
        }
    }
    fn ip(mut self, v: &str) -> Self {
        self.ip = v.into();
        self
    }
    fn path(mut self, v: &str) -> Self {
        self.path = v.into();
        self
    }
    fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.insert(k.to_lowercase(), v.into());
        self
    }
    fn cookie_header(mut self, raw: &str) -> Self {
        self.cookies = parse_cookie_header(raw);
        self.headers.insert("cookie".into(), raw.into());
        self
    }
    fn body(mut self, b: &str) -> Self {
        self.body = Bytes::from(b.to_string());
        self
    }
    fn build(self) -> RequestCtx {
        let host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            ..HostConfig::default()
        });
        let content_length = self.body.len() as u64;
        RequestCtx {
            req_id: "ac".into(),
            client_ip: self.ip.parse().unwrap(),
            client_port: 12345,
            method: self.method,
            host: "example.com".into(),
            port: 80,
            path: self.path,
            query: self.query,
            headers: self.headers,
            body_preview: self.body,
            content_length,
            is_tls: false,
            host_config,
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
            cookies: self.cookies,
        }
    }
}

fn rule_flat(id: &str, op: ConditionOp, conditions: Vec<Condition>) -> CustomRule {
    CustomRule {
        id: id.into(),
        host_code: "test".into(),
        name: id.into(),
        priority: 1,
        enabled: true,
        condition_op: op,
        conditions,
        action: RuleAction::Block,
        action_status: 403,
        action_msg: None,
        script: None,
        match_tree: None,
    }
}

fn rule_tree(id: &str, tree: ConditionNode) -> CustomRule {
    CustomRule {
        id: id.into(),
        host_code: "test".into(),
        name: id.into(),
        priority: 1,
        enabled: true,
        condition_op: ConditionOp::And,
        conditions: Vec::new(),
        action: RuleAction::Block,
        action_status: 403,
        action_msg: None,
        script: None,
        match_tree: Some(tree),
    }
}

const fn cond(field: ConditionField, op: Operator, v: ConditionValue) -> Condition {
    Condition {
        field,
        operator: op,
        value: v,
    }
}

fn engine_with(rule: CustomRule) -> CustomRulesEngine {
    let e = CustomRulesEngine::new();
    e.add_rule(rule);
    e
}

// ═══════════════════════════════════════════════════════════════════════════════
// AC matrix — one test per row
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ac01_ip_cidr_match() {
    let e = engine_with(rule_flat(
        "ac01",
        ConditionOp::And,
        vec![cond(
            ConditionField::Ip,
            Operator::CidrMatch,
            ConditionValue::Str("10.0.0.0/8".into()),
        )],
    ));
    assert!(e.check(&CtxBuilder::new().ip("10.0.1.5").build()).is_some());
    assert!(e.check(&CtxBuilder::new().ip("192.168.0.1").build()).is_none());
}

#[test]
fn ac02_path_exact() {
    let e = engine_with(rule_flat(
        "ac02",
        ConditionOp::And,
        vec![cond(
            ConditionField::Path,
            Operator::Eq,
            ConditionValue::Str("/login".into()),
        )],
    ));
    assert!(e.check(&CtxBuilder::new().path("/login").build()).is_some());
    assert!(e.check(&CtxBuilder::new().path("/login/x").build()).is_none());
}

#[test]
fn ac03_path_wildcard_glob() {
    let e = engine_with(rule_flat(
        "ac03",
        ConditionOp::And,
        vec![cond(
            ConditionField::Path,
            Operator::Wildcard,
            ConditionValue::Str("/api/*/admin".into()),
        )],
    ));
    assert!(e.check(&CtxBuilder::new().path("/api/v1/admin").build()).is_some());
    // `*` is segment-bounded — must not cross `/`.
    assert!(e.check(&CtxBuilder::new().path("/api/v1/v2/admin").build()).is_none());
    assert!(e.check(&CtxBuilder::new().path("/api/admin").build()).is_none());
}

#[test]
fn ac04_path_regex() {
    let e = engine_with(rule_flat(
        "ac04",
        ConditionOp::And,
        vec![cond(
            ConditionField::Path,
            Operator::Regex,
            ConditionValue::Str(r"^/users/\d+$".into()),
        )],
    ));
    assert!(e.check(&CtxBuilder::new().path("/users/42").build()).is_some());
    assert!(e.check(&CtxBuilder::new().path("/users/abc").build()).is_none());
}

#[test]
fn ac05_header_contains() {
    let e = engine_with(rule_flat(
        "ac05",
        ConditionOp::And,
        vec![cond(
            ConditionField::Header("x-forwarded-for".into()),
            Operator::Contains,
            ConditionValue::Str("10.0.0.1".into()),
        )],
    ));
    assert!(
        e.check(&CtxBuilder::new().header("x-forwarded-for", "10.0.0.1, 9.9.9.9").build())
            .is_some()
    );
    assert!(
        e.check(&CtxBuilder::new().header("x-forwarded-for", "1.1.1.1").build())
            .is_none()
    );
}

#[test]
fn ac06_cookie_by_name_eq() {
    let e = engine_with(rule_flat(
        "ac06",
        ConditionOp::And,
        vec![cond(
            ConditionField::Cookie(Some("session".into())),
            Operator::Eq,
            ConditionValue::Str("abc".into()),
        )],
    ));
    assert!(
        e.check(&CtxBuilder::new().cookie_header("session=abc; o=1").build())
            .is_some()
    );
    assert!(
        e.check(&CtxBuilder::new().cookie_header("session=zzz").build())
            .is_none()
    );
    assert!(e.check(&CtxBuilder::new().cookie_header("o=1").build()).is_none());
}

#[test]
fn ac07_body_contains_script() {
    let payload = format!("<script>{}</script>", "x".repeat(1000));
    let e = engine_with(rule_flat(
        "ac07",
        ConditionOp::And,
        vec![cond(
            ConditionField::Body,
            Operator::Contains,
            ConditionValue::Str("<script>".into()),
        )],
    ));
    assert!(e.check(&CtxBuilder::new().body(&payload).build()).is_some());
    assert!(e.check(&CtxBuilder::new().body("hello world").build()).is_none());
}

// ── AC-8 truth table ─────────────────────────────────────────────────────────
// (ip in 10.0.0.0/8 OR cookie session=bad) AND path~/api/*/admin

fn ac8_engine() -> CustomRulesEngine {
    let tree = ConditionNode::And(AndBranch {
        and: vec![
            ConditionNode::Or(OrBranch {
                or: vec![
                    ConditionNode::Leaf(cond(
                        ConditionField::Ip,
                        Operator::CidrMatch,
                        ConditionValue::Str("10.0.0.0/8".into()),
                    )),
                    ConditionNode::Leaf(cond(
                        ConditionField::Cookie(Some("session".into())),
                        Operator::Eq,
                        ConditionValue::Str("bad".into()),
                    )),
                ],
            }),
            ConditionNode::Leaf(cond(
                ConditionField::Path,
                Operator::Wildcard,
                ConditionValue::Str("/api/*/admin".into()),
            )),
        ],
    });
    engine_with(rule_tree("ac08", tree))
}

#[test]
fn ac08_tt_left_and_right_true_matches() {
    let e = ac8_engine();
    assert!(
        e.check(&CtxBuilder::new().ip("10.0.1.5").path("/api/v1/admin").build())
            .is_some()
    );
    assert!(
        e.check(
            &CtxBuilder::new()
                .ip("1.2.3.4")
                .path("/api/v1/admin")
                .cookie_header("session=bad")
                .build()
        )
        .is_some()
    );
}

#[test]
fn ac08_tf_left_true_right_false_misses() {
    let e = ac8_engine();
    assert!(
        e.check(&CtxBuilder::new().ip("10.0.1.5").path("/public").build())
            .is_none()
    );
}

#[test]
fn ac08_ft_left_false_right_true_misses() {
    let e = ac8_engine();
    assert!(
        e.check(
            &CtxBuilder::new()
                .ip("1.2.3.4")
                .path("/api/v1/admin")
                .cookie_header("session=ok")
                .build()
        )
        .is_none()
    );
}

#[test]
fn ac08_ff_misses() {
    let e = ac8_engine();
    assert!(
        e.check(&CtxBuilder::new().ip("1.2.3.4").path("/public").build())
            .is_none()
    );
}

#[test]
fn ac08_not_node_inverts_match() {
    // (NOT path=/healthz) AND method=GET → matches anything but /healthz
    let tree = ConditionNode::And(AndBranch {
        and: vec![
            ConditionNode::Not(NotBranch {
                not: Box::new(ConditionNode::Leaf(cond(
                    ConditionField::Path,
                    Operator::Eq,
                    ConditionValue::Str("/healthz".into()),
                ))),
            }),
            ConditionNode::Leaf(cond(
                ConditionField::Method,
                Operator::Eq,
                ConditionValue::Str("GET".into()),
            )),
        ],
    });
    let e = engine_with(rule_tree("ac08-not", tree));
    assert!(e.check(&CtxBuilder::new().path("/api").build()).is_some());
    assert!(e.check(&CtxBuilder::new().path("/healthz").build()).is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Regression — legacy DB rule shapes still match
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn regression_legacy_flat_and_rule_still_matches() {
    let e = engine_with(rule_flat(
        "leg-and",
        ConditionOp::And,
        vec![
            cond(
                ConditionField::Path,
                Operator::StartsWith,
                ConditionValue::Str("/admin".into()),
            ),
            cond(ConditionField::Method, Operator::Eq, ConditionValue::Str("POST".into())),
        ],
    ));
    let mut ctx = CtxBuilder::new().path("/admin/users").build();
    ctx.method = "POST".into();
    assert!(e.check(&ctx).is_some());
    let mut ctx2 = CtxBuilder::new().path("/admin/users").build();
    ctx2.method = "GET".into();
    assert!(e.check(&ctx2).is_none());
}

#[test]
fn regression_legacy_flat_or_rule_still_matches() {
    let e = engine_with(rule_flat(
        "leg-or",
        ConditionOp::Or,
        vec![
            cond(
                ConditionField::Ip,
                Operator::CidrMatch,
                ConditionValue::Str("10.0.0.0/8".into()),
            ),
            cond(
                ConditionField::Path,
                Operator::Eq,
                ConditionValue::Str("/blocked".into()),
            ),
        ],
    ));
    assert!(e.check(&CtxBuilder::new().ip("10.0.0.1").path("/x").build()).is_some());
    assert!(
        e.check(&CtxBuilder::new().ip("9.9.9.9").path("/blocked").build())
            .is_some()
    );
    assert!(e.check(&CtxBuilder::new().ip("9.9.9.9").path("/x").build()).is_none());
}

#[test]
fn regression_legacy_cookie_full_header() {
    // Legacy field=cookie (no name) → operator on whole Cookie header value.
    let e = engine_with(rule_flat(
        "leg-ck",
        ConditionOp::And,
        vec![cond(
            ConditionField::Cookie(None),
            Operator::Contains,
            ConditionValue::Str("track=1".into()),
        )],
    ));
    assert!(
        e.check(&CtxBuilder::new().cookie_header("a=b; track=1").build())
            .is_some()
    );
    assert!(e.check(&CtxBuilder::new().cookie_header("a=b").build()).is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Security — malformed inputs reject without panic
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn malformed_regex_rule_is_skipped_not_panic() {
    use waf_engine::rules::engine::compile_rule;
    let bad = rule_flat(
        "bad-re",
        ConditionOp::And,
        vec![cond(
            ConditionField::Path,
            Operator::Regex,
            ConditionValue::Str("(unclosed".into()),
        )],
    );
    assert!(compile_rule(&bad).is_err());
    // Engine must still load (rule simply skipped) and not match anything.
    let e = engine_with(bad);
    assert!(e.check(&CtxBuilder::new().path("/anything").build()).is_none());
}

#[test]
fn deeply_nested_tree_rejected_by_validator() {
    use waf_engine::rules::engine::{MAX_TREE_DEPTH, validate_tree};
    let mut node = ConditionNode::Leaf(cond(
        ConditionField::Path,
        Operator::Eq,
        ConditionValue::Str("/x".into()),
    ));
    for _ in 0..=MAX_TREE_DEPTH {
        node = ConditionNode::Not(NotBranch { not: Box::new(node) });
    }
    assert!(validate_tree(&node).is_err());
}
