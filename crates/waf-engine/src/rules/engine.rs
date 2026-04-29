//! Custom WAF Rules Engine
//!
//! Evaluates user-defined rules stored in `PostgreSQL` against incoming requests.
//! Each rule has:
//!   - Conditions (AND/OR) matching fields of the request
//!   - An action (Block / Allow / Log / Challenge)
//!   - An optional Rhai script for complex evaluation logic

use std::sync::Arc;

use anyhow::Context as _;
use dashmap::DashMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::warn;

use waf_common::{DetectionResult, Phase, RequestCtx};

// ── Condition field ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionField {
    Ip,
    Path,
    Query,
    Method,
    Body,
    Cookie,
    UserAgent,
    ContentType,
    ContentLength,
    Host,
    /// Arbitrary header — value is the header name (lowercased)
    Header(String),
    // ── GeoIP fields (populated when GeoIP is enabled) ──────────────────────
    /// Full country name (e.g. "China", "United States")
    GeoCountry,
    /// ISO 3166-1 alpha-2 country code (e.g. "CN", "US")
    GeoIso,
    /// Province / state
    GeoProvince,
    /// City
    GeoCity,
    /// ISP / organization
    GeoIsp,
}

// ── Comparison operator ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Eq,
    Ne,
    Contains,
    NotContains,
    StartsWith,
    EndsWith,
    Regex,
    InList,
    NotInList,
    CidrMatch,
    Gt,
    Lt,
    Gte,
    Lte,
}

// ── Condition value ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionValue {
    Str(String),
    List(Vec<String>),
    Number(i64),
}

// ── Single condition ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: ConditionField,
    pub operator: Operator,
    pub value: ConditionValue,
}

// ── Condition combinator ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConditionOp {
    #[default]
    And,
    Or,
}

impl ConditionOp {
    pub const fn parse_str(s: &str) -> Self {
        if s.eq_ignore_ascii_case("or") {
            Self::Or
        } else {
            Self::And
        }
    }
}

// ── Rule action ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Block,
    Allow,
    Log,
    Challenge,
}

impl RuleAction {
    pub fn parse_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "allow" => Self::Allow,
            "log" => Self::Log,
            "challenge" => Self::Challenge,
            _ => Self::Block,
        }
    }
}

// ── A single custom WAF rule ──────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CustomRule {
    pub id: String,
    pub host_code: String,
    pub name: String,
    pub priority: i32,
    pub enabled: bool,
    pub condition_op: ConditionOp,
    pub conditions: Vec<Condition>,
    pub action: RuleAction,
    pub action_status: u16,
    pub action_msg: Option<String>,
    /// Optional Rhai expression that overrides `conditions` when present.
    pub script: Option<String>,
}

// ── Custom rules engine ───────────────────────────────────────────────────────

/// Thread-safe custom rules engine.
///
/// Rules are cached in a `DashMap<host_code, Vec<CustomRule>>` sorted by
/// priority (ascending — lower number wins).  A special key `"*"` holds
/// global rules that apply to every host.
pub struct CustomRulesEngine {
    rules: DashMap<String, Vec<CustomRule>>,
    rhai: Arc<rhai::Engine>,
}

impl CustomRulesEngine {
    pub fn new() -> Self {
        let mut engine = rhai::Engine::new();
        // Restrict the scripting sandbox
        engine.set_max_operations(100_000);
        engine.set_max_call_levels(16);
        engine.set_max_expr_depths(64, 32);

        Self {
            rules: DashMap::new(),
            rhai: Arc::new(engine),
        }
    }

    /// Replace all rules for a host (sorted by priority).
    pub fn load_host(&self, host_code: &str, mut rules: Vec<CustomRule>) {
        rules.retain(|r| r.enabled);
        rules.sort_by_key(|r| r.priority);
        self.rules.insert(host_code.to_string(), rules);
    }

    /// Append a single rule (hot-add).
    pub fn add_rule(&self, rule: CustomRule) {
        let host_code = rule.host_code.clone();
        let mut entry = self.rules.entry(host_code).or_default();
        entry.push(rule);
        entry.sort_by_key(|r| r.priority);
    }

    /// Remove a rule by ID.
    pub fn remove_rule(&self, host_code: &str, rule_id: &str) {
        if let Some(mut rules) = self.rules.get_mut(host_code) {
            rules.retain(|r| r.id != rule_id);
        }
    }

    /// Total number of cached rules.
    pub fn len(&self) -> usize {
        self.rules.iter().map(|e| e.value().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Evaluate all rules against the request context.
    ///
    /// Returns the first matching `DetectionResult`, or `None`.
    pub fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        let host_code = &ctx.host_config.code;

        // Host-specific rules first
        if let Some(rules) = self.rules.get(host_code)
            && let Some(r) = self.eval_list(ctx, &rules)
        {
            return Some(r);
        }

        // Global rules
        if let Some(rules) = self.rules.get("*")
            && let Some(r) = self.eval_list(ctx, &rules)
        {
            return Some(r);
        }

        None
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn eval_list(&self, ctx: &RequestCtx, rules: &[CustomRule]) -> Option<DetectionResult> {
        for rule in rules {
            if !rule.enabled {
                continue;
            }

            let matched = rule.script.as_ref().map_or_else(
                || self.eval_conditions(ctx, &rule.conditions, &rule.condition_op),
                |script| self.eval_script(ctx, script),
            );

            if matched {
                return Some(DetectionResult {
                    rule_id: Some(rule.id.clone()),
                    rule_name: rule.name.clone(),
                    phase: Phase::CustomRule,
                    detail: format!("Custom rule '{}' matched", rule.name),
                });
            }
        }
        None
    }

    fn eval_script(&self, ctx: &RequestCtx, script: &str) -> bool {
        let mut scope = rhai::Scope::new();
        scope.push("ip", ctx.client_ip.to_string());
        scope.push("path", ctx.path.clone());
        scope.push("method", ctx.method.clone());
        scope.push("query", ctx.query.clone());
        scope.push("host", ctx.host.clone());
        scope.push("user_agent", ctx.headers.get("user-agent").cloned().unwrap_or_default());
        scope.push("referer", ctx.headers.get("referer").cloned().unwrap_or_default());
        scope.push(
            "content_type",
            ctx.headers.get("content-type").cloned().unwrap_or_default(),
        );
        #[allow(clippy::cast_possible_wrap)]
        scope.push("content_length", ctx.content_length as i64);

        self.rhai
            .eval_expression_with_scope::<bool>(&mut scope, script)
            .unwrap_or_else(|e| {
                warn!("Rhai script error: {e}");
                false
            })
    }

    fn eval_conditions(&self, ctx: &RequestCtx, conditions: &[Condition], op: &ConditionOp) -> bool {
        if conditions.is_empty() {
            return false;
        }
        match op {
            ConditionOp::And => conditions.iter().all(|c| self.eval_one(ctx, c)),
            ConditionOp::Or => conditions.iter().any(|c| self.eval_one(ctx, c)),
        }
    }

    fn eval_one(&self, ctx: &RequestCtx, cond: &Condition) -> bool {
        let fval = self.field_value(ctx, &cond.field);
        let fstr = fval.as_deref().unwrap_or("");

        match (&cond.operator, &cond.value) {
            (Operator::Eq, ConditionValue::Str(v)) => fstr.eq_ignore_ascii_case(v),
            (Operator::Ne, ConditionValue::Str(v)) => !fstr.eq_ignore_ascii_case(v),
            (Operator::Contains, ConditionValue::Str(v)) => fstr.contains(v.as_str()),
            (Operator::NotContains, ConditionValue::Str(v)) => !fstr.contains(v.as_str()),
            (Operator::StartsWith, ConditionValue::Str(v)) => fstr.starts_with(v.as_str()),
            (Operator::EndsWith, ConditionValue::Str(v)) => fstr.ends_with(v.as_str()),
            (Operator::Regex, ConditionValue::Str(v)) => Regex::new(v).ok().is_some_and(|r| r.is_match(fstr)),
            (Operator::InList, ConditionValue::List(l)) => l.iter().any(|v| v == fstr),
            (Operator::NotInList, ConditionValue::List(l)) => !l.iter().any(|v| v == fstr),
            (Operator::CidrMatch, ConditionValue::Str(cidr)) => cidr
                .parse::<ipnet::IpNet>()
                .ok()
                .is_some_and(|net| net.contains(&ctx.client_ip)),
            (Operator::Gt, ConditionValue::Number(n)) => fstr.parse::<i64>().ok().is_some_and(|v| v > *n),
            (Operator::Lt, ConditionValue::Number(n)) => fstr.parse::<i64>().ok().is_some_and(|v| v < *n),
            (Operator::Gte, ConditionValue::Number(n)) => fstr.parse::<i64>().ok().is_some_and(|v| v >= *n),
            (Operator::Lte, ConditionValue::Number(n)) => fstr.parse::<i64>().ok().is_some_and(|v| v <= *n),
            _ => false,
        }
    }

    #[allow(clippy::unused_self)]
    fn field_value(&self, ctx: &RequestCtx, field: &ConditionField) -> Option<String> {
        match field {
            ConditionField::Ip => Some(ctx.client_ip.to_string()),
            ConditionField::Path => Some(ctx.path.clone()),
            ConditionField::Query => Some(ctx.query.clone()),
            ConditionField::Method => Some(ctx.method.clone()),
            ConditionField::Host => Some(ctx.host.clone()),
            ConditionField::ContentLength => Some(ctx.content_length.to_string()),
            ConditionField::Body => Some(String::from_utf8_lossy(&ctx.body_preview).into_owned()),
            ConditionField::Cookie => ctx.headers.get("cookie").cloned(),
            ConditionField::UserAgent => ctx.headers.get("user-agent").cloned(),
            ConditionField::ContentType => ctx.headers.get("content-type").cloned(),
            ConditionField::Header(name) => ctx.headers.get(&name.to_lowercase()).cloned(),
            // ── GeoIP fields ────────────────────────────────────────────────
            ConditionField::GeoCountry => ctx.geo.as_ref().map(|g| g.country.clone()),
            ConditionField::GeoIso => ctx.geo.as_ref().map(|g| g.iso_code.clone()),
            ConditionField::GeoProvince => ctx.geo.as_ref().map(|g| g.province.clone()),
            ConditionField::GeoCity => ctx.geo.as_ref().map(|g| g.city.clone()),
            ConditionField::GeoIsp => ctx.geo.as_ref().map(|g| g.isp.clone()),
        }
    }
}

impl Default for CustomRulesEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper: deserialize a DB CustomRule row into an engine CustomRule ─────────

use waf_storage::models::CustomRule as DbCustomRule;

pub fn from_db_rule(row: &DbCustomRule) -> anyhow::Result<CustomRule> {
    let conditions: Vec<Condition> = serde_json::from_value(row.conditions.clone()).unwrap_or_default();

    Ok(CustomRule {
        id: row.id.to_string(),
        host_code: row.host_code.clone(),
        name: row.name.clone(),
        priority: row.priority,
        enabled: row.enabled,
        condition_op: ConditionOp::parse_str(&row.condition_op),
        conditions,
        action: RuleAction::parse_str(&row.action),
        action_status: u16::try_from(row.action_status).unwrap_or(403),
        action_msg: row.action_msg.clone(),
        script: row.script.clone(),
    })
}

// ── Recursive condition tree (storage-friendly; eval path wired in phase 04) ─

/// Nested AND/OR/Not tree of raw conditions.
///
/// Storage path is opt-in until phase 04: legacy flat `Vec<Condition>` rules
/// are auto-promoted to `And([Leaf,...])` (or `Or` per `condition_op`) by
/// [`compile_rule`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionNode {
    Leaf(Condition),
    And(Vec<Self>),
    Or(Vec<Self>),
    Not(Box<Self>),
}

// ── Compiled (in-memory only — not serializable) ──────────────────────────────

/// A rule with all heavy matchers (regex, CIDR, lookup sets) pre-compiled.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub meta: CustomRule,
    pub root: CompiledNode,
}

#[derive(Debug, Clone)]
pub enum CompiledNode {
    Leaf(CompiledCondition),
    And(Vec<Self>),
    Or(Vec<Self>),
    Not(Box<Self>),
}

#[derive(Debug, Clone)]
pub struct CompiledCondition {
    pub field: ConditionField,
    pub matcher: Matcher,
}

/// Operator + value fused into a state pre-compiled at rule-load time.
///
/// `Glob` (wildcard) is reserved for phase 02; `globset` is not yet a dep.
#[derive(Debug, Clone)]
pub enum Matcher {
    Eq(String),
    Ne(String),
    Contains(String),
    NotContains(String),
    StartsWith(String),
    EndsWith(String),
    Regex(Regex),
    InList(ahash::AHashSet<String>),
    NotInList(ahash::AHashSet<String>),
    Cidr(ipnet::IpNet),
    Gt(i64),
    Lt(i64),
    Gte(i64),
    Lte(i64),
}

/// Compile a raw rule into its eval-ready form.
///
/// Phase 01 only consumes the legacy flat `conditions` + `condition_op`; the
/// `match_tree` field is added in phase 04.
pub fn compile_rule(rule: &CustomRule) -> anyhow::Result<CompiledRule> {
    let leaves: Vec<CompiledNode> = rule
        .conditions
        .iter()
        .map(|c| compile_condition(c).map(CompiledNode::Leaf))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let root = match rule.condition_op {
        ConditionOp::And => CompiledNode::And(leaves),
        ConditionOp::Or => CompiledNode::Or(leaves),
    };

    Ok(CompiledRule {
        meta: rule.clone(),
        root,
    })
}

/// Compile a single condition; surfaces regex/CIDR errors so the caller can
/// decide whether to skip the rule.
fn compile_condition(cond: &Condition) -> anyhow::Result<CompiledCondition> {
    use ConditionValue as V;

    let matcher = match (&cond.operator, &cond.value) {
        (Operator::Eq, V::Str(s)) => Matcher::Eq(s.clone()),
        (Operator::Ne, V::Str(s)) => Matcher::Ne(s.clone()),
        (Operator::Contains, V::Str(s)) => Matcher::Contains(s.clone()),
        (Operator::NotContains, V::Str(s)) => Matcher::NotContains(s.clone()),
        (Operator::StartsWith, V::Str(s)) => Matcher::StartsWith(s.clone()),
        (Operator::EndsWith, V::Str(s)) => Matcher::EndsWith(s.clone()),
        (Operator::Regex, V::Str(s)) => {
            let re = Regex::new(s).with_context(|| format!("invalid regex: {s}"))?;
            Matcher::Regex(re)
        }
        (Operator::InList, V::List(l)) => Matcher::InList(l.iter().cloned().collect()),
        (Operator::NotInList, V::List(l)) => Matcher::NotInList(l.iter().cloned().collect()),
        (Operator::CidrMatch, V::Str(s)) => {
            let net = s
                .parse::<ipnet::IpNet>()
                .with_context(|| format!("invalid CIDR: {s}"))?;
            Matcher::Cidr(net)
        }
        (Operator::Gt, V::Number(n)) => Matcher::Gt(*n),
        (Operator::Lt, V::Number(n)) => Matcher::Lt(*n),
        (Operator::Gte, V::Number(n)) => Matcher::Gte(*n),
        (Operator::Lte, V::Number(n)) => Matcher::Lte(*n),
        (op, val) => {
            anyhow::bail!("unsupported operator/value combination: {op:?} / {val:?}");
        }
    };

    Ok(CompiledCondition {
        field: cond.field.clone(),
        matcher,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::Arc;
    use waf_common::HostConfig;

    fn make_ctx(path: &str, method: &str, ip: &str) -> RequestCtx {
        let host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            ..HostConfig::default()
        });
        RequestCtx {
            req_id: "test".into(),
            client_ip: ip.parse().unwrap(),
            client_port: 12345,
            method: method.into(),
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
        }
    }

    #[test]
    fn test_ip_cidr_match() {
        let engine = CustomRulesEngine::new();
        let rule = CustomRule {
            id: "r1".into(),
            host_code: "test".into(),
            name: "Block 10.0.0.0/8".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![Condition {
                field: ConditionField::Ip,
                operator: Operator::CidrMatch,
                value: ConditionValue::Str("10.0.0.0/8".into()),
            }],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
        };
        engine.add_rule(rule);

        let ctx = make_ctx("/", "GET", "10.0.1.5");
        assert!(engine.check(&ctx).is_some());

        let ctx2 = make_ctx("/", "GET", "192.168.1.1");
        assert!(engine.check(&ctx2).is_none());
    }

    #[test]
    fn test_path_starts_with() {
        let engine = CustomRulesEngine::new();
        let rule = CustomRule {
            id: "r2".into(),
            host_code: "test".into(),
            name: "Block admin".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![Condition {
                field: ConditionField::Path,
                operator: Operator::StartsWith,
                value: ConditionValue::Str("/admin".into()),
            }],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
        };
        engine.add_rule(rule);

        let ctx = make_ctx("/admin/users", "GET", "1.2.3.4");
        assert!(engine.check(&ctx).is_some());

        let ctx2 = make_ctx("/public", "GET", "1.2.3.4");
        assert!(engine.check(&ctx2).is_none());
    }

    #[test]
    fn test_rhai_script() {
        let engine = CustomRulesEngine::new();
        let rule = CustomRule {
            id: "r3".into(),
            host_code: "test".into(),
            name: "Rhai block DELETE on /api".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: Some(r#"method == "DELETE" && path.starts_with("/api")"#.into()),
        };
        engine.add_rule(rule);

        let ctx = make_ctx("/api/users/1", "DELETE", "1.2.3.4");
        assert!(engine.check(&ctx).is_some());

        let ctx2 = make_ctx("/api/users/1", "GET", "1.2.3.4");
        assert!(engine.check(&ctx2).is_none());
    }

    // ── compile_rule / compile_condition ──────────────────────────────────────

    fn mk_rule(op: ConditionOp, conditions: Vec<Condition>) -> CustomRule {
        CustomRule {
            id: "c1".into(),
            host_code: "test".into(),
            name: "compile".into(),
            priority: 1,
            enabled: true,
            condition_op: op,
            conditions,
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
        }
    }

    #[test]
    fn compile_flat_and_wraps_in_and_node() {
        let rule = mk_rule(
            ConditionOp::And,
            vec![
                Condition {
                    field: ConditionField::Path,
                    operator: Operator::StartsWith,
                    value: ConditionValue::Str("/admin".into()),
                },
                Condition {
                    field: ConditionField::Method,
                    operator: Operator::Eq,
                    value: ConditionValue::Str("POST".into()),
                },
            ],
        );

        let compiled = compile_rule(&rule).expect("compile ok");
        match compiled.root {
            CompiledNode::And(ref leaves) => {
                assert_eq!(leaves.len(), 2);
                assert!(matches!(leaves.first(), Some(CompiledNode::Leaf(_))));
            }
            _ => panic!("expected And root"),
        }
    }

    #[test]
    fn compile_flat_or_wraps_in_or_node() {
        let rule = mk_rule(
            ConditionOp::Or,
            vec![Condition {
                field: ConditionField::Ip,
                operator: Operator::CidrMatch,
                value: ConditionValue::Str("10.0.0.0/8".into()),
            }],
        );

        let compiled = compile_rule(&rule).expect("compile ok");
        assert!(matches!(compiled.root, CompiledNode::Or(ref l) if l.len() == 1));
    }

    #[test]
    fn compile_bad_regex_returns_err() {
        let rule = mk_rule(
            ConditionOp::And,
            vec![Condition {
                field: ConditionField::Path,
                operator: Operator::Regex,
                value: ConditionValue::Str("(unclosed".into()),
            }],
        );
        assert!(compile_rule(&rule).is_err());
    }

    #[test]
    fn compile_bad_cidr_returns_err() {
        let rule = mk_rule(
            ConditionOp::And,
            vec![Condition {
                field: ConditionField::Ip,
                operator: Operator::CidrMatch,
                value: ConditionValue::Str("not-a-cidr".into()),
            }],
        );
        assert!(compile_rule(&rule).is_err());
    }

    #[test]
    fn compile_mismatched_operator_value_returns_err() {
        // Eq expects Str, not Number → must error rather than silently match.
        let rule = mk_rule(
            ConditionOp::And,
            vec![Condition {
                field: ConditionField::ContentLength,
                operator: Operator::Eq,
                value: ConditionValue::Number(42),
            }],
        );
        assert!(compile_rule(&rule).is_err());
    }

    #[test]
    fn compile_in_list_builds_hashset() {
        let rule = mk_rule(
            ConditionOp::And,
            vec![Condition {
                field: ConditionField::Method,
                operator: Operator::InList,
                value: ConditionValue::List(vec!["GET".into(), "POST".into(), "GET".into()]),
            }],
        );
        let compiled = compile_rule(&rule).expect("compile ok");
        match &compiled.root {
            CompiledNode::And(leaves) => match leaves.first() {
                Some(CompiledNode::Leaf(c)) => match &c.matcher {
                    Matcher::InList(set) => {
                        assert_eq!(set.len(), 2); // dedup
                        assert!(set.contains("GET"));
                    }
                    _ => panic!("expected InList matcher"),
                },
                _ => panic!("expected leaf"),
            },
            _ => panic!("expected And root"),
        }
    }
}
