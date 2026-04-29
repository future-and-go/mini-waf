//! Custom WAF Rules Engine
//!
//! Evaluates user-defined rules stored in `PostgreSQL` against incoming requests.
//! Each rule has:
//!   - Conditions (AND/OR) matching fields of the request
//!   - An action (Block / Allow / Log / Challenge)
//!   - An optional Rhai script for complex evaluation logic

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Context as _;
use dashmap::DashMap;
use globset::{Glob, GlobBuilder, GlobMatcher};
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
    Wildcard,
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
    rules: DashMap<String, Vec<RuleEntry>>,
    rhai: Arc<rhai::Engine>,
}

/// Internal storage cell: keeps the raw rule (needed for eval/script + meta) and
/// an optional pre-compiled tree. `compiled` is `None` when compile fails — in
/// that case we skip the rule on eval and rely on a load-time warn log.
#[derive(Debug, Clone)]
struct RuleEntry {
    raw: CustomRule,
    compiled: Option<CompiledRule>,
}

impl RuleEntry {
    fn from_rule(rule: CustomRule) -> Self {
        let compiled = match compile_rule(&rule) {
            Ok(c) => Some(c),
            Err(e) => {
                warn!(rule_id = %rule.id, error = %e, "Failed to compile rule; skipping");
                None
            }
        };
        Self { raw: rule, compiled }
    }
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
    pub fn load_host(&self, host_code: &str, rules: Vec<CustomRule>) {
        let mut entries: Vec<RuleEntry> = rules
            .into_iter()
            .filter(|r| r.enabled)
            .map(RuleEntry::from_rule)
            .collect();
        entries.sort_by_key(|e| e.raw.priority);
        self.rules.insert(host_code.to_string(), entries);
    }

    /// Append a single rule (hot-add).
    pub fn add_rule(&self, rule: CustomRule) {
        let host_code = rule.host_code.clone();
        let entry = RuleEntry::from_rule(rule);
        let mut bucket = self.rules.entry(host_code).or_default();
        bucket.push(entry);
        bucket.sort_by_key(|e| e.raw.priority);
    }

    /// Remove a rule by ID.
    pub fn remove_rule(&self, host_code: &str, rule_id: &str) {
        if let Some(mut rules) = self.rules.get_mut(host_code) {
            rules.retain(|e| e.raw.id != rule_id);
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

    fn eval_list(&self, ctx: &RequestCtx, rules: &[RuleEntry]) -> Option<DetectionResult> {
        for entry in rules {
            let rule = &entry.raw;
            if !rule.enabled {
                continue;
            }

            // Eval order:
            // 1. Rhai script overrides everything (legacy escape hatch).
            // 2. Compiled tree path (preferred) — built once at insert time.
            // 3. Legacy flat eval — only when compile failed and no script set.
            let matched = rule.script.as_ref().map_or_else(
                || {
                    entry.compiled.as_ref().map_or_else(
                        || self.eval_conditions(ctx, &rule.conditions, &rule.condition_op),
                        |compiled| eval_compiled_node(ctx, &compiled.root),
                    )
                },
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
        field_value(ctx, field)
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
    Glob(GlobMatcher),
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
        (Operator::Wildcard, V::Str(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                anyhow::bail!("empty wildcard pattern");
            }
            // Bare `**` matches everything across separators — accidental footgun.
            if trimmed == "**" {
                anyhow::bail!("bare '**' wildcard not allowed (matches everything)");
            }
            // `literal_separator(true)` makes `*` segment-bounded (won't cross `/`),
            // while `**` remains the explicit cross-segment wildcard.
            let glob: Glob = GlobBuilder::new(trimmed)
                .literal_separator(true)
                .build()
                .with_context(|| format!("invalid wildcard pattern: {s}"))?;
            Matcher::Glob(glob.compile_matcher())
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

impl Matcher {
    /// Single dispatch: each variant evaluates its pre-compiled state against
    /// the resolved field string (or the request IP for CIDR).
    pub fn matches(&self, fstr: &str, ctx_ip: IpAddr) -> bool {
        match self {
            Self::Eq(s) => fstr.eq_ignore_ascii_case(s),
            Self::Ne(s) => !fstr.eq_ignore_ascii_case(s),
            Self::Contains(s) => fstr.contains(s.as_str()),
            Self::NotContains(s) => !fstr.contains(s.as_str()),
            Self::StartsWith(s) => fstr.starts_with(s.as_str()),
            Self::EndsWith(s) => fstr.ends_with(s.as_str()),
            Self::Regex(re) => re.is_match(fstr),
            Self::Glob(g) => g.is_match(fstr),
            Self::InList(set) => set.contains(fstr),
            Self::NotInList(set) => !set.contains(fstr),
            Self::Cidr(net) => net.contains(&ctx_ip),
            Self::Gt(n) => fstr.parse::<i64>().is_ok_and(|v| v > *n),
            Self::Lt(n) => fstr.parse::<i64>().is_ok_and(|v| v < *n),
            Self::Gte(n) => fstr.parse::<i64>().is_ok_and(|v| v >= *n),
            Self::Lte(n) => fstr.parse::<i64>().is_ok_and(|v| v <= *n),
        }
    }
}

/// Recursive evaluator over a `CompiledNode` tree.
fn eval_compiled_node(ctx: &RequestCtx, node: &CompiledNode) -> bool {
    match node {
        CompiledNode::Leaf(c) => {
            let fval = field_value(ctx, &c.field);
            c.matcher.matches(fval.as_deref().unwrap_or(""), ctx.client_ip)
        }
        CompiledNode::And(v) => v.iter().all(|n| eval_compiled_node(ctx, n)),
        CompiledNode::Or(v) => v.iter().any(|n| eval_compiled_node(ctx, n)),
        CompiledNode::Not(b) => !eval_compiled_node(ctx, b),
    }
}

/// Standalone field resolver — mirrors `CustomRulesEngine::field_value`.
/// Free function so `eval_compiled_node` need not borrow the engine.
fn field_value(ctx: &RequestCtx, field: &ConditionField) -> Option<String> {
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
        ConditionField::GeoCountry => ctx.geo.as_ref().map(|g| g.country.clone()),
        ConditionField::GeoIso => ctx.geo.as_ref().map(|g| g.iso_code.clone()),
        ConditionField::GeoProvince => ctx.geo.as_ref().map(|g| g.province.clone()),
        ConditionField::GeoCity => ctx.geo.as_ref().map(|g| g.city.clone()),
        ConditionField::GeoIsp => ctx.geo.as_ref().map(|g| g.isp.clone()),
    }
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

    // ── Phase 02: wildcard + matcher dispatch ────────────────────────────────

    #[test]
    fn wildcard_glob_matches_segment() {
        // AC-3: `/api/*/admin` matches `/api/v1/admin`, misses `/api/admin`.
        let engine = CustomRulesEngine::new();
        engine.add_rule(CustomRule {
            id: "w1".into(),
            host_code: "test".into(),
            name: "wildcard".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![Condition {
                field: ConditionField::Path,
                operator: Operator::Wildcard,
                value: ConditionValue::Str("/api/*/admin".into()),
            }],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
        });

        assert!(engine.check(&make_ctx("/api/v1/admin", "GET", "1.2.3.4")).is_some());
        assert!(engine.check(&make_ctx("/api/admin", "GET", "1.2.3.4")).is_none());
    }

    #[test]
    fn wildcard_does_not_cross_slash() {
        // `*` is segment-bounded; only `**` crosses `/`.
        let rule = mk_rule(
            ConditionOp::And,
            vec![Condition {
                field: ConditionField::Path,
                operator: Operator::Wildcard,
                value: ConditionValue::Str("/api/*/admin".into()),
            }],
        );
        let compiled = compile_rule(&rule).expect("compile ok");
        let CompiledNode::And(leaves) = &compiled.root else {
            panic!("expected And");
        };
        let CompiledNode::Leaf(c) = leaves.first().expect("one leaf") else {
            panic!("expected leaf");
        };
        let Matcher::Glob(g) = &c.matcher else {
            panic!("expected Glob matcher");
        };
        assert!(g.is_match("/api/v1/admin"));
        assert!(!g.is_match("/api/v1/v2/admin"));
    }

    #[test]
    fn wildcard_compile_failure_returns_err() {
        // Empty pattern.
        let rule = mk_rule(
            ConditionOp::And,
            vec![Condition {
                field: ConditionField::Path,
                operator: Operator::Wildcard,
                value: ConditionValue::Str(String::new()),
            }],
        );
        assert!(compile_rule(&rule).is_err());

        // Bare `**` rejected.
        let rule2 = mk_rule(
            ConditionOp::And,
            vec![Condition {
                field: ConditionField::Path,
                operator: Operator::Wildcard,
                value: ConditionValue::Str("**".into()),
            }],
        );
        assert!(compile_rule(&rule2).is_err());

        // Mismatched value type (List instead of Str).
        let rule3 = mk_rule(
            ConditionOp::And,
            vec![Condition {
                field: ConditionField::Path,
                operator: Operator::Wildcard,
                value: ConditionValue::List(vec!["a".into()]),
            }],
        );
        assert!(compile_rule(&rule3).is_err());
    }

    #[test]
    fn matcher_dispatch_table() {
        let ip: IpAddr = "10.0.0.5".parse().unwrap();

        assert!(Matcher::Eq("GET".into()).matches("get", ip));
        assert!(!Matcher::Ne("GET".into()).matches("GET", ip));
        assert!(Matcher::Contains("foo".into()).matches("xfoox", ip));
        assert!(Matcher::NotContains("foo".into()).matches("bar", ip));
        assert!(Matcher::StartsWith("/api".into()).matches("/api/v1", ip));
        assert!(Matcher::EndsWith(".php".into()).matches("/x.php", ip));
        assert!(Matcher::Regex(Regex::new("^a.c$").unwrap()).matches("abc", ip));

        let glob = GlobBuilder::new("/api/*/x")
            .literal_separator(true)
            .build()
            .unwrap()
            .compile_matcher();
        assert!(Matcher::Glob(glob).matches("/api/v1/x", ip));

        let mut set = ahash::AHashSet::new();
        set.insert("GET".to_string());
        assert!(Matcher::InList(set.clone()).matches("GET", ip));
        assert!(!Matcher::NotInList(set).matches("GET", ip));

        let net: ipnet::IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(Matcher::Cidr(net).matches("", ip));

        assert!(Matcher::Gt(10).matches("11", ip));
        assert!(Matcher::Lt(10).matches("9", ip));
        assert!(Matcher::Gte(10).matches("10", ip));
        assert!(Matcher::Lte(10).matches("10", ip));
    }

    #[test]
    fn compiled_path_evaluates_via_tree() {
        // Sanity: insertion path compiles, eval_list uses compiled tree, and
        // legacy fallback still works for unsupported combos (none here).
        let engine = CustomRulesEngine::new();
        engine.add_rule(CustomRule {
            id: "p1".into(),
            host_code: "test".into(),
            name: "compiled path".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![
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
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
        });

        assert!(engine.check(&make_ctx("/admin/x", "POST", "1.2.3.4")).is_some());
        assert!(engine.check(&make_ctx("/admin/x", "GET", "1.2.3.4")).is_none());
        assert!(engine.check(&make_ctx("/public", "POST", "1.2.3.4")).is_none());
    }
}
