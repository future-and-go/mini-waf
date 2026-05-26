//! Custom WAF Rules Engine
//!
//! Evaluates user-defined rules stored in `PostgreSQL` against incoming requests.
//! Each rule has:
//!   - Conditions (AND/OR) matching fields of the request
//!   - An action (Block / Allow / Log / Challenge)
//!   - An optional Rhai script for complex evaluation logic

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use anyhow::Context as _;
use dashmap::DashMap;
use globset::{Glob, GlobBuilder, GlobMatcher};
use parking_lot::Mutex;
use regex::Regex;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use super::load_status::{self, RuleLoadFailure};

use waf_common::{DetectionResult, Phase, RequestCtx};

// ── Condition field ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionField {
    Ip,
    Path,
    Query,
    Method,
    Body,
    /// Cookie field. `None` returns the whole `Cookie:` header (legacy /
    /// back-compat); `Some(name)` returns the value of one cookie by name
    /// from the parsed `RequestCtx.cookies` map. Names are case-sensitive.
    Cookie(Option<String>),
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
    /// HTTP response body — evaluated at response time, not request time.
    /// Rules targeting this field are partitioned into a separate evaluation
    /// phase so they don't accidentally match against the request body.
    ResponseBody,
    /// Multi-field scan: path → query → body → non-routing headers.
    /// Used by `pm_from_file`, `contains_any`, `detect_sqli`, `detect_xss`
    /// when YAML sets `pattern_field: all`.
    All,
}

// Custom Deserialize: accepts both legacy bare strings (`"cookie"`,
// `"path"`, …) and newtype map forms (`{cookie: "session"}`,
// `{header: "x-foo"}`). Legacy `"cookie"` deserializes to `Cookie(None)`
// for back-compat with existing DB rules.
impl<'de> Deserialize<'de> for ConditionField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FieldVisitor;

        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = ConditionField;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a ConditionField (string tag or single-key map)")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                match v {
                    "ip" => Ok(ConditionField::Ip),
                    "path" => Ok(ConditionField::Path),
                    "query" => Ok(ConditionField::Query),
                    "method" => Ok(ConditionField::Method),
                    "body" => Ok(ConditionField::Body),
                    "cookie" => Ok(ConditionField::Cookie(None)),
                    "user_agent" => Ok(ConditionField::UserAgent),
                    "content_type" => Ok(ConditionField::ContentType),
                    "content_length" => Ok(ConditionField::ContentLength),
                    "host" => Ok(ConditionField::Host),
                    "geo_country" => Ok(ConditionField::GeoCountry),
                    "geo_iso" => Ok(ConditionField::GeoIso),
                    "geo_province" => Ok(ConditionField::GeoProvince),
                    "geo_city" => Ok(ConditionField::GeoCity),
                    "geo_isp" => Ok(ConditionField::GeoIsp),
                    "response_body" => Ok(ConditionField::ResponseBody),
                    "all" => Ok(ConditionField::All),
                    other => Err(E::unknown_variant(
                        other,
                        &[
                            "ip",
                            "path",
                            "query",
                            "method",
                            "body",
                            "cookie",
                            "user_agent",
                            "content_type",
                            "content_length",
                            "host",
                            "header",
                            "geo_country",
                            "geo_iso",
                            "geo_province",
                            "geo_city",
                            "geo_isp",
                            "response_body",
                            "all",
                        ],
                    )),
                }
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                self.visit_str(&v)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let key: String = map
                    .next_key()?
                    .ok_or_else(|| de::Error::custom("expected single-key map"))?;
                let result = match key.as_str() {
                    "header" => {
                        let name: String = map.next_value()?;
                        ConditionField::Header(name)
                    }
                    "cookie" => {
                        let name: Option<String> = map.next_value()?;
                        ConditionField::Cookie(name)
                    }
                    other => return Err(de::Error::unknown_variant(other, &["header", "cookie"])),
                };
                if map.next_key::<String>()?.is_some() {
                    return Err(de::Error::custom("expected exactly one key"));
                }
                Ok(result)
            }
        }

        deserializer.deserialize_any(FieldVisitor)
    }
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
    // Operators evaluated by specialised check modules, not the condition matcher.
    // Stored so YAML round-trips losslessly.
    PmFromFile,
    DetectSqli,
    DetectXss,
    ContainsAny,
}

// ── Condition value ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionValue {
    Str(String),
    List(Vec<String>),
    Number(i64),
    /// Pre-compiled Aho-Corasick automaton for `pm_from_file` / `contains_any`.
    /// Constructed only at load time by the YAML parser — never produced by
    /// serde round-trip, so the variant carries `#[serde(skip)]`.
    #[serde(skip)]
    AhoCorasick(Arc<AhoCorasick>),
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

// ── Rule action (defined in waf-common, re-exported for downstream consumers) ─
pub use waf_common::RuleAction;

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
    /// Optional nested AND/OR/Not condition tree. When `Some`, takes precedence
    /// over the flat `conditions` + `condition_op` legacy pair at compile time.
    pub match_tree: Option<ConditionNode>,
    /// FR-025: Risk score delta when this rule matches.
    pub risk_delta: Option<i16>,
    /// FR-025: Override action for risk scoring ("block" forces immediate block).
    pub risk_action: Option<String>,
    // ── Registry/OWASP compatibility fields ──
    /// Pre-compiled regex pattern evaluated against `pattern_field`.
    pub pattern: Option<Regex>,
    /// Which request field the pattern targets (e.g. "all", "path", "query").
    pub pattern_field: String,
    /// Rule category (sqli, xss, ssti, etc.).
    pub category: Option<String>,
    /// Severity level (critical, high, medium, low).
    pub severity: Option<String>,
    /// OWASP CRS paranoia level (1-4).
    pub paranoia: Option<u8>,
    /// Tags for filtering/grouping.
    pub tags: Vec<String>,
    /// Arbitrary metadata key-value pairs.
    pub metadata: HashMap<String, String>,
    /// External reference URL.
    pub reference: Option<String>,
}

// ── FR-025 Rule Verdict ───────────────────────────────────────────────────────

/// A single risk delta contribution from a matched rule.
#[derive(Debug, Clone)]
pub struct RiskDelta {
    pub rule_id: String,
    pub delta: i16,
}

/// Result of rule engine evaluation with risk scoring support.
///
/// Contains the detection result (if any rules matched) plus accumulated
/// risk deltas and override flags for the scorer.
#[derive(Debug, Clone, Default)]
pub struct RuleVerdict {
    /// Detection result from the first blocking rule, if any.
    pub result: Option<DetectionResult>,
    /// Risk deltas from ALL matched rules (not just the first).
    pub risk_deltas: Vec<RiskDelta>,
    /// True if any matched rule has `risk_action: "block"`.
    pub override_block: bool,
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
    load_report: Mutex<load_status::RuleLoadReport>,
}

/// Where a rule was sourced from. Tracked per `RuleEntry` so the engine
/// can selectively wipe file-loaded rules on hot-reload without touching
/// DB-loaded rules in the same priority bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleSource {
    Db,
    File,
}

/// Internal storage cell: keeps the raw rule (needed for eval/script + meta) and
/// an optional pre-compiled tree. `compiled` is `None` when compile fails — in
/// that case we skip the rule on eval and rely on a load-time warn log.
#[derive(Debug, Clone)]
struct RuleEntry {
    raw: CustomRule,
    compiled: Option<CompiledRule>,
    source: RuleSource,
}

impl RuleEntry {
    fn from_rule(rule: CustomRule) -> Option<Self> {
        Self::from_rule_with_source(rule, RuleSource::Db)
    }

    fn from_rule_with_source(rule: CustomRule, source: RuleSource) -> Option<Self> {
        let compiled = match compile_rule(&rule) {
            Ok(c) => c,
            Err(e) => {
                error!(rule_id = %rule.id, error = %e, "Rule rejected: compile failed");
                return None;
            }
        };
        Some(Self {
            raw: rule,
            compiled,
            source,
        })
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
            load_report: Mutex::new(load_status::RuleLoadReport::default()),
        }
    }

    /// Return a snapshot of the current load report (failed rules, etc.).
    pub fn load_report(&self) -> load_status::RuleLoadReport {
        self.load_report.lock().clone()
    }

    /// Emit a structured log summary of the last rule load cycle.
    pub fn emit_load_summary(&self) {
        let report = self.load_report.lock();
        let loaded = report.loaded.len();
        let failed = report.failed.len();
        tracing::info!(loaded, failed, "rule_load_summary");
        for f in &report.failed {
            tracing::error!(
                rule_id = %f.rule_id,
                file = %f.file.display(),
                reason = %f.reason,
                "rule_load_failed"
            );
        }
    }

    /// Emit retro-audit log counting PatternSet/PatternList matcher instances.
    pub fn emit_retro_audit(&self) {
        let mut pm_count: usize = 0;
        let mut ca_count: usize = 0;
        for bucket in &self.rules {
            for entry in bucket.value() {
                if let Some(compiled) = &entry.compiled {
                    count_pattern_matchers(&compiled.root, &mut pm_count, &mut ca_count);
                }
            }
        }
        if pm_count > 0 || ca_count > 0 {
            tracing::warn!(
                pm_from_file_rules = pm_count,
                contains_any_rules = ca_count,
                "retro_audit: these rule types were inert prior to fix-260524-pm-matcher; coverage now active"
            );
        }
    }

    /// Replace all rules for a host (sorted by priority).
    pub fn load_host(&self, host_code: &str, rules: Vec<CustomRule>) {
        let mut entries: Vec<RuleEntry> = rules
            .into_iter()
            .filter(|r| r.enabled)
            .filter_map(RuleEntry::from_rule)
            .collect();
        entries.sort_by_key(|e| e.raw.priority);
        self.rules.insert(host_code.to_string(), entries);
    }

    /// Append a single rule (hot-add). Tagged as `RuleSource::Db`.
    pub fn add_rule(&self, rule: CustomRule) {
        self.insert_rule(rule, RuleSource::Db);
    }

    /// Append a single file-sourced rule. Tagged as `RuleSource::File` so
    /// `clear_file_rules` can wipe it on hot-reload.
    ///
    /// Tracks compile failures in the load report for observability.
    pub fn add_file_rule(&self, rule: CustomRule) {
        self.insert_rule_tracked(rule, RuleSource::File);
    }

    fn insert_rule(&self, rule: CustomRule, source: RuleSource) {
        let host_code = rule.host_code.clone();
        let entry = match RuleEntry::from_rule_with_source(rule, source) {
            Some(e) => e,
            None => return,
        };
        let mut bucket = self.rules.entry(host_code).or_default();
        bucket.push(entry);
        bucket.sort_by_key(|e| e.raw.priority);
    }

    fn insert_rule_tracked(&self, rule: CustomRule, source: RuleSource) {
        let rule_id = rule.id.clone();
        let host_code = rule.host_code.clone();
        let compile_result = compile_rule(&rule);
        let entry = match compile_result {
            Ok(compiled) => {
                self.load_report
                    .lock()
                    .record(load_status::RuleLoadStatus::Loaded { rule_id });
                RuleEntry {
                    raw: rule,
                    compiled,
                    source,
                }
            }
            Err(e) => {
                let reason = load_status::classify_error(&e);
                error!(
                    rule_id = %rule_id,
                    reason = reason,
                    error = %e,
                    "rule_load_failed"
                );
                self.load_report
                    .lock()
                    .record(load_status::RuleLoadStatus::Failed(RuleLoadFailure {
                        rule_id: rule_id.clone(),
                        file: std::path::PathBuf::from(&rule_id),
                        reason: reason.to_string(),
                    }));
                return;
            }
        };
        let mut bucket = self.rules.entry(host_code).or_default();
        bucket.push(entry);
        bucket.sort_by_key(|e| e.raw.priority);
    }

    /// Drop every file-sourced rule across all hosts.
    ///
    /// Called by the hot-reload watcher before re-loading from disk so that
    /// edits/removals don't leave stale entries behind. DB-sourced rules
    /// in the same buckets are preserved.
    pub fn clear_file_rules(&self) {
        for mut bucket in self.rules.iter_mut() {
            bucket.retain(|e| e.source != RuleSource::File);
        }
        *self.load_report.lock() = load_status::RuleLoadReport::default();
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

    /// Check whether any loaded rules target `ConditionField::ResponseBody`.
    pub fn has_response_rules(&self) -> bool {
        self.rules
            .iter()
            .any(|bucket| bucket.value().iter().any(|e| rule_targets_response_body(&e.raw)))
    }

    /// Evaluate response-body rules against the given response body text.
    ///
    /// Only rules whose `pattern_field` is `"response_body"` and that carry
    /// a pre-compiled `pattern` regex are tested. Rules using `pm_from_file`,
    /// `detect_sqli`, or condition trees for `response_body` are not yet
    /// supported — those require Phase 2 wiring.
    ///
    /// Returns the first match as a `DetectionResult` with `Phase::CustomRule`.
    pub fn check_response_body(&self, host_code: &str, response_body: &str) -> Option<DetectionResult> {
        let check_bucket = |entries: &[RuleEntry]| -> Option<DetectionResult> {
            for entry in entries {
                let rule = &entry.raw;
                if !rule.enabled || !rule_targets_response_body(rule) {
                    continue;
                }
                // Response bodies are not URL-encoded, so match directly
                // (no test_with_decode — that is for request-path evasion).
                if rule.pattern.as_ref().is_some_and(|p| p.is_match(response_body)) {
                    return Some(DetectionResult {
                        rule_id: Some(rule.id.clone()),
                        rule_name: rule.name.clone(),
                        phase: Phase::CustomRule,
                        detail: format!("Response body rule '{}' matched", rule.name),
                        rule_action: Some(rule.action),
                        action_status: Some(rule.action_status),
                    });
                }
            }
            None
        };

        if let Some(rules) = self.rules.get(host_code)
            && let Some(result) = check_bucket(&rules)
        {
            return Some(result);
        }
        if let Some(rules) = self.rules.get("*")
            && let Some(result) = check_bucket(&rules)
        {
            return Some(result);
        }
        None
    }

    /// Evaluate all rules against the request context.
    ///
    /// Returns the first matching `DetectionResult`, or `None`.
    /// For FR-025 risk scoring, use [`check_with_verdict`] instead.
    pub fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        self.check_with_verdict(ctx).result
    }

    /// FR-025: Evaluate all rules and return a full `RuleVerdict`.
    ///
    /// Collects ALL matching rules' risk deltas and override flags, not just
    /// the first blocking rule. The `result` field contains the first blocking
    /// detection (for action determination), while `risk_deltas` contains all
    /// matched rules' contributions for scoring.
    pub fn check_with_verdict(&self, ctx: &RequestCtx) -> RuleVerdict {
        let host_code = &ctx.host_config.code;
        let mut verdict = RuleVerdict::default();

        // Host-specific rules first
        if let Some(rules) = self.rules.get(host_code) {
            self.eval_list_with_verdict(ctx, &rules, &mut verdict);
        }

        // Global rules
        if let Some(rules) = self.rules.get("*") {
            self.eval_list_with_verdict(ctx, &rules, &mut verdict);
        }

        verdict
    }

    /// Evaluate only rules with `paranoia <= max_paranoia`, returning results
    /// tagged with `Phase::Owasp` instead of `Phase::CustomRule`.
    ///
    /// Used by `OWASPCheck` to run OWASP CRS rules through the unified engine
    /// while preserving paranoia-level filtering and the OWASP phase tag.
    #[allow(clippy::significant_drop_tightening)]
    pub fn check_owasp(&self, ctx: &RequestCtx, max_paranoia: u8) -> Option<DetectionResult> {
        let rules = self.rules.get("*")?;
        for entry in rules.iter() {
            let rule = &entry.raw;
            if !rule.enabled {
                continue;
            }
            if rule.paranoia.unwrap_or(1) > max_paranoia {
                continue;
            }

            let matched = self.eval_single_rule(ctx, entry);
            if matched {
                return Some(DetectionResult {
                    rule_id: Some(rule.id.clone()),
                    rule_name: rule.name.clone(),
                    phase: Phase::Owasp,
                    detail: format!("OWASP rule {} triggered ({})", rule.id, rule.name),
                    rule_action: Some(RuleAction::Block),
                    action_status: Some(403),
                });
            }
        }
        None
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Evaluate a list of rules, accumulating risk deltas into the verdict.
    ///
    /// Eval order (updated for pattern support):
    /// 1. Rhai script (legacy escape hatch)
    /// 2. Compiled `match_tree` (preferred)
    /// 3. Legacy flat conditions
    /// 4. Pattern + field (fallback when no `conditions`/`match_tree`)
    fn eval_list_with_verdict(&self, ctx: &RequestCtx, rules: &[RuleEntry], verdict: &mut RuleVerdict) {
        for entry in rules {
            let rule = &entry.raw;
            if !rule.enabled {
                continue;
            }

            let matched = self.eval_single_rule(ctx, entry);

            if matched {
                let _span = tracing::info_span!(
                    "rule_fire",
                    rule_id = %rule.id,
                    host_code = %rule.host_code,
                )
                .entered();

                // Collect risk delta if present
                if let Some(delta) = rule.risk_delta {
                    verdict.risk_deltas.push(RiskDelta {
                        rule_id: rule.id.clone(),
                        delta,
                    });
                }

                // Check for override_block
                if rule.risk_action.as_deref() == Some("block") {
                    verdict.override_block = true;
                }

                // Set the first blocking detection result
                if verdict.result.is_none() {
                    verdict.result = Some(DetectionResult {
                        rule_id: Some(rule.id.clone()),
                        rule_name: rule.name.clone(),
                        phase: Phase::CustomRule,
                        detail: format!("Custom rule '{}' matched", rule.name),
                        rule_action: Some(rule.action),
                        action_status: Some(rule.action_status),
                    });
                }
            }
        }
    }

    /// Evaluate a single rule entry against the request context.
    fn eval_single_rule(&self, ctx: &RequestCtx, entry: &RuleEntry) -> bool {
        let rule = &entry.raw;

        // Response-body rules are evaluated in the response phase only.
        if rule_targets_response_body(rule) {
            return false;
        }

        rule.script.as_ref().map_or_else(
            || {
                entry.compiled.as_ref().map_or_else(
                    || {
                        if !rule.conditions.is_empty() {
                            self.eval_conditions(ctx, &rule.conditions, &rule.condition_op)
                        } else if let Some(ref pattern) = rule.pattern {
                            pattern_matches_request(pattern, &rule.pattern_field, ctx)
                        } else {
                            false
                        }
                    },
                    |compiled| eval_compiled_node(ctx, &compiled.root),
                )
            },
            |script| self.eval_script(ctx, script),
        )
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
        scope.push("cookie", ctx.headers.get("cookie").cloned().unwrap_or_default());

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
            (Operator::Regex, _) => {
                error!("BUG: regex condition reached uncompiled eval_one");
                false
            }
            (Operator::InList, ConditionValue::List(l)) => l.iter().any(|v| v == fstr),
            (Operator::NotInList, ConditionValue::List(l)) => !l.iter().any(|v| v == fstr),
            (Operator::CidrMatch, _) => {
                error!("BUG: cidr condition reached uncompiled eval_one");
                false
            }
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
    // The `conditions` column is dual-shape:
    //   - legacy: a JSON array of `Condition` objects.
    //   - new:    a JSON object `{"match_tree": <ConditionNode>}`.
    // Detect by presence of the `match_tree` key on a top-level object.
    let (conditions, match_tree) = match &row.conditions {
        serde_json::Value::Object(map) if map.contains_key("match_tree") => {
            let tree: ConditionNode =
                serde_json::from_value(map.get("match_tree").cloned().unwrap_or(serde_json::Value::Null))
                    .context("parse match_tree")?;
            (Vec::new(), Some(tree))
        }
        _ => {
            let conds: Vec<Condition> = serde_json::from_value(row.conditions.clone()).unwrap_or_default();
            (conds, None)
        }
    };

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
        match_tree,
        risk_delta: row.risk_delta,
        risk_action: row.risk_action.clone(),
        pattern: None,
        pattern_field: "all".to_string(),
        category: None,
        severity: None,
        paranoia: None,
        tags: Vec::new(),
        metadata: HashMap::new(),
        reference: None,
    })
}

// ── Recursive condition tree ─────────────────────────────────────────────────

/// Nested AND/OR/Not tree of raw conditions.
///
/// Wire format uses key-presence disambiguation:
/// - `{ "and": [...] }` → `And` branch
/// - `{ "or":  [...] }` → `Or` branch
/// - `{ "not": {...} }` → `Not` branch
/// - bare `{ "field": ..., "operator": ..., "value": ... }` → `Leaf`
///
/// Legacy flat `Vec<Condition>` rules are auto-promoted to `And([Leaf,...])`
/// (or `Or` per `condition_op`) by [`compile_rule`] when `match_tree` is `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionNode {
    And(AndBranch),
    Or(OrBranch),
    Not(NotBranch),
    Leaf(Condition),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndBranch {
    pub and: Vec<ConditionNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrBranch {
    pub or: Vec<ConditionNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotBranch {
    pub not: Box<ConditionNode>,
}

/// Maximum allowed depth of a `ConditionNode` tree. Guards against
/// adversarial deep-nested rules causing stack overflow at compile/eval time.
pub const MAX_TREE_DEPTH: usize = 16;

/// Maximum total leaf count per tree — defensive cap against blowup.
pub const MAX_TREE_LEAVES: usize = 256;

/// Validate a tree's depth and leaf count.
///
/// Returns `Err` if depth > [`MAX_TREE_DEPTH`] or leaves > [`MAX_TREE_LEAVES`].
pub fn validate_tree(node: &ConditionNode) -> anyhow::Result<()> {
    fn walk(n: &ConditionNode, depth: usize, leaves: &mut usize) -> anyhow::Result<()> {
        if depth > MAX_TREE_DEPTH {
            anyhow::bail!("condition tree exceeds max depth {MAX_TREE_DEPTH}");
        }
        match n {
            ConditionNode::Leaf(_) => {
                *leaves += 1;
                if *leaves > MAX_TREE_LEAVES {
                    anyhow::bail!("condition tree exceeds max leaves {MAX_TREE_LEAVES}");
                }
                Ok(())
            }
            ConditionNode::And(b) => b.and.iter().try_for_each(|c| walk(c, depth + 1, leaves)),
            ConditionNode::Or(b) => b.or.iter().try_for_each(|c| walk(c, depth + 1, leaves)),
            ConditionNode::Not(b) => walk(&b.not, depth + 1, leaves),
        }
    }
    let mut leaves = 0usize;
    walk(node, 1, &mut leaves)
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
    // libinjection-based detectors (ported from OWASPCheck)
    DetectSqli,
    DetectXss,
    // Aho-Corasick pattern matchers (case-insensitive, leftmost-first).
    // `PatternSet` is sourced from a `.data` file (`pm_from_file`).
    // `PatternList` is sourced from an inline whitespace-separated list (`contains_any`).
    PatternSet(Arc<AhoCorasick>),
    PatternList(Arc<AhoCorasick>),
}

/// Compile a raw rule into its eval-ready form.
///
/// Selects the compile path based on rule shape:
/// 1. `match_tree` present → recursively compile the nested tree (preferred).
/// 2. Otherwise → wrap legacy flat `conditions` as `And`/`Or` per `condition_op`.
pub fn compile_rule(rule: &CustomRule) -> anyhow::Result<Option<CompiledRule>> {
    // Pattern-only rules are evaluated via `pattern_matches_request` at
    // runtime — they don't need (and must not have) a compiled tree,
    // otherwise the vacuous `And(vec![])` would match everything.
    if rule.match_tree.is_none() && rule.conditions.is_empty() {
        return Ok(None);
    }

    let root = if let Some(tree) = rule.match_tree.as_ref() {
        validate_tree(tree)?;
        compile_tree(tree)?
    } else {
        let leaves: Vec<CompiledNode> = rule
            .conditions
            .iter()
            .map(|c| compile_condition(c).map(CompiledNode::Leaf))
            .collect::<anyhow::Result<Vec<_>>>()?;
        match rule.condition_op {
            ConditionOp::And => CompiledNode::And(leaves),
            ConditionOp::Or => CompiledNode::Or(leaves),
        }
    };

    Ok(Some(CompiledRule {
        meta: rule.clone(),
        root,
    }))
}

/// Recursively compile a `ConditionNode` tree into a `CompiledNode` tree.
fn compile_tree(node: &ConditionNode) -> anyhow::Result<CompiledNode> {
    Ok(match node {
        ConditionNode::Leaf(c) => CompiledNode::Leaf(compile_condition(c)?),
        ConditionNode::And(b) => CompiledNode::And(b.and.iter().map(compile_tree).collect::<anyhow::Result<Vec<_>>>()?),
        ConditionNode::Or(b) => CompiledNode::Or(b.or.iter().map(compile_tree).collect::<anyhow::Result<Vec<_>>>()?),
        ConditionNode::Not(b) => CompiledNode::Not(Box::new(compile_tree(&b.not)?)),
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
            let re = regex::RegexBuilder::new(s)
                .size_limit(1 << 20)
                .build()
                .with_context(|| format!("invalid regex: {s}"))?;
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
        // libinjection detectors — value is ignored (detection is on the field)
        (Operator::DetectSqli, _) => Matcher::DetectSqli,
        (Operator::DetectXss, _) => Matcher::DetectXss,
        // Aho-Corasick multi-pattern matchers (pre-compiled at YAML load time).
        (Operator::PmFromFile, V::AhoCorasick(ac)) => Matcher::PatternSet(ac.clone()),
        (Operator::ContainsAny, V::AhoCorasick(ac)) => Matcher::PatternList(ac.clone()),
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
            Self::DetectSqli => detect_with_decode(fstr, |b| libinjectionrs::detect_sqli(b).is_injection()),
            Self::DetectXss => detect_with_decode(fstr, |b| libinjectionrs::detect_xss(b).is_injection()),
            Self::PatternSet(ac) | Self::PatternList(ac) => ac_matches_with_decode(ac, fstr),
        }
    }
}

/// Aho-Corasick scan with URL-decode bypass protection.
///
/// Mirrors `detect_with_decode`: tries raw input first, then single-pass and
/// recursive URL-decoded forms. Used for `pm_from_file` / `contains_any` so
/// that `/%2Eenv` matches `.env` after decoding.
fn ac_matches_with_decode(ac: &AhoCorasick, raw: &str) -> bool {
    use crate::checks::{url_decode, url_decode_recursive};

    if ac.is_match(raw) {
        return true;
    }
    let decoded = url_decode(raw);
    if decoded != raw && ac.is_match(&decoded) {
        return true;
    }
    let recursive = url_decode_recursive(raw);
    recursive != decoded && ac.is_match(&recursive)
}

/// Run a libinjection detector on raw + URL-decoded forms to catch encoding
/// bypass attempts (e.g. `%27OR%201%3D1` evading `SQLi` detection).
fn detect_with_decode(raw: &str, detector: impl Fn(&[u8]) -> bool) -> bool {
    use crate::checks::{url_decode, url_decode_recursive};

    if detector(raw.as_bytes()) {
        return true;
    }
    let decoded = url_decode(raw);
    if decoded != raw && detector(decoded.as_bytes()) {
        return true;
    }
    let recursive = url_decode_recursive(raw);
    recursive != decoded && detector(recursive.as_bytes())
}

// ── Pattern evaluation (Phase 2: YAML format consolidation) ─────────────────

/// Headers that carry routing/connection metadata, not attacker-controlled
/// payload. Must be skipped when `pattern_field` is `"all"` to avoid false
/// positives (e.g. SSRF rules tripping on `Host: localhost`).
fn is_routing_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | ":authority"
            | ":method"
            | ":path"
            | ":scheme"
            | "accept"
            | "accept-encoding"
            | "accept-language"
            | "connection"
            | "content-length"
            | "x-forwarded-host"
            | "x-real-ip"
    )
}

/// Test a value against a regex, trying URL-decoded variants to prevent
/// encoding bypass attacks (e.g. `%7B%7B7%2A7%7D%7D` evading SSTI rules).
fn test_with_decode(pattern: &Regex, raw: &str) -> bool {
    use crate::checks::{url_decode, url_decode_recursive};

    if pattern.is_match(raw) {
        return true;
    }
    let decoded = url_decode(raw);
    if decoded != raw && pattern.is_match(&decoded) {
        return true;
    }
    let recursive = url_decode_recursive(raw);
    recursive != decoded && pattern.is_match(&recursive)
}

/// Check if a compiled regex pattern matches the specified request field(s).
///
/// When field is `"all"`, checks path → query → headers (minus routing) → body
/// with URL-decode bypass protection (same logic as `OWASPCheck`).
fn pattern_matches_request(pattern: &Regex, field: &str, ctx: &RequestCtx) -> bool {
    match field {
        "path" => test_with_decode(pattern, &ctx.path),
        "query" => test_with_decode(pattern, &ctx.query),
        "body" => test_with_decode(pattern, &String::from_utf8_lossy(&ctx.body_preview)),
        "method" => pattern.is_match(&ctx.method),
        // "host"        — canonical field name for the HTTP Host header.
        // "header_host" — legacy alias kept for backward-compat with third-party
        //                 CRS YAML that uses `pattern_field: header_host`.
        //                 Both match only ctx.host to prevent false positives
        //                 caused by X-Forwarded-For or other proxy headers.
        "host" | "header_host" => pattern.is_match(&ctx.host),
        "user_agent" => ctx
            .headers
            .get("user-agent")
            .is_some_and(|v| test_with_decode(pattern, v)),
        "cookies" => ctx.cookies.iter().any(|(_, v)| test_with_decode(pattern, v)),
        "headers" => ctx
            .headers
            .iter()
            .filter(|(k, _)| !is_routing_header(k))
            .any(|(_, v)| test_with_decode(pattern, v)),
        // Response body rules are evaluated via check_response_body(), not here.
        "response_body" => false,
        // "all" or unknown field — check everything, smallest first
        _ => {
            test_with_decode(pattern, &ctx.path)
                || test_with_decode(pattern, &ctx.query)
                || ctx
                    .headers
                    .iter()
                    .filter(|(k, _)| !is_routing_header(k))
                    .any(|(_, v)| test_with_decode(pattern, v))
                || test_with_decode(pattern, &String::from_utf8_lossy(&ctx.body_preview))
        }
    }
}

/// Recursive evaluator over a `CompiledNode` tree.
fn eval_compiled_node(ctx: &RequestCtx, node: &CompiledNode) -> bool {
    match node {
        CompiledNode::Leaf(c) => eval_compiled_leaf(ctx, c),
        CompiledNode::And(v) => v.iter().all(|n| eval_compiled_node(ctx, n)),
        CompiledNode::Or(v) => v.iter().any(|n| eval_compiled_node(ctx, n)),
        CompiledNode::Not(b) => !eval_compiled_node(ctx, b),
    }
}

/// Evaluate a single compiled leaf, expanding `ConditionField::All` into a
/// path → query → body → non-routing-headers iteration. First hit wins.
fn eval_compiled_leaf(ctx: &RequestCtx, c: &CompiledCondition) -> bool {
    if matches!(c.field, ConditionField::All) {
        let body = String::from_utf8_lossy(&ctx.body_preview);
        if c.matcher.matches(&ctx.path, ctx.client_ip)
            || c.matcher.matches(&ctx.query, ctx.client_ip)
            || c.matcher.matches(&body, ctx.client_ip)
        {
            return true;
        }
        return ctx
            .headers
            .iter()
            .filter(|(k, _)| !is_routing_header(k))
            .any(|(_, v)| c.matcher.matches(v, ctx.client_ip));
    }
    let fval = field_value(ctx, &c.field);
    c.matcher.matches(fval.as_deref().unwrap_or(""), ctx.client_ip)
}

/// Returns `true` when a rule's `pattern_field` targets response body content.
fn rule_targets_response_body(rule: &CustomRule) -> bool {
    rule.pattern_field == "response_body"
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
        ConditionField::Cookie(None) => ctx.headers.get("cookie").cloned(),
        ConditionField::Cookie(Some(name)) => ctx.cookies.get(name).cloned(),
        ConditionField::UserAgent => ctx.headers.get("user-agent").cloned(),
        ConditionField::ContentType => ctx.headers.get("content-type").cloned(),
        ConditionField::Header(name) => ctx.headers.get(&name.to_lowercase()).cloned(),
        ConditionField::GeoCountry => ctx.geo.as_ref().map(|g| g.country.clone()),
        ConditionField::GeoIso => ctx.geo.as_ref().map(|g| g.iso_code.clone()),
        ConditionField::GeoProvince => ctx.geo.as_ref().map(|g| g.province.clone()),
        ConditionField::GeoCity => ctx.geo.as_ref().map(|g| g.city.clone()),
        ConditionField::GeoIsp => ctx.geo.as_ref().map(|g| g.isp.clone()),
        // ResponseBody is evaluated at response time, not request time.
        // Return None here so request-phase rules never match accidentally.
        ConditionField::ResponseBody | ConditionField::All => None,
    }
}

/// Walk a compiled tree and count `PatternSet` / `PatternList` matcher instances.
fn count_pattern_matchers(node: &CompiledNode, pm_count: &mut usize, ca_count: &mut usize) {
    match node {
        CompiledNode::Leaf(c) => match &c.matcher {
            Matcher::PatternSet(_) => *pm_count += 1,
            Matcher::PatternList(_) => *ca_count += 1,
            _ => {}
        },
        CompiledNode::And(v) | CompiledNode::Or(v) => {
            for child in v {
                count_pattern_matchers(child, pm_count, ca_count);
            }
        }
        CompiledNode::Not(b) => count_pattern_matchers(b, pm_count, ca_count),
    }
}

#[cfg(test)]
#[allow(clippy::trivial_regex)]
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
            cookies: std::collections::HashMap::new(),
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
            match_tree: None,
            risk_delta: None,
            risk_action: None,
            pattern: None,
            pattern_field: "all".into(),
            category: None,
            severity: None,
            paranoia: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
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
            match_tree: None,
            risk_delta: None,
            risk_action: None,
            pattern: None,
            pattern_field: "all".into(),
            category: None,
            severity: None,
            paranoia: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
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
            match_tree: None,
            risk_delta: None,
            risk_action: None,
            pattern: None,
            pattern_field: "all".into(),
            category: None,
            severity: None,
            paranoia: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
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
            match_tree: None,
            risk_delta: None,
            risk_action: None,
            pattern: None,
            pattern_field: "all".into(),
            category: None,
            severity: None,
            paranoia: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
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

        let compiled = compile_rule(&rule).expect("compile ok").expect("has tree");
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

        let compiled = compile_rule(&rule).expect("compile ok").expect("has tree");
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
        let compiled = compile_rule(&rule).expect("compile ok").expect("has tree");
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
            match_tree: None,
            risk_delta: None,
            risk_action: None,
            pattern: None,
            pattern_field: "all".into(),
            category: None,
            severity: None,
            paranoia: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
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
        let compiled = compile_rule(&rule).expect("compile ok").expect("has tree");
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
            match_tree: None,
            risk_delta: None,
            risk_action: None,
            pattern: None,
            pattern_field: "all".into(),
            category: None,
            severity: None,
            paranoia: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
        });

        assert!(engine.check(&make_ctx("/admin/x", "POST", "1.2.3.4")).is_some());
        assert!(engine.check(&make_ctx("/admin/x", "GET", "1.2.3.4")).is_none());
        assert!(engine.check(&make_ctx("/public", "POST", "1.2.3.4")).is_none());
    }

    // ── Phase 03: cookie-by-name + ctx.cookies ───────────────────────────────

    fn make_ctx_with_cookies(cookie_header: &str) -> RequestCtx {
        let mut ctx = make_ctx("/", "GET", "1.2.3.4");
        ctx.headers.insert("cookie".into(), cookie_header.into());
        ctx.cookies = waf_common::parse_cookie_header(cookie_header);
        ctx
    }

    #[test]
    fn cookie_by_name_matches_value() {
        // AC-6: field=cookie, name=session, op=eq, value=abc must match
        // `Cookie: session=abc; other=x`.
        let engine = CustomRulesEngine::new();
        engine.add_rule(CustomRule {
            id: "ck1".into(),
            host_code: "test".into(),
            name: "cookie session=abc".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![Condition {
                field: ConditionField::Cookie(Some("session".into())),
                operator: Operator::Eq,
                value: ConditionValue::Str("abc".into()),
            }],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
            match_tree: None,
            risk_delta: None,
            risk_action: None,
            pattern: None,
            pattern_field: "all".into(),
            category: None,
            severity: None,
            paranoia: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
        });

        assert!(engine.check(&make_ctx_with_cookies("session=abc; other=x")).is_some());
        assert!(engine.check(&make_ctx_with_cookies("session=zzz")).is_none());
        assert!(engine.check(&make_ctx_with_cookies("other=x")).is_none());
    }

    #[test]
    fn cookie_no_name_returns_full_header() {
        // Cookie(None) preserves legacy whole-header semantics.
        let engine = CustomRulesEngine::new();
        engine.add_rule(CustomRule {
            id: "ck2".into(),
            host_code: "test".into(),
            name: "cookie contains track".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![Condition {
                field: ConditionField::Cookie(None),
                operator: Operator::Contains,
                value: ConditionValue::Str("track=1".into()),
            }],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
            match_tree: None,
            risk_delta: None,
            risk_action: None,
            pattern: None,
            pattern_field: "all".into(),
            category: None,
            severity: None,
            paranoia: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
        });

        assert!(engine.check(&make_ctx_with_cookies("a=b; track=1")).is_some());
        assert!(engine.check(&make_ctx_with_cookies("a=b")).is_none());
    }

    #[test]
    fn cookie_legacy_string_deserializes_as_none() {
        // DB-stored rules with legacy `"field": "cookie"` must round-trip
        // into `Cookie(None)` — preserves back-compat for existing rules.
        let json = r#"{"field":"cookie","operator":"contains","value":"x"}"#;
        let cond: Condition = serde_json::from_str(json).expect("legacy parse");
        assert!(matches!(cond.field, ConditionField::Cookie(None)));
    }

    #[test]
    fn cookie_with_name_deserializes_from_map() {
        // New shape: `{"cookie": "session"}` → Cookie(Some("session")).
        let json = r#"{"field":{"cookie":"session"},"operator":"eq","value":"abc"}"#;
        let cond: Condition = serde_json::from_str(json).expect("named parse");
        match cond.field {
            ConditionField::Cookie(Some(name)) => assert_eq!(name, "session"),
            other => panic!("expected Cookie(Some), got {other:?}"),
        }
    }

    #[test]
    fn cookie_explicit_null_deserializes_as_none() {
        // `{"cookie": null}` is explicit form of legacy whole-header.
        let json = r#"{"field":{"cookie":null},"operator":"contains","value":"x"}"#;
        let cond: Condition = serde_json::from_str(json).expect("null parse");
        assert!(matches!(cond.field, ConditionField::Cookie(None)));
    }

    // ── Phase 04: nested AND/OR/Not condition tree ──────────────────────────

    fn leaf(field: ConditionField, op: Operator, val: &str) -> ConditionNode {
        ConditionNode::Leaf(Condition {
            field,
            operator: op,
            value: ConditionValue::Str(val.into()),
        })
    }

    fn rule_with_tree(tree: ConditionNode) -> CustomRule {
        CustomRule {
            id: "t1".into(),
            host_code: "test".into(),
            name: "tree".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: Vec::new(),
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
            match_tree: Some(tree),
            risk_delta: None,
            risk_action: None,
            pattern: None,
            pattern_field: "all".into(),
            category: None,
            severity: None,
            paranoia: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
        }
    }

    #[test]
    fn tree_json_roundtrip_nested() {
        // `(ip in CIDR OR cookie=bad) AND path~/api/*/admin`
        let json = r#"{
            "and": [
              { "or": [
                  {"field":"ip","operator":"cidr_match","value":"10.0.0.0/8"},
                  {"field":{"cookie":"session"},"operator":"eq","value":"bad"}
              ]},
              {"field":"path","operator":"wildcard","value":"/api/*/admin"}
            ]
        }"#;
        let tree: ConditionNode = serde_json::from_str(json).expect("parse tree");
        let back = serde_json::to_value(&tree).expect("serialize tree");
        // Round-trip should preserve top-level and-array length.
        assert!(back.get("and").and_then(|v| v.as_array()).is_some_and(|a| a.len() == 2));
    }

    #[test]
    fn tree_depth_exceeded_rejected() {
        // Build a chain of Not nodes deeper than MAX_TREE_DEPTH.
        let mut node = leaf(ConditionField::Path, Operator::Eq, "/x");
        for _ in 0..=MAX_TREE_DEPTH {
            node = ConditionNode::Not(NotBranch { not: Box::new(node) });
        }
        assert!(validate_tree(&node).is_err());
    }

    #[test]
    fn tree_leaves_exceeded_rejected() {
        let leaves = (0..=MAX_TREE_LEAVES)
            .map(|_| leaf(ConditionField::Path, Operator::Eq, "/x"))
            .collect();
        let tree = ConditionNode::Or(OrBranch { or: leaves });
        assert!(validate_tree(&tree).is_err());
    }

    #[test]
    fn legacy_db_rule_still_compiles() {
        // No match_tree → falls back to flat conditions wrapped in And/Or.
        let rule = mk_rule(
            ConditionOp::Or,
            vec![Condition {
                field: ConditionField::Ip,
                operator: Operator::CidrMatch,
                value: ConditionValue::Str("10.0.0.0/8".into()),
            }],
        );
        let compiled = compile_rule(&rule).expect("compile ok").expect("has tree");
        assert!(matches!(compiled.root, CompiledNode::Or(ref l) if l.len() == 1));
    }

    /// AC-8 truth table: `(ip in 10.0.0.0/8 OR cookie session=bad) AND path~/api/*/admin`
    fn ac8_tree() -> ConditionNode {
        ConditionNode::And(AndBranch {
            and: vec![
                ConditionNode::Or(OrBranch {
                    or: vec![
                        leaf(ConditionField::Ip, Operator::CidrMatch, "10.0.0.0/8"),
                        ConditionNode::Leaf(Condition {
                            field: ConditionField::Cookie(Some("session".into())),
                            operator: Operator::Eq,
                            value: ConditionValue::Str("bad".into()),
                        }),
                    ],
                }),
                leaf(ConditionField::Path, Operator::Wildcard, "/api/*/admin"),
            ],
        })
    }

    fn ac8_engine() -> CustomRulesEngine {
        let engine = CustomRulesEngine::new();
        engine.add_rule(rule_with_tree(ac8_tree()));
        engine
    }

    fn ac8_ctx(ip: &str, path: &str, cookie: &str) -> RequestCtx {
        let mut ctx = make_ctx(path, "GET", ip);
        ctx.headers.insert("cookie".into(), cookie.into());
        ctx.cookies = waf_common::parse_cookie_header(cookie);
        ctx
    }

    #[test]
    fn ac8_tt_left_true_right_true_matches() {
        // Left OR true (ip in CIDR), Right true (path matches): expect match.
        let engine = ac8_engine();
        assert!(engine.check(&ac8_ctx("10.0.1.5", "/api/v1/admin", "")).is_some());
        // Also true via the cookie branch of the OR.
        assert!(
            engine
                .check(&ac8_ctx("1.2.3.4", "/api/v1/admin", "session=bad"))
                .is_some()
        );
    }

    #[test]
    fn ac8_tf_left_true_right_false_misses() {
        // Left true, Right false (path mismatch): expect miss.
        let engine = ac8_engine();
        assert!(engine.check(&ac8_ctx("10.0.1.5", "/public", "")).is_none());
    }

    #[test]
    fn ac8_ft_left_false_right_true_misses() {
        // Left false (ip not in CIDR, cookie not bad), Right true: expect miss.
        let engine = ac8_engine();
        assert!(
            engine
                .check(&ac8_ctx("1.2.3.4", "/api/v1/admin", "session=ok"))
                .is_none()
        );
    }

    #[test]
    fn ac8_ff_left_false_right_false_misses() {
        // Both false: expect miss.
        let engine = ac8_engine();
        assert!(engine.check(&ac8_ctx("1.2.3.4", "/public", "session=ok")).is_none());
    }

    #[test]
    fn from_db_rule_detects_match_tree_shape() {
        use chrono::Utc;
        use uuid::Uuid;
        use waf_storage::models::CustomRule as DbCustomRule;

        let conditions = serde_json::json!({
            "match_tree": {
                "and": [
                    {"field": "path", "operator": "starts_with", "value": "/api"},
                    {"not": {"field": "method", "operator": "eq", "value": "GET"}}
                ]
            }
        });
        let row = DbCustomRule {
            id: Uuid::new_v4(),
            host_code: "test".into(),
            name: "tree-rule".into(),
            description: None,
            priority: 1,
            enabled: true,
            condition_op: "and".into(),
            conditions,
            action: "block".into(),
            action_status: 403,
            action_msg: None,
            script: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            risk_delta: None,
            risk_action: None,
        };
        let rule = from_db_rule(&row).expect("parse db row");
        assert!(rule.match_tree.is_some());
        assert!(rule.conditions.is_empty());
        // And ensure it compiles.
        compile_rule(&rule).expect("compile tree rule");
    }

    #[test]
    fn from_db_rule_legacy_array_still_works() {
        use chrono::Utc;
        use uuid::Uuid;
        use waf_storage::models::CustomRule as DbCustomRule;

        let conditions = serde_json::json!([
            {"field": "path", "operator": "starts_with", "value": "/admin"}
        ]);
        let row = DbCustomRule {
            id: Uuid::new_v4(),
            host_code: "test".into(),
            name: "legacy-rule".into(),
            description: None,
            priority: 1,
            enabled: true,
            condition_op: "and".into(),
            conditions,
            action: "block".into(),
            action_status: 403,
            action_msg: None,
            script: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            risk_delta: None,
            risk_action: None,
        };
        let rule = from_db_rule(&row).expect("parse legacy row");
        assert!(rule.match_tree.is_none());
        assert_eq!(rule.conditions.len(), 1);
    }

    // ── Phase 1: ResponseBody field mapping ─────────────────────────────

    #[test]
    fn response_body_deserializes_from_string() {
        let json = r#"{"field":"response_body","operator":"contains","value":"shell"}"#;
        let cond: Condition = serde_json::from_str(json).expect("deser");
        assert!(matches!(cond.field, ConditionField::ResponseBody));
    }

    #[test]
    fn response_body_field_value_returns_none() {
        let ctx = make_ctx("/", "GET", "1.2.3.4");
        let val = field_value(&ctx, &ConditionField::ResponseBody);
        assert!(val.is_none(), "ResponseBody should be None at request time");
    }

    #[test]
    fn response_body_rule_skipped_at_request_time() {
        let engine = CustomRulesEngine::new();
        let rule = CustomRule {
            id: "rb-001".into(),
            host_code: "test".into(),
            name: "detect shell in response".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
            match_tree: None,
            risk_delta: None,
            risk_action: None,
            pattern: Some(Regex::new("r57shell").unwrap()),
            pattern_field: "response_body".into(),
            category: Some("web-shell".into()),
            severity: Some("critical".into()),
            paranoia: Some(1),
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
        };
        engine.add_rule(rule);

        // Should NOT match at request time even if body contains pattern
        let mut ctx = make_ctx("/", "GET", "1.2.3.4");
        ctx.body_preview = bytes::Bytes::from("r57shell detected");
        assert!(
            engine.check(&ctx).is_none(),
            "response_body rule must not fire at request time"
        );
    }

    #[test]
    fn check_response_body_matches_pattern() {
        let engine = CustomRulesEngine::new();
        engine.add_rule(CustomRule {
            id: "rb-002".into(),
            host_code: "*".into(),
            name: "detect stack trace".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
            match_tree: None,
            risk_delta: None,
            risk_action: None,
            pattern: Some(Regex::new(r"(?i)java\.lang\.NullPointerException").unwrap()),
            pattern_field: "response_body".into(),
            category: Some("data-leakage".into()),
            severity: Some("high".into()),
            paranoia: Some(1),
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
        });

        assert!(engine.has_response_rules());

        let result = engine.check_response_body(
            "test",
            "Error: java.lang.NullPointerException at com.example.Main.run(Main.java:42)",
        );
        assert!(result.is_some(), "should detect stack trace in response body");

        let result = engine.check_response_body("test", "Hello, world!");
        assert!(result.is_none(), "clean response should not match");
    }

    #[test]
    fn check_response_body_host_specific() {
        let engine = CustomRulesEngine::new();
        engine.add_rule(CustomRule {
            id: "rb-003".into(),
            host_code: "api-host".into(),
            name: "api-specific response rule".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
            match_tree: None,
            risk_delta: None,
            risk_action: None,
            pattern: Some(Regex::new("SENSITIVE_DATA").unwrap()),
            pattern_field: "response_body".into(),
            category: None,
            severity: None,
            paranoia: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
        });

        // Matches for the correct host
        assert!(
            engine
                .check_response_body("api-host", "contains SENSITIVE_DATA here")
                .is_some()
        );
        // Does NOT match for a different host (no global rules loaded)
        assert!(
            engine
                .check_response_body("other-host", "contains SENSITIVE_DATA here")
                .is_none()
        );
    }

    #[test]
    fn has_response_rules_false_when_none() {
        let engine = CustomRulesEngine::new();
        assert!(!engine.has_response_rules());

        // Add a request-time rule — should still be false
        engine.add_rule(mk_rule(
            ConditionOp::And,
            vec![Condition {
                field: ConditionField::Path,
                operator: Operator::Eq,
                value: ConditionValue::Str("/admin".into()),
            }],
        ));
        assert!(!engine.has_response_rules());
    }

    #[test]
    fn pattern_matches_request_returns_false_for_response_body() {
        let pattern = Regex::new("secret").unwrap();
        let mut ctx = make_ctx("/", "GET", "1.2.3.4");
        ctx.body_preview = bytes::Bytes::from("secret data");
        // Even though body contains "secret", field="response_body" must not match
        assert!(!pattern_matches_request(&pattern, "response_body", &ctx));
    }

    // ── Phase 1: Regex pre-compilation guarantee ────────────────────────

    #[test]
    fn invalid_regex_rejects_rule_at_load() {
        let engine = CustomRulesEngine::new();
        engine.add_rule(CustomRule {
            id: "bad-re".into(),
            host_code: "test".into(),
            name: "bad regex".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![Condition {
                field: ConditionField::Path,
                operator: Operator::Regex,
                value: ConditionValue::Str("[invalid".into()),
            }],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
            match_tree: None,
            risk_delta: None,
            risk_action: None,
            pattern: None,
            pattern_field: "all".into(),
            category: None,
            severity: None,
            paranoia: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
        });
        assert!(engine.is_empty(), "rule with invalid regex must be rejected at load");
    }

    #[test]
    fn eval_one_regex_arm_returns_false_fail_closed() {
        let engine = CustomRulesEngine::new();
        let cond = Condition {
            field: ConditionField::Path,
            operator: Operator::Regex,
            value: ConditionValue::Str("^admin.*".into()),
        };
        let ctx = make_ctx("/admin/login", "GET", "1.2.3.4");
        assert!(
            !engine.eval_one(&ctx, &cond),
            "uncompiled regex eval_one must return false (fail-closed)"
        );
    }

    #[test]
    fn valid_regex_compiles_and_matches_at_eval() {
        let engine = CustomRulesEngine::new();
        engine.add_rule(CustomRule {
            id: "good-re".into(),
            host_code: "test".into(),
            name: "regex match".into(),
            priority: 1,
            enabled: true,
            condition_op: ConditionOp::And,
            conditions: vec![Condition {
                field: ConditionField::Path,
                operator: Operator::Regex,
                value: ConditionValue::Str("^/admin.*".into()),
            }],
            action: RuleAction::Block,
            action_status: 403,
            action_msg: None,
            script: None,
            match_tree: None,
            risk_delta: None,
            risk_action: None,
            pattern: None,
            pattern_field: "all".into(),
            category: None,
            severity: None,
            paranoia: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
            reference: None,
        });
        assert_eq!(engine.len(), 1, "valid regex rule must be loaded");

        let ctx_match = make_ctx("/admin/login", "GET", "1.2.3.4");
        assert!(engine.check(&ctx_match).is_some(), "regex should match /admin/login");

        let ctx_miss = make_ctx("/user/profile", "GET", "1.2.3.4");
        assert!(
            engine.check(&ctx_miss).is_none(),
            "regex should not match /user/profile"
        );
    }

    #[test]
    fn eval_one_cidr_arm_returns_false_fail_closed() {
        let engine = CustomRulesEngine::new();
        let cond = Condition {
            field: ConditionField::Ip,
            operator: Operator::CidrMatch,
            value: ConditionValue::Str("10.0.0.0/8".into()),
        };
        let ctx = make_ctx("/", "GET", "10.0.1.5");
        assert!(
            !engine.eval_one(&ctx, &cond),
            "uncompiled cidr eval_one must return false (fail-closed)"
        );
    }
}
