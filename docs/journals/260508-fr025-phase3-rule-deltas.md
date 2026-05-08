# FR-025 Phase 3: L1 Rule Deltas Implementation Complete

**Date**: 2026-05-08 13:52
**Severity**: N/A (Feature Completion)
**Component**: Risk Engine / Rule Delta Layer (L1)
**Status**: Resolved

## What Happened

Implemented FR-025 Phase 3: L1 Rule Deltas — WAF rule matches now contribute risk deltas to the cumulative scoring pipeline. Extended Rule/CustomRule structs with `risk_delta: Option<i16>` and `risk_action: Option<String>`. Created `check_with_verdict()` method to collect ALL matched rules (not short-circuit on first match). All 812 waf-engine tests pass.

## The Technical Win

**Verdict collection design**: CustomRulesEngine now collects every matched rule via `RuleVerdict` type, accumulating risk_delta across rule categories (SSTI=60, SSRF=55, XXE=60, SQLi=45, XSS=40). Built `clamp_per_request_deltas()` to enforce [0,100] ceiling — oldest positive deltas truncated first when budget exhausted. `dominant_contributor()` selects max |delta| rule for X-WAF-Rule-Id header.

Updated all 4 parsers (yaml.rs, json.rs, modsec.rs, custom_rule_yaml.rs) atomically — no stale rule formats. Documented delta convention table in code-standards.md: severity tiers (Critical→Critical-1, High→1-10, etc.).

## Key Decisions & Rationale

- **Why collect all matches, not short-circuit?** Risk aggregation requires full rule history per request; short-circuiting loses signal.
- **Why clamp at [0,100]?** Prevents delta inflation; oldest-first truncation preserves recent (higher-confidence) rule signals.
- **Why dominant_contributor for header?** Debugging: max absolute delta identifies the rule that moved risk most — easier audit trail.
- **Sample deltas in advanced.yaml?** Real-world guidance; operators copy patterns; delta=0 defaults for custom rules (backwards-compatible).

## What's Next

Phase 4: Velocity Deltas L2 — time-windowed request rate (req/sec) contributes additional risk. Seed layer (L0) + Rule deltas (L1) feed into velocity scorer. Risk action field enables per-rule enforcement (block vs. challenge) downstream.

Commit: f4298fc
