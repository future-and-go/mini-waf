---
phase: 1
title: "Fix response_body Field Mapping"
status: done
priority: P1
effort: "3h"
dependencies: []
---

# Phase 1: Fix response_body Field Mapping

## Overview

53 YAML rules use `pattern_field: response_body` to detect data leakage in HTTP responses (web shells, SQL error strings, Java stack traces, API keys). The parser `parse_pattern_field_to_condition()` silently maps `response_body` to `ConditionField::Body` (request body) via the catch-all `_ =>` branch. These rules never fire on their intended target.

**Why this matters:** The response body content scanner (`gateway/src/filters/response_body_content_scanner.rs`, FR-033) already handles response-time scanning with hardcoded patterns (stack traces, error messages, API keys, internal IPs). The YAML rules in question overlap with FR-033's scope but are user-configurable. We need to decide: route them to the existing scanner, or add a new `ResponseBody` variant.

**Why we chose this approach:** Adding a `ResponseBody` variant to `ConditionField` is the cleanest fix — it makes the field parseable, serializable, and queryable through the existing rule engine. The gateway already has the `response_body_filter` hook point. Wiring `ResponseBody` rules into that pipeline keeps the architecture consistent without duplicating scan logic.

**Alternative considered:** Simply logging a warning on `response_body` (no actual fix). Rejected — this leaves 53 rules non-functional and doesn't solve the underlying problem.

## Requirements

- Functional: `pattern_field: response_body` must evaluate against actual HTTP response body bytes
- Functional: Existing request-time rule evaluation must not regress
- Non-functional: Response body scanning must respect the existing `MAX_DECOMPRESS_BYTES` (4MB) and `MAX_INPUT_BYTES` (8MB) limits from FR-033

## Architecture

```
Request phase (unchanged):
  YAML rules with pattern_field: path/query/body/... → CustomRulesEngine

Response phase (new):
  YAML rules with pattern_field: response_body
    → Collected at parse time into separate Vec<CustomRule>
    → Evaluated in gateway::proxy::response_body_filter() alongside FR-033 scanner
    → Match → log attack event (same as request-time rules)
```

## Related Code Files

- Modify: `crates/waf-engine/src/rules/engine.rs` — add `ResponseBody` variant to `ConditionField` enum (line 27)
- Modify: `crates/waf-engine/src/rules/engine.rs` — add `"response_body"` to `Deserialize` impl `visit_str` match (line 74)
- Modify: `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs` — add `"response_body"` arm to `parse_pattern_field_to_condition()` (line 208)
- Modify: `crates/waf-engine/src/checks/owasp.rs` — add `"response_body"` arm to `legacy_map_field()` (line 451)
- Modify: `crates/gateway/src/proxy.rs` — wire `ResponseBody` rules into `response_body_filter()` (line 838)
- Read: `crates/gateway/src/filters/response_body_content_scanner.rs` — understand existing response scan pipeline
- Read: `crates/waf-engine/src/checks/mod.rs` — line 59 comment about deferred response_body_filter path

## Implementation Steps

1. **Add `ResponseBody` variant to `ConditionField` enum** in `engine.rs:27`
   - Add below `GeoIsp`: `ResponseBody`
   - Add `"response_body"` to the `visit_str` match in `Deserialize` impl (~line 89)
   - Add `"response_body"` to the expected variants list (~line 97)

2. **Fix `parse_pattern_field_to_condition()`** in `custom_rule_yaml.rs:208`
   - Add explicit arm: `"response_body" => ConditionField::ResponseBody`
   - This handles all 43 `custom_rule_v1` files that use this field

3. **Fix `legacy_map_field()`** in `owasp.rs:451`
   - Add arm: `"response_body" => ConditionField::ResponseBody`
   - This handles any legacy-format files referencing this field

4. **Partition rules by evaluation phase** in `CustomRulesEngine`
   - At load time, split rules into `request_rules: Vec<CustomRule>` and `response_rules: Vec<CustomRule>` based on whether any condition uses `ConditionField::ResponseBody`
   - Expose `pub fn response_rules(&self) -> &[CustomRule]` accessor

5. **Wire response rules into `response_body_filter()`** in `proxy.rs:838`
   - After FR-033 scanner runs, iterate `response_rules()` and evaluate each rule's regex against the accumulated response body bytes
   - On match: emit attack log event (reuse existing `SecurityEvent` logging)
   - Respect `MAX_DECOMPRESS_BYTES` limit (already enforced by decompressor)

6. **Run `cargo check` and `cargo test`** to verify no regressions

## Success Criteria

- [x] `ConditionField::ResponseBody` variant exists and deserializes from `"response_body"` string
- [x] `parse_pattern_field_to_condition("response_body")` returns `ConditionField::ResponseBody` (not `Body`)
- [x] `legacy_map_field("response_body")` returns `ConditionField::ResponseBody` (not `Body`)
- [x] Rules with `pattern_field: response_body` are separated from request-time rules at load time
- [x] Response body rules are evaluated in the `response_body_filter` pipeline
- [x] `cargo check` passes with zero warnings related to these changes
- [x] Existing request-time rule tests still pass (1286 waf-engine + 327 gateway = 1613 total)

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Response body scanning adds latency | Medium | Low | Rules only evaluated on responses, behind existing decompressor; FR-033 scanner already adds comparable cost |
| Large response bodies cause memory pressure | Low | Medium | Existing `MAX_DECOMPRESS_BYTES` (4MB) cap already enforced by decompressor pipeline |
| Regex patterns designed for response content may have false positives on binary responses | Low | Low | Content scanner already skips non-text content types; reuse same guard |

## Common Pitfalls

- **Don't forget the `Deserialize` impl.** The `ConditionField` has a custom deserializer (`visit_str` at line 74) — adding the enum variant alone is not enough. You must also add the string mapping there, or DB-stored rules with `response_body` will fail to deserialize.
- **Don't evaluate response rules at request time.** If a `ResponseBody` rule accidentally runs in the request phase, it will match against request body (the original bug). The partition into `request_rules` / `response_rules` prevents this.
- **Don't skip the catch-all fix.** Even after adding `"response_body"` to the match, the `_ => ConditionField::Body` catch-all at line 220 still exists. Consider changing it to log a warning for truly unknown fields instead of silent fallback.
