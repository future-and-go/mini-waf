---
phase: 5
title: "Observability & Retro-audit"
status: pending
priority: P3
effort: "3h"
dependencies: [3]
---

# Phase 5: Observability & Retro-audit

## Overview

Wire Prometheus metrics + tracing spans so the next silent-fail (if any) is detectable in a dashboard, not via a curl 6 months later. The retro-audit log is an explicit acknowledgement: any operator running before this fix had inert coverage — we name it.

## Requirements

- Prometheus metrics registered against the existing registry:
  - `waf_rules_loaded_total{result, reason}` (counter)
  - `waf_rule_fire_total{rule_id, host_code}` (counter — likely already exists; verify)
  - `waf_pattern_file_bytes{path_hash}` (gauge)
  - `waf_pattern_file_patterns{path_hash}` (gauge)
  - `waf_data_file_reloads_total{path_hash}` (counter)
- Tracing span on rule fire: `rule_id`, `matched_field`, `match` (truncated to 64 chars).
- Retro-audit log: one-shot startup log naming "rules previously inert before fix-260524".

## Architecture

Metric registration colocated with existing WAF metrics module (grep for `Counter::new` / `lazy_static!` / `prometheus::register_` to locate registry).

Path hashing: SHA-256 of canonical path, first 8 hex chars. Avoids leaking filesystem layout via label cardinality.

Retro-audit: implementable as a one-shot `tracing::warn!` at engine startup describing how many `pm_from_file`/`contains_any` rules are now active that previously weren't:

```rust
tracing::warn!(
    pm_from_file_rules = pm_count,
    contains_any_rules = ca_count,
    "retro_audit: these rule types were inert prior to fix-260524-pm-matcher; coverage now active"
);
```

## Related Code Files

- **Modify:**
  - WAF metrics module (locate via grep — likely `crates/waf-engine/src/metrics.rs` or similar)
  - `crates/waf-engine/src/rules/manager.rs` (increment counters on load complete)
  - `crates/waf-engine/src/rules/engine.rs` (tracing span on rule fire — only if not already there)
  - `crates/waf-engine/src/rules/data_file_registry.rs` (emit reload counter)

## Implementation Steps

1. **Locate existing metrics module** — `grep -rn "register_counter\|register_gauge\|prometheus" crates/waf-engine/src | head -20`.

2. Add the new counters/gauges to that module. Reuse the registry — do NOT create a parallel one.

3. Increment `waf_rules_loaded_total{result="loaded"}` and `{result="failed", reason=...}` at the end of each rule load cycle.

4. On `DataFileRegistry::load_or_get` cache miss, set `pattern_file_bytes` / `pattern_file_patterns` gauges and bump `data_file_reloads_total`.

5. Tracing span on rule fire — wrap the eval call site:
   ```rust
   let _span = tracing::info_span!("rule_fire", rule_id = %rule.id, matched_field, match = %truncate(matched_str, 64)).entered();
   ```

6. Retro-audit log: in engine post-load, count `Matcher::PatternSet` + `Matcher::PatternList` instances and emit a single `warn` log if count > 0.

7. Verify via integration test: spin up engine, send a request that fires a rule, assert counter value increased (use prometheus testutil or simple scrape parsing).

## Success Criteria

- [ ] All five metrics registered and exposed via existing `/metrics` endpoint.
- [ ] Manual scrape after firing CRS-930130 shows `waf_rule_fire_total{rule_id="CRS-930130"}` incremented.
- [ ] Retro-audit log emitted exactly once per startup.
- [ ] No new test failures.
- [ ] `cargo fmt --all -- --check` clean.

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| High-cardinality `rule_id` label explodes time series | Rule set is bounded (~hundreds). Acceptable. |
| Path label leaks filesystem structure | Hash truncation. |
| Span overhead per rule fire | `info` level + sampling already controlled by tracing-subscriber config. |

## Out of Scope

- Dashboards (Grafana JSON) — separate ops task.
- Alerting rules — separate ops task.
- Replacing the existing rule_fire metric if it already exists in a different shape.
