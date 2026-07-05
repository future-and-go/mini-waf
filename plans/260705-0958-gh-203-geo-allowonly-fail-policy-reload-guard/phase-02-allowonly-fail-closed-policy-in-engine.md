---
phase: 2
title: "AllowOnly fail-closed policy in engine"
status: completed
dependencies: [1]
effort: "2h"
---

# Phase 2: AllowOnly fail-closed policy in engine

# (dependency on Phase 1 is scheduling only — both edit engine crate; no code coupling)

## Overview

Give `GeoRule` an opt-in `fail_closed` flag and make `GeoCheck::check` policy-
aware so that AllowOnly rules can **block** when the request has no determinable
country (missing xdb, lookup failure, private IP → empty/absent `ctx.geo`).
Default `false` = current fail-open behavior. This phase is pure engine
(`geo.rs`) with unit tests; the API/loader wiring that sets the flag is Phase 3.
The flag defaults to `false` everywhere, so all existing `GeoRule` construction
sites keep working unchanged.

## Requirements

- Functional: `GeoRule` gains `fail_closed: bool`; only meaningful for
  `GeoRuleMode::AllowOnly` (ignored for `Block`).
- Functional: when `ctx.geo` is `None` or empty AND the host has an AllowOnly
  rule with `fail_closed == true`, `check()` returns a `Block`
  (`Phase::GeoIp`, detail names "geo data unavailable").
- Functional: when geo is unavailable and no fail-closed AllowOnly rule applies,
  `check()` returns `None` (fail-open — unchanged).
- Functional: when geo data IS present, behavior is byte-for-byte unchanged
  (block/allow matching as today).
- Non-functional: the data-present hot path stays allocation-free; the empty-geo
  branch only runs when `ctx.geo` is `None`/empty (already the rare path).

## Architecture

### 1. Add the field (`geo.rs:23-31`)

```rust
pub struct GeoRule {
    pub id: String,
    pub name: String,
    pub mode: GeoRuleMode,
    pub iso_codes: HashSet<String>,
    pub countries: HashSet<String>,
    /// AllowOnly only: block when the request has no determinable country
    /// (missing xdb / lookup failure / private IP). Default false = fail-open.
    pub fail_closed: bool,
}
```

Every existing `GeoRule { .. }` literal must add `fail_closed: false`. Verified
construction sites to update:
- `geo.rs` tests: `geo.rs:226-232`, `geo.rs:247-253`, `geo.rs:269-274`.
- GH-197 `geo_config.rs` mapping (lands first) — its emitters gain the field;
  Phase 3 sets it from the row. If Phase 3 runs before GH-197 merges, coordinate.
- Re-grep before editing: `rg -n "GeoRule\s*\{" crates/` (list every literal;
  there are 3 in `geo.rs` tests today plus GH-197's loader — confirm count at
  implementation time).

### 2. Make `check()` policy-aware (`geo.rs:165-175`)

Current early return drops out before rules are consulted. Restructure so the
empty/absent-geo case still checks for a fail-closed AllowOnly rule:

```rust
fn check(&self, ctx: &mut RequestCtx) -> Option<DetectionResult> {
    let host = &ctx.host_config.code;
    match &ctx.geo {
        Some(geo) if !(geo.country.is_empty() && geo.iso_code.is_empty()) => {
            self.eval_rules(host, geo)          // data present — unchanged path
        }
        // geo absent or empty: only a fail-closed AllowOnly rule acts
        _ => self.eval_fail_closed(host),
    }
}
```

Add `GeoCheck::eval_fail_closed(&self, host_code: &str) -> Option<DetectionResult>`:
mirror `eval_rules`' host-then-global lookup (`geo.rs:88-102`), but scan for a
rule with `mode == AllowOnly && fail_closed` and, if found, return a `Block`
`DetectionResult` (`Phase::GeoIp`, `rule_id`/`rule_name` from the rule, detail
e.g. `"Blocked by geo allowlist '{name}': geo data unavailable (fail-closed)"`).
Keep `rule_action`/`action_status` `None` like the existing arms.

Keep the existing `match_rules` / `geo_matches` (`geo.rs:104-155`) untouched —
they only run on the data-present path.

## Related Code Files

- Modify: `crates/waf-engine/src/checks/geo.rs` — add `fail_closed` to `GeoRule`
  (23-31); restructure `check()` (165-175); add `eval_fail_closed` near
  `eval_rules` (88-102); update 3 test literals; add fail-closed/fail-open tests.
- Reference (do not change here): `engine.rs:850` (geo runs at Phase 17);
  `engine.rs:770-771` (`ctx.geo` population); `engine.rs:774-781` (IP whitelist
  short-circuits before geo — the private-IP mitigation).

## Implementation Steps

1. Add `fail_closed: bool` to `GeoRule`; fix all literals (`rg -n "GeoRule\s*\{"`).
2. Add `eval_fail_closed`; restructure `check()` to route empty/absent geo to it.
3. Unit tests (see Success Criteria) covering both fail modes and unchanged
   data-present behavior.
4. `cargo test -p waf-engine geo`; `cargo clippy -p waf-engine`; `cargo fmt`.

## Success Criteria

- [ ] AllowOnly `['US']`, `fail_closed:true`, `ctx.geo = None` → `check()` returns
      `Some(Block)` (`Phase::GeoIp`).
- [ ] AllowOnly `['US']`, `fail_closed:true`, `ctx.geo = Some(empty GeoIpInfo)` →
      `Block` (covers private-IP / lookup-miss).
- [ ] AllowOnly `['US']`, `fail_closed:false`, geo empty/None → `None` (fail-open,
      unchanged — regression guard).
- [ ] AllowOnly `['US']`, `fail_closed:true`, `ctx.geo = US` → `None` (allowed).
- [ ] AllowOnly `['US']`, `fail_closed:true`, `ctx.geo = CN` → `Block` (existing
      not-in-list behavior still fires).
- [ ] Block-mode rule + empty/None geo → `None` regardless of any flag (Block
      never fails closed).
- [ ] All existing `geo.rs` tests still pass unchanged.

## Risk Assessment

- **Control-flow inversion in a hot-path check (High).** The `check()` restructure
  is exactly the kind of change that silently flips behavior. Mitigation: the
  fail-open regression guard test (geo empty + `fail_closed:false` → `None`) and
  the unchanged-data-present tests must both pass; the data-present arm calls the
  *same* `eval_rules` as today.
- **`ctx.geo == None` (service disabled) blocked under fail-closed (Med).** With
  the strict interpretation, disabling GeoIP entirely while a fail-closed
  AllowOnly rule is configured blocks matching hosts. This is intentional and
  opt-in but surprising; documented in plan Key Decisions + Open Questions. IP
  whitelist (`engine.rs:774-781`) exempts internal ranges upstream.
- **Missed construction site (Low).** A `GeoRule` literal without `fail_closed`
  fails to compile — caught immediately, not silently. Re-grep before edit.
- **Rollback:** remove `eval_fail_closed`, restore the early-return `check()`,
  drop the field; no persisted state.
</content>
