# Code Review — GH-195 Risk Action Enforcement

Branch: `fix/gh-195-risk-action-enforcement` (working-tree, uncommitted)
Scope: `crates/waf-engine/src/engine.rs`, `crates/waf-engine/src/risk/canary.rs`, `crates/waf-engine/CLAUDE.md`
Verified: `cargo check -p waf-engine --tests` compiles clean.

## Overall Assessment

Ship-ready. The fix wires `ScorerResult.action` into the returned `WafDecision`
as an escalation-only gate and completes FR-028 canary → DDoS-ban wiring. All
five acceptance criteria trace to code + a passing test. No blocking issues. No
public-contract breakage. Side-effect ordering (log/community/audit) matches the
existing detection pipeline. The specific race, double-count, clamp, and
error-path concerns raised in the task were checked and are non-issues.

## Acceptance Criteria — verified

- **AC#1** (scorer Block/Challenge surface in decision): engine.rs:714-723 gate +
  `make_risk_decision` (735-757) build `Phase::RiskScore` / `rule_name =
  "cumulative_risk"`, Block carries a rendered block-page body via
  `WafDecision::block` (equivalent to `make_block_decision`), `risk_score`
  reattached at 721. Test `risk_threshold_matrix_enforced`.
- **AC#2** (canary hit → 403 score 100 + DDoS ban): scorer.rs:182-206 force_max +
  ban-table insert; engine.rs canary layer bound to `ddos_check.ban_table()` at
  264-270. Test `canary_hit_bans_and_pin_blocks` sub-cases a/b, incl. follow-up
  block at `Phase::Ddos`.
- **AC#3** (pinned actor blocks via override): `state.is_pinned` → `decide(...,
  override_block=true)` (scorer.rs:258-260, threshold.rs:18-23). Sub-case c.
- **Monitor mode**: `apply_mode(... "risk_assessment" ...)` downgrades to LogOnly;
  `is_enforcement_allowed()` true (types.rs). Test `risk_block_respects_monitor_mode`.
- **Risk never overrides pipeline**: `matches!(decision.action, WafAction::Allow)`
  gate. Enforced and LogOnly'd SQLi both keep `Phase::SqlInjection`. Test
  `risk_never_overrides_pipeline_decisions`.

## Targeted concerns from the task — all cleared

- **Double-counting `risk_score`**: none. In the escalation branch the pre-set
  `decision.risk_score` (708) is discarded when `decision = risk_decision` (722);
  final score set exactly once at 721. Non-escalation branch keeps the 708 value.
- **`.min(100)` clamp**: redundant (`ScorerResult.score` is `u8` already clamped
  0..=100) but harmless; matches prior code. Not worth changing.
- **Scorer error path**: `let Ok(scorer_result) = ...` skips the whole block on
  `Err`; `decision.risk_score` stays at the pipeline default (0 for plain Allow).
  Behaviorally equivalent to the old `map_or(0, ...)`. No panic, no escalation on
  error (fail-open for risk only — safe, pipeline decision preserved).
- **`replace_risk_config` ordering / race**: canary `reload(paths)` +
  `set_ban_ttl_secs` run *before* `risk_cfg.store` (engine.rs:319-321). Analyzed
  against concurrent `inspect()`: the only transient window is old
  `cfg.canary.enabled` with new paths/ttl. Enabling (false→true): gate still off
  → new paths simply not yet active (safe delay). Disabling (true→false, paths
  cleared): `check_and_ban` on the empty set returns false (safe). Path-only
  change: transiently uses new paths, which is the desired end state. Effectively
  race-free; ordering is correct. Not a defect.

## Side-effect ordering — verified against pipeline

`send_audit_event` is called once at the end (engine.rs:725) with the FINAL
decision, so escalated risk blocks are audited correctly. In the escalation
branch `log_security_event` + `report_community_signal` fire after `apply_mode`
(718-720), which is exactly the detection-pipeline pattern (e.g. 879-880,
892-893) — including firing in monitor/LogOnly mode. Pipeline blocks
(`FastPath::Miss`, non-Allow action) skip the escalation gate, so there is no
double `log_security_event` and no double audit. Confirmed parity.

## Public contract

- `WafDecision` shape unchanged.
- `CanaryLayer::set_ban_ttl_secs` `&mut self` const fn → `&self` fn: source- and
  ABI-compatible for callers (calling `&self` on an owned/`Arc` value still
  works). Only external caller is `replace_risk_config`. `ban_ttl_secs()` /
  `ban_ttl_ms()` lost `const` — grepped all crates (waf-api, tests): no
  const-context use. No break.
- `ban_ttl_secs: AtomicU32` is a private field; struct is constructed only via
  the `new*`/`with_*` constructors, all updated. External test/API callers use
  the constructors and getters only. No break.

## Informational (non-blocking, no action required)

1. `make_risk_decision` collapses the non-Block case into the `_ =>` arm as
   Challenge. The caller gate guarantees action ∈ {Block, Challenge}, so `_` is
   always Challenge today. Slightly fragile if a future gate/variant drifts; an
   explicit `WafAction::Challenge` arm with `debug_assert!`/`unreachable!` on the
   remainder would make the invariant self-documenting. Style only.
2. In monitor mode a risk block still pushes a community-blocklist signal for a
   non-enforced decision. This is deliberate parity with every other detection
   phase (SQLi/OWASP/etc. behave identically), so it is a pre-existing design
   choice, not introduced here. Flagging only for awareness.
3. Docs sync in `crates/waf-engine/CLAUDE.md` matches the implemented behavior.

## Metrics

- Type/compile: `cargo check -p waf-engine --tests` clean.
- New tests: 4 inline `#[tokio::test]` (PG testcontainer / PG_TEST_URL pattern,
  same as existing `fast_path_exits_skip_risk_scoring`). Require Docker or
  PG_TEST_URL at runtime — execution-env dependency, not a code defect.
- Lint/fmt: reported clean by author; not re-run (unchanged since).

## Unresolved Questions

- None blocking. Confirm CI has Docker/PG_TEST_URL so the new testcontainer
  tests actually execute rather than silently being skipped/failing in a
  Docker-less runner.
