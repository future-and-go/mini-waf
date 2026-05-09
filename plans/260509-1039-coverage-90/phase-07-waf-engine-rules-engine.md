# Phase 07 — waf-engine: `engine.rs`, `checker.rs`, `block_page.rs`, `rules/manager.rs`, `rules/hot_reload.rs` → 85%

## Context Links
- Baseline: `plans/260509-1039-coverage-90/plan.md`
- Crate: `crates/waf-engine/`
- Existing: `rule_engine_acceptance.rs`, `custom_rule_*.rs`. Inline tests in `rules/registry.rs` (99.79%), `rules/sources.rs` (100%), `rules/builtin/*` (100%).
- **Depends on Phase 02 (waf-storage)** — `engine.rs` and `checker.rs` need `Database`.

## Overview
- **Priority:** P2
- **Status:** pending (BLOCKED on Phase 02)
- **Target:** 85% line for these 5 files combined
- File ownership glob: exact files listed (no other phase touches these); plus new `crates/waf-engine/tests/engine_*.rs` and `crates/waf-engine/tests/rules_manager_*.rs`.

## Key Insights
- `engine.rs` (961 regions, **0%**) — the WafEngine builder + `evaluate()` orchestrator. Wires every check; needs `Database` + a real config + a sample request. Highest-leverage gap in the workspace.
- `checker.rs` (covered as part of `RuleStore`) — IP/URL whitelist/blacklist matchers; not in workspace tail summary, MUST verify baseline first.
- `block_page.rs` (not in tail) — HTML rendering for blocked responses; pure templating, easy.
- `rules/manager.rs` (810 regions, 67.65%) — file watcher + multi-format parser orchestrator. Hot-path with notify and tokio.
- `rules/hot_reload.rs` (135 regions, 71.11%) — watcher state machine.

## Requirements
- `WafEngine::new` with various configs (rules enabled/disabled, DDoS on/off, RL on/off, tx_velocity on/off).
- `WafEngine::evaluate(RequestCtx)` for: clean request → Allow; SQLi payload → Block; banned IP → Block; rate-limited → Block; whitelisted IP → bypass.
- Hot-reload: write rule YAML to tempdir, signal reload, assert new rule active.
- Block page: every variant (403, 429, 451 challenge) renders with attack metadata.
- `RuleStore::reload_all`: loads from DB, verifies counts, atomic-swap correctness.

## Architecture
```
waf-engine/src/
├── engine.rs            ← 961 regions, 0% — biggest single win
├── checker.rs           ← RuleStore + check_ip/url
├── block_page.rs        ← HTML render
└── rules/
    ├── manager.rs       ← 810 regions, 67% — file watcher + parser dispatch
    └── hot_reload.rs    ← 135 regions, 71% — debounce state
```

## Related Code Files
**Modify (inline tests):**
- `crates/waf-engine/src/block_page.rs` — every variant
- `crates/waf-engine/src/rules/hot_reload.rs` — debounce edge cases
- `crates/waf-engine/src/rules/manager.rs` — extend existing inline; add format-dispatch + error-isolation tests

**Create:**
- `crates/waf-engine/tests/engine_lifecycle.rs` — `WafEngine::new` matrix (with/without each subsystem). ≤ 200 LOC.
- `crates/waf-engine/tests/engine_evaluate_clean.rs` — clean GET, clean POST, OPTIONS, large body within limits → Allow.
- `crates/waf-engine/tests/engine_evaluate_attack.rs` — SQLi, XSS, RCE, traversal, scanner UA → Block with correct rule_id.
- `crates/waf-engine/tests/engine_evaluate_lists.rs` — IP whitelist bypasses; IP blacklist blocks; URL allowlist bypasses; URL blocklist blocks.
- `crates/waf-engine/tests/engine_evaluate_rate_limit.rs` — burst floods, tier policy enforcement.
- `crates/waf-engine/tests/checker_rule_store.rs` — `RuleStore::reload_all`, atomic swap correctness, snapshot consistency under concurrent reads.
- `crates/waf-engine/tests/rules_manager_format_dispatch.rs` — load mixed YAML+JSON+ModSec dirs; per-file error isolation; stale rules cleared.
- `crates/waf-engine/tests/rules_hot_reload_state.rs` — file write → debounce → reload exactly once; rapid writes coalesce.

## Implementation Steps
1. Verify baseline: `cargo llvm-cov -p waf-engine --summary-only | grep -E '(engine\.rs|checker\.rs|block_page\.rs|manager\.rs|hot_reload\.rs)'`. Record per-file %.
2. Build `tests/common/engine_fixture.rs` (≤120 LOC) returning `(Database, WafEngine, AppConfig)` using Phase 02 `start_postgres()` + minimal config.
3. `engine_lifecycle.rs`: build engine with each subsystem permutation; assert no panic; assert correct subsystem instances present.
4. `engine_evaluate_clean.rs`: synthesise `RequestCtx` with `RequestCtx::new(...)` — clean GET → `WafDecision::Allow`. Cover: empty body, small body, JSON body, multipart.
5. `engine_evaluate_attack.rs`: feed payloads from `rules/owasp-crs/` test fixtures (or inline known-malicious literals) → assert `WafDecision::Block { rule_id: ... }`.
6. `engine_evaluate_lists.rs`: insert IP/URL via `Database`, call `RuleStore::reload_all`, then evaluate → expected outcome.
7. `engine_evaluate_rate_limit.rs`: burst N requests above tier capacity → first M Allow, rest Block.
8. `checker_rule_store.rs`: pre-populate DB with 1000 IPs/URLs, call `reload_all`, assert counts match. Spawn N readers + 1 reload concurrently → no inconsistencies.
9. `rules_manager_format_dispatch.rs`: tempdir with mixed-format files (1 valid YAML, 1 invalid YAML, 1 valid JSON, 1 unknown ext) → expect 2 loaded, 1 logged-error, 1 ignored. Stale rules: load A, delete A, reload → A absent.
10. `rules_hot_reload_state.rs`: write 5 files in 100ms → exactly 1 reload after debounce window. Touch unchanged file → no reload.
11. `block_page.rs` inline: render each template; assert HTML contains attack rule_id, client_ip, request_id (for forensics); assert no XSS via attacker-supplied data (escape!).

## Todo List
- [ ] Capture baseline % for all 5 files
- [ ] `tests/common/engine_fixture.rs`
- [ ] `tests/engine_lifecycle.rs`
- [ ] `tests/engine_evaluate_clean.rs`
- [ ] `tests/engine_evaluate_attack.rs`
- [ ] `tests/engine_evaluate_lists.rs`
- [ ] `tests/engine_evaluate_rate_limit.rs`
- [ ] `tests/checker_rule_store.rs`
- [ ] `tests/rules_manager_format_dispatch.rs`
- [ ] `tests/rules_hot_reload_state.rs`
- [ ] Inline tests for `block_page.rs` (every template variant + XSS-safe assertion)
- [ ] Inline mop-up for `rules/hot_reload.rs` debounce edge cases
- [ ] Combined coverage of 5 owned files ≥ 85%
- [ ] `engine.rs` specifically ≥ 75% (lower bound — orchestrator has many seldom-used branches)

## Success Criteria
- Combined ≥ 85% line; `engine.rs` ≥ 75%; `block_page.rs` ≥ 95%.
- All new test files compile + pass under `cargo test -p waf-engine --no-fail-fast`.
- No flake on 5x rerun.

## Risk Assessment
- **High**: `engine.rs` orchestrates many subsystems. Construction errors → test compile failures cascade. Mitigate by building one subsystem at a time.
- **Medium**: Hot-reload tests may be timing-sensitive on slow CI. Use existing patterns from `access_hot_reload.rs` (proven).
- **Medium**: `block_page.rs` HTML assertions can be brittle to template churn. Match on stable identifiers (CSS class, data-* attrs), not full HTML.
- **Low**: Block-page XSS assertions trivially expose injection bugs.

## Security Considerations
- `block_page.rs`: every attacker-controlled field (URI, UA, IP) MUST be HTML-escaped before render. Add explicit `<script>` payload tests asserting escape.
- `RuleStore::reload_all` concurrent test: no torn reads; assert reader sees pre- or post- snapshot, never partial.

## Next Steps
- Once `engine.rs` is testable, Phase 06 + 08 can use the `engine_fixture` for end-to-end checks too.
