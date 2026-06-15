---
phase: 2
title: "TDD Engine ModeRegistry Wiring"
status: pending
priority: P0
effort: "2h"
dependencies: [1]
---

# Phase 2: TDD Engine ModeRegistry Wiring

## Overview

Wire `ModeRegistry` into `WafEngine` so the 5 mode-setting sites call `resolve(feature, policy)` instead of checking `host_config.log_only_mode` alone. Uses OnceLock setter pattern (same as audit_sender/geoip). ModeRegistry is Clone — `engine.set_mode_registry(state.mode_registry.clone())` shares the underlying ArcSwap. No AppState signature change.

## Requirements

- Functional: Engine calls `mode_registry.resolve()` at every decision point. Per-feature mode reflected in `WafDecision.mode` and downstream X-WAF-Mode header.
- Non-functional: Lock-free read via ArcSwap (already implemented in ModeRegistry). One small `format!()` allocation per resolve() with policy — accepted as negligible. Fallback to host_config when mode_registry not set.

## Architecture

```
main.rs
  ├── AppState { mode_registry: ModeRegistry }  ← unchanged
  ├── engine.set_mode_registry(state.mode_registry.clone())
  │     └── O(1) clone: ModeRegistry wraps Arc<ArcSwap<ModeState>>
  └── Both point to same ArcSwap — mutations visible to both

WafEngine
  ├── mode_registry: OnceLock<ModeRegistry>
  ├── set_mode_registry(&self, mr: ModeRegistry)
  └── apply_mode(&self, ctx, &mut decision, feature, policy)
        ├── mode_registry.get() → resolve(feature, policy)
        └── LogOnly from either registry or host_config wins
```

**5 mode-setting sites to update:**

| Site | Line | Current | New |
|------|------|---------|-----|
| `make_block_decision()` | ~830 | `host_config.log_only_mode` | Keep as safety net → remove after all callers use apply_mode |
| IP blacklist | ~648 | No mode check | `self.apply_mode()` with `access_control/ip_blacklist` |
| URL blacklist | ~662 | No mode check | `self.apply_mode()` with `access_control/url_blacklist` |
| Rate-limit special case | ~720 | `host_config.log_only_mode` | `self.apply_mode()` with `rate_limiting/per_ip` |
| Custom rules | ~778 | `host_config.log_only_mode` | `self.apply_mode()` with `custom_rules/None` (BEFORE `is_enforcement_allowed()`) |

**Two-step migration:** Keep `host_config.log_only_mode` check in `make_block_decision` while adding `apply_mode()` everywhere. Once all sites verified, remove the redundant check in a separate commit. This prevents silent enforcement regression if a site is missed.

**Approach:** Keep `make_block_decision` static (minimal diff). Add `apply_mode(&self, ...)` as a new instance method. Call after every decision creation point.

## Related Code Files

- Modify: `crates/waf-engine/src/engine.rs` — add field, setter, apply_mode, update call sites
- Unchanged: `crates/waf-api/src/state.rs` — ModeRegistry is Clone, no signature change
- Modify: `crates/prx-waf/src/main.rs` — add `engine.set_mode_registry(state.mode_registry.clone())` after AppState built
- Create: `crates/waf-engine/tests/engine_mode_registry.rs` — TDD tests
- Read: `crates/waf-engine/src/interop/mode_registry.rs` — resolve() API
- Read: `crates/waf-engine/src/interop/checker_feature_map.rs` — Phase 1 output

## Implementation Steps

### TDD: Write Tests First

1. Create `crates/waf-engine/tests/engine_mode_registry.rs`

2. Test `apply_mode_uses_registry_log_only` — construct engine with ModeRegistry where `injection_control` is LogOnly. Call `make_block_decision` + `apply_mode` with feature="injection_control". Assert `decision.mode == LogOnly`.

3. Test `apply_mode_uses_registry_enforce` — ModeRegistry default Enforce, host_config.log_only_mode=false. Assert `decision.mode == Enforce`.

4. Test `apply_mode_host_config_floor` — ModeRegistry says Enforce for a feature, but host_config.log_only_mode=true. Assert `decision.mode == LogOnly` (host floor wins).

5. Test `apply_mode_both_log_only` — both sources say LogOnly. Assert LogOnly.

6. Test `apply_mode_policy_level_override` — set policy "injection_control.sqli" to LogOnly while feature default is Enforce. Call with feature="injection_control", policy=Some("sqli"). Assert LogOnly.

7. Test `apply_mode_no_registry_fallback` — mode_registry OnceLock not set. Assert falls back to host_config behavior.

8. Test `apply_mode_default_log_only_feature_enforce` — set_all(LogOnly), then set_feature("injection_control", Enforce). Verify injection_control resolves to Enforce while bot_detection resolves to LogOnly. (Inversion case: quarantine everything except one feature.)

9. Run tests — should fail (apply_mode doesn't exist yet)

### Implement Engine Changes

10. Add field to `WafEngine` struct:
    ```rust
    mode_registry: OnceLock<ModeRegistry>,
    ```

11. Add to constructor's `Self { ... }`:
    ```rust
    mode_registry: OnceLock::new(),
    ```

12. Add setter method:
    ```rust
    pub fn set_mode_registry(&self, mr: ModeRegistry) {
        let _ = self.mode_registry.set(mr);
    }
    ```

13. Add `apply_mode` method:
    ```rust
    fn apply_mode(
        &self,
        ctx: &RequestCtx,
        decision: &mut WafDecision,
        feature: &str,
        policy: Option<&str>,
    ) {
        let log_only = if let Some(mr) = self.mode_registry.get() {
            mr.resolve(feature, policy) == InteropMode::LogOnly
        } else {
            false
        };
        if log_only || ctx.host_config.log_only_mode {
            decision.mode = InteropMode::LogOnly;
        }
    }
    ```

14. **DO NOT remove** `host_config.log_only_mode` from `make_block_decision()` yet — keep as safety net during migration.

15. Add `apply_mode()` to IP/URL blacklist sites in `inspect_pipeline` (~648, ~662). These call `WafDecision::block()` directly (NOT make_block_decision), so they currently have NO mode check at all:
    ```rust
    // IP blacklist (~648):
    let mut ip_blacklist = check_ip_blacklist(ctx, &self.store);
    self.apply_mode(ctx, &mut ip_blacklist, "access_control", Some("ip_blacklist"));

    // URL blacklist (~662):
    let mut url_bl = check_url_blacklist(ctx, &self.store);
    self.apply_mode(ctx, &mut url_bl, "access_control", Some("url_blacklist"));
    ```

16. Add `apply_mode()` to all `make_block_decision` call sites (10 sites). Capture phase before result is consumed:
    ```rust
    let phase = result.phase;
    let mut decision = Self::make_block_decision(ctx, &rule_name, result, 403);
    let (feat, pol) = phase_feature_identity(phase);
    self.apply_mode(ctx, &mut decision, feat, pol);
    ```

    **Sites** (in `inspect_pipeline`):
    - DDoS check (~674)
    - CrowdSec bouncer (~685)
    - Community blocklist (~696)
    - GeoIP (~704)
    - Checker loop non-RateLimit (~725)
    - SQLi (~737)
    - CrowdSec AppSec (~749)
    - OWASP (~794)
    - Sensitive (~803)
    - Anti-hotlink (~812)

17. Update rate-limit special case (~720):
    ```rust
    // Replace: if ctx.host_config.log_only_mode { d.mode = InteropMode::LogOnly; }
    // With:
    self.apply_mode(ctx, &mut d, "rate_limiting", Some("per_ip"));
    ```

18. Update custom rules (~778) — **MUST be before `is_enforcement_allowed()` check at ~786:**
    ```rust
    // Replace: if ctx.host_config.log_only_mode { decision.mode = InteropMode::LogOnly; }
    // With:
    self.apply_mode(ctx, &mut decision, "custom_rules", None);
    // Then: if !decision.is_enforcement_allowed() { return decision; }
    ```

19. Update checker pipeline loop (~711-732) — capture phase, use apply_mode:
    ```rust
    let phase = result.phase;
    let rule_name = result.rule_name.clone();
    let decision = if phase == Phase::RateLimit {
        let body = render_block_page(ctx, &rule_name);
        let mut d = WafDecision::rate_limit(429, Some(body), result);
        self.apply_mode(ctx, &mut d, "rate_limiting", Some("per_ip"));
        d
    } else {
        let mut d = Self::make_block_decision(ctx, &rule_name, result, 403);
        let (feat, pol) = phase_feature_identity(phase);
        self.apply_mode(ctx, &mut d, feat, pol);
        d
    };
    ```

### Wire ModeRegistry in main.rs

20. In `crates/prx-waf/src/main.rs` — after `AppState` is built (~1772), add:
    ```rust
    engine.set_mode_registry(api_state.mode_registry.clone());
    ```
    Also in `run_seed_admin` (~1033) after `AppState::new()`:
    ```rust
    engine.set_mode_registry(state.mode_registry.clone());
    ```
    **No AppState signature change** — ModeRegistry is Clone (wraps Arc<ArcSwap>).

### Remove Safety Net (separate commit)

21. After all sites verified with tests, remove the redundant `host_config.log_only_mode` check from `make_block_decision()` (~830-832). The function becomes a pure decision factory.

22. Grep verification: `grep -n "log_only_mode" crates/waf-engine/src/engine.rs` should return zero matches.

### Verify

23. Run `cargo check --workspace` — zero errors
24. Run `cargo test -p waf-engine` — all tests pass
25. Run `cargo fmt --all`
26. Run `cargo clippy --workspace` — zero warnings

## Success Criteria

- [ ] `WafEngine` holds `OnceLock<ModeRegistry>` (Clone, not Arc-wrapped)
- [ ] `apply_mode()` calls `mode_registry.resolve(feature, policy)`
- [ ] All 5 mode-setting sites updated (10 make_block_decision callers, 2 blacklist direct sites, rate-limit, custom rules)
- [ ] Custom rules: `apply_mode()` called BEFORE `is_enforcement_allowed()` check
- [ ] `host_config.log_only_mode` removed from `make_block_decision()` body (separate commit after all callers verified)
- [ ] AppState unchanged — `engine.set_mode_registry(state.mode_registry.clone())` in main.rs
- [ ] Fallback: if mode_registry OnceLock not set, host_config behavior preserved
- [ ] `cargo check --workspace` passes
- [ ] All TDD tests pass
- [ ] No clippy warnings

## Risk Assessment

- **Medium risk:** 14 call sites updated in engine.rs. Each is mechanical (add 2 lines after decision creation) but volume increases chance of missing one.
  - **Mitigation:** Two-step migration — keep `log_only_mode` in `make_block_decision` as safety net, add `apply_mode()` everywhere, then remove. Grep for remaining `log_only_mode` after changes.
- **Low risk:** main.rs change is one line per construction site (2 total). No AppState signature change.
- **Edge case:** Checkers in `self.checkers` vec share a loop — `result.phase` must be captured before `result` moves into `make_block_decision`. Handled in step 19.
- **Edge case:** IP/URL blacklist create decisions without `make_block_decision` — these have NO mode check today (pre-existing gap). Fixed by explicit `apply_mode()` calls in step 15.
- **Note:** `resolve()` allocates a `String` via `format!("{feature}.{policy}")` on every call with a policy. Acceptable for ArcSwap hot-path (~nanosecond HashMap lookup). Not zero-alloc but negligible.
