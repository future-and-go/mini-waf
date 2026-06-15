---
phase: 7
title: "rate-limit / tx-velocity / ddos"
status: pending
effort: "1d"
priority: P1
dependencies: [3]
---

# Phase 7: rate-limit / tx-velocity / ddos

## Overview

Three modules with the same migration shape — no admin API (server-side edit only) — bundled into one phase because the per-module work is small and the pattern is already proven by Phases 3–6. Same TDD discipline applied three times.

| Module | Root key | Notable shape |
|--------|----------|---------------|
| `rate_limit` | `rate_limit:` | `[rate_limit.tiers.{critical,high,medium,catch_all}]` four sub-tables |
| `tx_velocity` | `tx_velocity:` | `endpoint_roles:` sequence → `[[tx_velocity.endpoint_roles]]`; nested `[tx_velocity.classifiers.{sequence,withdrawal_velocity,limit_change_velocity}]` |
| `ddos` | (none — root level) | `[per_ip]`, `[per_fingerprint]`, `ban_durations_secs = [60, 300, 3600]`, `[store]` |

## Requirements

- Functional: All three `from_path` calls switch to `toml::from_str`.
- Functional: Three new `.toml` files ship, hand-translated with comments.
- Functional: Three `.yaml` files deleted.

## Related Code Files

### rate-limit
- Modify: `crates/waf-engine/src/checks/rate_limit/config.rs`
- Modify: `crates/waf-engine/src/checks/rate_limit/reload.rs`
- Modify: `crates/waf-common/src/config.rs` (doc comment lines 39 + 53 — `rate-limit.yaml` references)
- Modify: `crates/waf-engine/src/engine.rs` (doc comments for rate-limit, tx-velocity, ddos paths)
- Create: `configs/rate-limit.toml`
- Delete: `configs/rate-limit.yaml`

### tx-velocity
- Modify: `crates/waf-engine/src/checks/tx_velocity/config.rs`
- Modify: `crates/waf-engine/tests/checks_tx_velocity_reload.rs`
- Create: `configs/tx-velocity.toml`
- Delete: `configs/tx-velocity.yaml`

### ddos
- Modify: `crates/waf-engine/src/checks/ddos/config.rs`
- Modify: `crates/waf-engine/src/checks/ddos/reload.rs`
- Modify: `crates/waf-engine/src/checks/ddos/mod.rs` (doc comment)
- Modify: `crates/waf-api/src/ddos_api.rs` (codec, path)
- Create: `configs/ddos.toml`
- Delete: `configs/ddos.yaml`

## Implementation Steps

Apply per-module loop (3× iterations):

1. **rate-limit:**
   - Rewrite all `r#"rate_limit:..."#` fixtures in `config.rs::tests` to TOML.
   - Tier blocks → `[rate_limit.tiers.critical]`, etc.
   - Swap `from_yaml_str` (existing public name) → `from_toml_str` AND keep an internal `from_path` that dispatches. Or just rename and audit callers.
   - Hand-write `configs/rate-limit.toml`.
   - Tests: `cargo test -p waf-engine rate_limit::` + `cargo test -p waf-engine --test '*' rate_limit`.

2. **tx-velocity:**
   - Rewrite `tests/checks_tx_velocity_reload.rs` + inline tests.
   - `endpoint_roles:` sequence → `[[tx_velocity.endpoint_roles]]` blocks.
   - `[tx_velocity.classifiers]` parent table; child tables `[tx_velocity.classifiers.sequence]`, `.withdrawal_velocity`, `.limit_change_velocity`.
   - Swap parser.
   - Hand-write `configs/tx-velocity.toml`.
   - Tests: `cargo test -p waf-engine tx_velocity::` + `tests/checks_tx_velocity_reload`.

3. **ddos:**
   - Rewrite `ddos/config.rs::tests` + `ddos/reload.rs::tests`.
   - Root level (no wrapper) — `enabled = true` first, then `[per_ip]`, `[per_fingerprint]`, then `ban_durations_secs = [60, 300, 3600]`, then `[store]`. (Scalar arrays must precede tables.)
   - Swap parser.
   - Hand-write `configs/ddos.toml`.
   - Update `ddos_api.rs` (codec + path).
   - Tests: `cargo test -p waf-engine ddos::` + `cargo test -p waf-api ddos`.

After all three modules:
```bash
cargo check --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

## Todo List

- [ ] rate-limit: tests rewritten, parser swapped, `.toml` shipped, `.yaml` deleted
- [ ] tx-velocity: tests rewritten, parser swapped, `.toml` shipped, `.yaml` deleted
- [ ] ddos: tests rewritten, parser swapped, `.toml` shipped, `.yaml` deleted
- [ ] `waf-common/src/config.rs` doc references updated
- [ ] `engine.rs` doc references updated
- [ ] `ddos_api.rs` codec + path swap
- [ ] All three modules' tests green
- [ ] Workspace clippy + fmt clean

## Success Criteria

- [ ] `cargo test --workspace` green
- [ ] No `configs/*.yaml` for these three modules left in the tree
- [ ] Live boot: `cargo run -- -c configs/default.toml run` starts; hot-reload touching each `.toml` works

## Risk Assessment

- **Risk:** `from_yaml_str` is a public API on `RateLimitFileConfig` — renaming breaks downstream. **Mitigation:** Check callers via `grep -rn from_yaml_str crates/`; rename if no external dependency or add a thin `pub fn from_yaml_str` that returns an error directing to the new name (cleaner: just rename — this is a hard cutover).
- **Risk:** `engine.rs` test references YAML paths across multiple methods. **Mitigation:** `grep -n "yaml\|yml" crates/waf-engine/src/engine.rs` audit before this phase, fix in one go.
- **Risk:** Three modules in one phase = larger blast radius if one parser swap breaks. **Mitigation:** Commit per-module so bisect is clean; final phase commit only after all three are green.
