# Phase 06 — waf-engine: `checks/` + `access/` → 90%

## Context Links
- Baseline: `plans/260509-1039-coverage-90/plan.md`
- Crate: `crates/waf-engine/`
- Existing acceptance suites: `sql_injection_acceptance.rs`, `ddos_*.rs`, `tx_velocity_integration.rs`, `relay_*.rs`, `access_*.rs`, `behavior_*.rs`, `custom_rule_*.rs`, `rule_engine_acceptance.rs`.

## Overview
- **Priority:** P2
- **Status:** pending
- **Target:** 90% line for these submodules combined
- File ownership glob: `crates/waf-engine/src/{checks,access}/**` AND `crates/waf-engine/tests/{checks,access}_*` (new test files prefixed `checks_` or `access_`)

## Key Insights
- `access/` already heavily covered by `access_hot_reload.rs` + `access_reload_under_load.rs`.
- `checks/` is the largest submodule (12 151 LOC, 55 files) — splits into:
  - `ddos/`, `rate_limit/`, `tx_velocity/` already have soak/proptest/integration → mop-up only
  - `sql_injection*` (3 files) — 63+ acceptance tests → already strong
  - `xss.rs`, `rce.rs`, `dir_traversal.rs`, `scanner.rs`, `bot.rs`, `sensitive.rs`, `anti_hotlink.rs`, `geo.rs`, `owasp.rs` — likely have some inline; need mop-up
- Baseline for these submodules NOT visible in workspace summary tail (truncated). **Owner MUST first run** `cargo llvm-cov -p waf-engine --summary-only` and grep for `checks/` and `access/` paths to identify exact gaps.

## Requirements
- Per-check public `fn check_*` invoked at least once happy + once attack + once edge (empty input, oversized input).
- Hot-reload paths: load valid config, mutate file, observe ArcSwap snapshot change.
- Action executors (DDoS ban, rate-limit deny) cover: store success, store error → fail-mode dispatch.

## Architecture
```
waf-engine/src/
├── access/                       (1151 LOC, 6 files)
│   ├── trie.rs                   ← Patricia IP trie
│   ├── lists.rs                  ← AccessLists facade
│   └── … (mod, config, reload)
└── checks/                       (12151 LOC, 55 files)
    ├── ddos/                     ← already strong (soak/proptest)
    ├── rate_limit/               ← already strong (memory + redis + breaker)
    ├── tx_velocity/              ← already strong
    ├── sql_injection*            ← 63+ ACs
    ├── xss.rs                    ← libinjection + regex
    ├── rce.rs
    ├── dir_traversal.rs
    ├── scanner.rs
    ├── bot.rs
    ├── sensitive.rs              ← Aho-Corasick
    ├── anti_hotlink.rs
    ├── geo.rs
    ├── owasp.rs
    └── mod.rs                    ← Check trait + registry
```

## Related Code Files
**Modify (inline tests):** all gap files identified by step 1 below.

**Create (only as needed; prefer extending inline + existing tests files):**
- `crates/waf-engine/tests/checks_xss_edge_cases.rs` — encoding bypass, oversized input
- `crates/waf-engine/tests/checks_rce_acceptance.rs` — shell metacharacter matrix
- `crates/waf-engine/tests/checks_dir_traversal.rs` — encoded `..`, double-encoded
- `crates/waf-engine/tests/checks_scanner_fingerprints.rs` — UA matrix (Nmap, Nikto, sqlmap, masscan)
- `crates/waf-engine/tests/checks_bot_detection.rs` — headless markers, missing UA
- `crates/waf-engine/tests/checks_sensitive_aho_corasick.rs` — overlap, case, partial
- `crates/waf-engine/tests/checks_anti_hotlink.rs` — referer present/missing/whitelisted
- `crates/waf-engine/tests/checks_geo_block_allow.rs`
- `crates/waf-engine/tests/checks_owasp_crs_loaded.rs`
- `crates/waf-engine/tests/checks_registry_dispatch.rs` — Check trait registration order
- `crates/waf-engine/tests/access_lists_corner.rs` — empty list, IPv4-mapped-IPv6, /0 wildcard

## Implementation Steps
1. Run `cargo llvm-cov -p waf-engine --summary-only --ignore-filename-regex 'vendor/|target/'`. Pipe through `grep -E 'checks/|access/'`. Write the per-file %s into a scratch list. **Pick lowest-coverage files first.**
2. For each gap file:
   - Identify each `pub fn` and each match arm.
   - If logic is pure (no IO, no time): add inline `#[cfg(test)] mod tests`.
   - If logic spans state (recorder, store): create dedicated `tests/checks_<name>.rs`.
3. **DO NOT mock libinjection / aho-corasick / regex** — feed real inputs.
4. For `mod.rs` (Check registry): assert `register_default_checks()` returns expected count + ordering.
5. For action executors (DDoS ban, RL deny): use `MockClock` from `ddos/detector/clock.rs` (already exists, not a business-logic mock — it's a clock seam) + `MemoryCounterStore`. Trigger ban → assert `IpTable` entry with TTL.
6. Hot-reload tests: write YAML → notify → wait on `ArcSwap` change with bounded timeout (use existing patterns from `access_hot_reload.rs`).
7. Re-measure and iterate until `checks/` + `access/` average ≥ 90%.

## Todo List
- [ ] Run baseline grep, document per-file %.
- [ ] Mop-up inline tests in any `checks/*.rs` < 80%.
- [ ] `tests/checks_xss_edge_cases.rs` (≤200 LOC)
- [ ] `tests/checks_rce_acceptance.rs`
- [ ] `tests/checks_dir_traversal.rs`
- [ ] `tests/checks_scanner_fingerprints.rs`
- [ ] `tests/checks_bot_detection.rs`
- [ ] `tests/checks_sensitive_aho_corasick.rs`
- [ ] `tests/checks_anti_hotlink.rs`
- [ ] `tests/checks_geo_block_allow.rs`
- [ ] `tests/checks_owasp_crs_loaded.rs`
- [ ] `tests/checks_registry_dispatch.rs`
- [ ] `tests/access_lists_corner.rs` (Patricia trie edge cases)
- [ ] Combined `checks/` + `access/` ≥ 90%
- [ ] `cargo check --tests -p waf-engine` clean
- [ ] No new file > 200 LOC

## Success Criteria
- Combined coverage of `checks/` + `access/` ≥ 90% line.
- Each individual file in scope ≥ 80%.
- Existing acceptance suites still pass.

## Risk Assessment
- **Medium**: 55 files × varying state seams. Time-budget risk; prioritize lowest-% first.
- **Low**: Deterministic logic; no flake risk.

## Security Considerations
- All attack-payload tests must verify **detection** (not just no-panic). False-negative regressions are worse than false-positive regressions.
- Pattern files must NOT include real CVE payloads beyond what's in `rules/`.

## Next Steps
- Phase 07 owner needs to coordinate on shared `engine.rs` test seams (they own `engine.rs`, you own `checks/`).
