# Phase 10 — prx-waf binary (CLI parser + victoria_logs) → 35%

## Context Links
- Baseline: `plans/260509-1039-coverage-90/plan.md`
- Crate: `crates/prx-waf/`
- Existing: 1 inline test module, 0 integration test files.

## Overview
- **Priority:** P3 (binary entrypoint — capped target)
- **Status:** pending
- **Target:** **35% line** (baseline 5.85%) — **infeasible to reach 90%** for the reasons below.
- File ownership glob: `crates/prx-waf/**`

## Why 90% is infeasible (push-back)

`prx-waf/src/main.rs` is **1050 lines, 49 functions** of CLI dispatch + runtime bootstrap that:

1. **Spawns OS threads + tokio runtimes** for API server, HTTP/3 server, cluster node, Pingora — each blocks indefinitely.
2. **Loads + applies live config** from disk and environment — side-effectful.
3. **Writes to stdout/stderr** for CLI feedback.
4. **Calls `prx_waf::main()`-style code paths** that hand off to `gateway::WafProxy::start()` which never returns.

Standard binary-coverage strategies:

| Approach | Verdict |
|----------|---------|
| Refactor `main.rs` → expose `pub fn run_cli(args, stdout, deps) -> Result<...>` | **Recommended later — out of scope for this plan.** Requires touching the boot sequence which has implications for cluster timing, signal handling, and Pingora init order. |
| `assert_cmd` to spawn binary + assert exit code | Doable for `--help`, `migrate`, `seed-admin`, `rules list`, `cluster token`. Cannot test `run` (blocks). |
| Split `main.rs` into `lib.rs` + `bin/prx-waf.rs` | Same scope concern as full refactor. |

### Coverage realistically reachable

- `--help`, `--version`: ~30 lines (clap auto)
- `migrate` command: ~40 lines (DB-fixture-dependent, blocked on Phase 02)
- `seed-admin`: ~30 lines (Phase 02)
- `rules list/validate/reload`: ~80 lines (Phase 02 + tempdir rules)
- `cluster token generate`: ~25 lines (pure crypto)
- `crowdsec status`: ~30 lines (httpmock)
- `victoria_logs/installer.rs` (currently 36.51%): bring to 70% with tempdir + httpmock
- `victoria_logs/sidecar.rs` (currently 0%): supervisor loop with subprocess. Cover non-spawn paths only (config parse, error mapping). Realistic ceiling 30%.

**Total reachable:** ~ 35% line on the crate. Anything above requires the boot-sequence refactor flagged above.

## Requirements
- `assert_cmd` based smoke for: `--help`, `--version`, `migrate`, `seed-admin`, `rules list`, `cluster token generate`, `crowdsec status`.
- `victoria_logs/installer.rs`: download + extract + checksum (httpmock) → 70%.
- `victoria_logs/sidecar.rs`: config parse + error variants → 30%.

## Architecture
```
prx-waf/src/
├── main.rs                  ← 1050 lines. Cap: ~10% reachable (CLI dispatch only)
└── victoria_logs/
    ├── installer.rs         ← 36% → 70%
    ├── sidecar.rs           ← 0%  → 30%
    └── mod.rs               ← (not in tail summary)
```

## Related Code Files
**Modify (inline tests):**
- `crates/prx-waf/src/victoria_logs/installer.rs` — extract pure helpers (URL build, checksum verify, archive extract); cover.
- `crates/prx-waf/src/victoria_logs/sidecar.rs` — config parse, error mapping, retry-backoff math; cover pure parts.

**Create:**
- `crates/prx-waf/Cargo.toml` — add `[dev-dependencies] assert_cmd = "2"`, `predicates = "3"`, `httpmock = "0.7"`, `tempfile`.
- `crates/prx-waf/tests/cli_help_version.rs` — `--help`, `--version`, no-args (usage), invalid-subcommand (exit code 2).
- `crates/prx-waf/tests/cli_migrate_seed.rs` — depends on Phase 02 fixture; `migrate`, then `seed-admin`, then `seed-admin` again (idempotent).
- `crates/prx-waf/tests/cli_rules_subcmd.rs` — `rules list`, `rules validate <good.yaml>`, `rules validate <bad.yaml>` (non-zero exit + diagnostic).
- `crates/prx-waf/tests/cli_cluster_token.rs` — `cluster token generate --ttl 1h`, parse stdout; `cluster token generate --ttl invalid` (exit code).
- `crates/prx-waf/tests/cli_crowdsec_status.rs` — httpmock LAPI, `crowdsec status` reports up/down.
- `crates/prx-waf/tests/victoria_logs_installer.rs` — httpmock-backed download + checksum mismatch + extract to tempdir.
- `crates/prx-waf/tests/victoria_logs_sidecar.rs` — config parse + error variants only.

## Implementation Steps
1. Add dev-deps; verify `assert_cmd::Command::cargo_bin("prx-waf")` works against debug build.
2. `cli_help_version.rs`: assert exit 0 + stdout contains "prx-waf" / "Usage:".
3. `cli_migrate_seed.rs`: spin postgres via Phase 02 helper, write minimal config TOML to tempdir pointing at it, run `migrate`, assert exit 0; run `seed-admin`, assert admin row inserted; rerun `seed-admin`, assert idempotent (no error).
4. `cli_rules_subcmd.rs`: tempdir with rules/, run `rules list -c <cfg>`, assert N rules; `rules validate good.yaml` exit 0; bad.yaml exit non-zero.
5. `cli_cluster_token.rs`: run `cluster token generate --ttl 1h -c <cfg>`, parse base64 token, assert decodes.
6. `cli_crowdsec_status.rs`: httpmock `/v1/decisions/stream` returns 200 + JSON; assert "OK" in stdout.
7. `victoria_logs_installer.rs`: extract pure helpers (URL building per platform, sha256 verify, tar.gz unpack to tempdir); test each.
8. `victoria_logs_sidecar.rs`: cover config parse + error variants. DO NOT spawn real subprocess in tests.

## Todo List
- [ ] Dev-deps in `Cargo.toml`
- [ ] `tests/cli_help_version.rs`
- [ ] `tests/cli_migrate_seed.rs` (gated on Phase 02)
- [ ] `tests/cli_rules_subcmd.rs`
- [ ] `tests/cli_cluster_token.rs`
- [ ] `tests/cli_crowdsec_status.rs`
- [ ] `tests/victoria_logs_installer.rs`
- [ ] `tests/victoria_logs_sidecar.rs`
- [ ] Inline pure-helper tests in `victoria_logs/{installer,sidecar}.rs`
- [ ] `cargo llvm-cov -p prx-waf --summary-only` ≥ 35%
- [ ] No new file > 200 LOC

## Success Criteria
- ≥ 35% line crate-wide.
- `victoria_logs/installer.rs` ≥ 70%; `victoria_logs/sidecar.rs` ≥ 30%.
- Every CLI subcommand except `run` exercised with at least one happy + one error case.

## Risk Assessment
- **High**: Spawning the binary for each test is slow (~50ms × N). Mitigate with `assert_cmd::Command::cargo_bin` reuse.
- **Medium**: Tests depend on debug build artifact present — `cargo test` should build it automatically; verify in CI.
- **Low**: tarball / sha256 helpers are deterministic.

## Security Considerations
- Installer tests must verify checksum mismatch ABORTS — false-pass here = supply-chain risk.
- Token-gen tests: never log generated secrets to stdout in tests.
- CLI tests must NOT bind any real ports.

## Next Steps
- Recommend follow-up plan: refactor `main.rs` into `lib.rs` (`pub fn run(...)`) + thin `bin/`. That unlocks 80%+ for prx-waf. Out of scope for this coverage push.
