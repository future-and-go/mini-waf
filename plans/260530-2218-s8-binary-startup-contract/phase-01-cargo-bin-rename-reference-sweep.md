---
phase: 1
title: "Cargo bin rename + reference sweep"
status: pending
priority: P1
effort: "0.5d"
dependencies: []
---

# Phase 1: Cargo bin rename + reference sweep

## Overview

Rename the Cargo `[[bin]]` output from `prx-waf` to `waf`, then sweep every reference to `target/release/prx-waf` (and `/usr/local/bin/prx-waf`) in the repo and update each one. The crate name stays `prx-waf` — only the binary filename changes. Self-test: after this phase `cargo build --release -p prx-waf` produces `target/release/waf`, not `target/release/prx-waf`.

## Context Links

- Contract §8: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 504–528
- Gap report §8: `plans/reports/contract-gap-analysis-260527-1133-waf-interop-v23-report.md` lines 113–124
- Current bin definition: `crates/prx-waf/Cargo.toml:7-9`
- Release pipeline that ALREADY rename-after-build today: `.github/workflows/release.yaml:108-112`

## Reference Inventory (grep-verified)

Files that reference the binary by path and must be updated:

| File | Lines | Current | Notes |
|---|---|---|---|
| `crates/prx-waf/Cargo.toml` | 7–9 | `[[bin]] name = "prx-waf" / path = "src/main.rs"` | The change. Flip `name` only. |
| `Dockerfile` | 61 | `cargo build --release --features … -p prx-waf` | `-p prx-waf` is the crate flag — keep |
| `Dockerfile` | 80 | `COPY --from=builder /build/target/release/prx-waf /usr/local/bin/prx-waf` | Update both source and dest paths |
| `Dockerfile` | 94 | `RUN chmod +x /usr/local/bin/prx-waf` | Update dest path |
| `Dockerfile` | 102 | `CMD ["/usr/local/bin/prx-waf", "--config", "/app/configs/default.toml", "run"]` | Update path |
| `Dockerfile.prebuilt` | 11 | `COPY target/release/prx-waf /usr/local/bin/prx-waf` | Update both paths |
| `Dockerfile.prebuilt` | 18 | `RUN chmod +x /usr/local/bin/prx-waf` | Update path |
| `Dockerfile.prebuilt` | 25 | `CMD ["/usr/local/bin/prx-waf", ...]` | Update path |
| `prx-waf.service` | 12 | `ExecStart=/usr/local/bin/prx-waf --config /etc/prx-waf/config.toml run` | Update binary path; leave systemd unit/user/dirs as `prx-waf` |
| `.github/workflows/release.yaml` | 110–112 | `install -m 0755 target/release/prx-waf "$STAGE/waf"` | **Simplify:** binary IS `waf` now → `install -m 0755 target/release/waf "$STAGE/waf"` (or drop the rename comment) |
| `.github/workflows/release.yaml` | 103 | `cargo build --release --locked --features gateway/valkey -p prx-waf` | Keep — `-p` flag uses crate name |
| `.github/workflows/deploy-cluster.yml` | 77–93 | `cargo build --release -p prx-waf` (keep); `target/release/prx-waf` → S3 (update) | One path update |
| `.github/workflows/nightly-e2e.yml`, `coverage.yml`, `scripts/deploy-on-vm.sh` | grep | TBD per file | Confirm whether they touch the binary path or only the crate flag |
| `tests/e2e/docker-compose.e2e.yml`, `tests/e2e-cluster.sh`, `tests/e2e/cluster-override.yml`, `tests/e2e/circuit-breaker/docker-compose.yml`, `tests/e2e/README.md` | grep | TBD per file | Likely container_name or volume only; verify per file |
| `scripts/ec2-install-gh-runner.sh` | grep | TBD | Probably runner labels, not binary |

**Untouched (intentional):**
- `crates/prx-waf/` directory name — crate rename is out of scope.
- `crates/prx-waf/CLAUDE.md`, top-level docs that describe the crate by name.
- `docker-compose.yml` `container_name: prx-waf` — container labels, not binary path.
- `prx-waf.service` `User=prx-waf` / `Group=prx-waf` / `WorkingDirectory=/opt/prx-waf` / `EnvironmentFile=/etc/prx-waf/env` — OS-level identifiers, not binary path.
- `release-manifest.json` — generated artifact; will refresh on next release.
- All `prx-waf` strings inside Rust source (struct names, log messages) — internal.

## Architecture

Single line change to the Cargo manifest cascades binary-filename updates across deployment artifacts. No code logic changes. Crate name (`prx-waf`) stays the dependency identifier so `-p prx-waf` still selects this crate in workspace commands.

```
Cargo.toml [[bin]] name "prx-waf" → "waf"
                |
                └→ cargo build emits target/release/waf
                     |
                     ├→ Dockerfile copies it to /usr/local/bin/waf
                     ├→ Dockerfile.prebuilt copies it to /usr/local/bin/waf
                     ├→ prx-waf.service ExecStart=/usr/local/bin/waf …
                     └→ release.yaml installs target/release/waf as $STAGE/waf
                          (no post-build rename step needed anymore)
```

## Related Code Files

**Modify (mandatory):**
- `crates/prx-waf/Cargo.toml`
- `Dockerfile`
- `Dockerfile.prebuilt`
- `prx-waf.service`
- `.github/workflows/release.yaml`
- `.github/workflows/deploy-cluster.yml`

**Inspect-then-modify-if-referenced:**
- `.github/workflows/nightly-e2e.yml`
- `.github/workflows/coverage.yml`
- `.github/workflows/scripts/deploy-on-vm.sh`
- `tests/e2e/docker-compose.e2e.yml`
- `tests/e2e-cluster.sh`
- `tests/e2e/cluster-override.yml`
- `tests/e2e/circuit-breaker/docker-compose.yml`
- `tests/e2e/README.md`
- `scripts/ec2-install-gh-runner.sh`

**Untouched:**
- Crate `Cargo.toml` `name = "prx-waf"` (package name)
- Rust source files
- `docker-compose.yml` container names

## Implementation Steps

1. **Sweep first, change second.** Run the authoritative grep — record the exact line numbers per file:
   ```sh
   rg -n --no-heading "target/release/prx-waf|/usr/local/bin/prx-waf|/bin/prx-waf" \
     --glob '!vendor/**' --glob '!target/**' .
   ```
   Cross-check against the inventory table. Any file outside the table is a new finding — add it before editing.

2. **Flip the Cargo bin name.** Edit `crates/prx-waf/Cargo.toml`:
   ```toml
   [[bin]]
   name = "waf"
   path = "src/main.rs"
   ```
   `cargo check --workspace` — must pass cleanly. `cargo build --release -p prx-waf` — confirm `target/release/waf` appears, `target/release/prx-waf` does not.

3. **Update Dockerfile.** Replace each `prx-waf` binary-path occurrence with `waf`:
   - Line 80: `COPY --from=builder /build/target/release/waf /usr/local/bin/waf`
   - Line 94: `RUN chmod +x /usr/local/bin/waf`
   - Line 102: `CMD ["/usr/local/bin/waf", "--config", "/app/configs/default.toml", "run"]`
   - Leave the `-p prx-waf` build flag on line 61 untouched.

4. **Update Dockerfile.prebuilt** mirroring lines 11/18/25.

5. **Update prx-waf.service** line 12 `ExecStart=/usr/local/bin/waf --config /etc/prx-waf/config.toml run`. Do NOT change `User`/`Group`/`WorkingDirectory`/`EnvironmentFile` (those are OS identifiers, not binary paths).

6. **Update release.yaml.** Simplify lines 108–112:
   ```yaml
   - name: Stage release tree
     run: |
       install -m 0755 target/release/waf "$STAGE/waf"
       # … rest unchanged
   ```
   Drop the now-stale comment about renaming `prx-waf` → `waf`.

7. **Update deploy-cluster.yml** line 93: `aws s3 cp target/release/waf "s3://${BUCKET}/${KEY}"` (and `KEY="releases/${GITHUB_SHA}/waf"`). Keep `-p prx-waf` on line 78.

8. **Inspect the "modify-if-referenced" files.** For each, grep for `prx-waf` and decide:
   - Binary path? → update.
   - Container name / volume / user / runner label / crate flag (`-p prx-waf`)? → leave.
   Document the per-file decision in the PR description.

9. **Verify the build artifact name.** From a clean tree:
   ```sh
   cargo clean -p prx-waf
   cargo build --release -p prx-waf
   test -x target/release/waf && ! test -e target/release/prx-waf
   ```

10. **Pre-push formatting.** Per `CLAUDE.md` Pre-Push Formatting rule: `cargo fmt --all` then `cargo fmt --all -- --check`. No code lines edited in this phase, so should be no-op — verify.

## Success Criteria

- [ ] `cargo build --release -p prx-waf` produces `target/release/waf`
- [ ] `target/release/prx-waf` does not exist after a clean build
- [ ] `cargo check --workspace` passes
- [ ] `rg "target/release/prx-waf|/usr/local/bin/prx-waf"` returns zero hits outside `vendor/`, `target/`, generated files, and historical CHANGELOG/journal entries
- [ ] Dockerfile builds without error (verify in CI; full image build acceptable as this phase invalidates the cache)
- [ ] release.yaml workflow_dispatch dry-run produces a staged tree where `$STAGE/waf` exists

## Risk Assessment

| Risk | Likelihood | Mitigation |
|---|---|---|
| Missed reference in a CI script causes deploy failure | Medium | Authoritative grep in Step 1; PR description lists every file inspected with verdict |
| Docker layer cache invalidation forces full rebuild on every developer | High one-time | Acceptable; document in commit message |
| Operator scripts in `/etc/prx-waf/` env files reference binary path | Low | Out of repo; flag in CHANGELOG that operators must update systemd ExecStart |
| Release artifact name change confuses downstream consumers (S3 keys, etc.) | Low | KEY pattern still ends in `/waf` after the change; no consumer-visible change |
