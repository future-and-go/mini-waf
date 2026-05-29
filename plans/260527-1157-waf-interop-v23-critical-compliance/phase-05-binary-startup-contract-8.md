---
phase: 5
title: "Binary Startup Contract (§8)"
status: pending
priority: P2
effort: "0.5d"
dependencies: [3]
---

# Phase 5: Binary Startup Contract (§8)

## Overview

Make the binary discoverable as `./waf` with `./waf run` startup. Uses a wrapper script + config auto-discovery — no rename of the actual Cargo binary `prx-waf`, preserving CI/Docker/systemd compatibility.

## Context Links

- Contract §8: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 504–528
- Gap report §8: `plans/reports/contract-gap-analysis-260527-1133-waf-interop-v23-report.md` lines 113–122
- Binary entry: `crates/prx-waf/src/main.rs`
- Current config: `configs/default.toml`
- Cargo.toml binary name: `crates/prx-waf/Cargo.toml`

## Requirements

**Contract §8 binary expectations:**

| Requirement | Current State | Solution |
|-------------|--------------|----------|
| Binary at `./waf` | `./target/release/prx-waf` | Wrapper script at repo root |
| Start: `./waf run` | `prx-waf -c configs/default.toml run` | Auto-discover config |
| Config: `./waf.yaml` or `./waf.toml` | `configs/default.toml` | Fallback config search path |
| Logs: `./waf_audit.log` | VictoriaLogs (primary) + JSONL interop (secondary) | Phase 3 handles JSONL; VictoriaLogs unchanged |
| Health endpoint polled on startup | `GET /health` on port 9527 | Already works |

**Non-functional:**
- Existing `prx-waf -c configs/default.toml run` command MUST continue working
- Docker/systemd deployments unaffected
- Wrapper script is POSIX shell (no bash-isms)

## Architecture

### Two-Pronged Approach

**1. Config auto-discovery in the binary itself:**

When `-c` flag is not provided, the binary searches for config in order:
1. `./waf.toml` (CWD)
2. `./waf.yaml` (CWD) — parse YAML → convert to TOML internally
3. `./configs/default.toml` (existing default)
4. Error if none found

**2. Wrapper script `./waf`:**

```sh
#!/bin/sh
exec ./target/release/prx-waf "$@"
```

For release/benchmark distribution, the build step copies `target/release/prx-waf` to `./waf`:
```makefile
release:
    cargo build --release
    cp target/release/prx-waf ./waf
    chmod +x ./waf
```

### Config File Symlink/Copy

For the benchmark, provide a `waf.toml` in the repo root that's either:
- A symlink to `configs/default.toml`
- A benchmark-specific config with the right ports and audit log path

## Related Code Files

**Create:**
- `waf` — POSIX shell wrapper script at repo root (3 lines)
- `Makefile` or build script entry for `./waf` binary copy

**Modify:**
- `crates/prx-waf/src/main.rs` — add config auto-discovery when `-c` not provided
- `configs/default.toml` — add `[interop]` section with `audit_log_path` and `benchmark_secret`

## Implementation Steps

### TDD: Write Tests First

1. **Unit test for config auto-discovery logic**:
   - Given `waf.toml` exists in CWD → uses it
   - Given only `waf.yaml` exists → uses it
   - Given neither → falls back to `configs/default.toml`
   - Given `-c custom.toml` flag → uses explicit path (no auto-discovery)

2. **Shell test for wrapper script**:
   - `./waf --help` → shows help text
   - `./waf run` with valid config → starts and responds to health check

### Implement

3. **Add config auto-discovery** in `main.rs`:
   ```rust
   fn resolve_config_path(cli_path: Option<&str>) -> anyhow::Result<PathBuf> {
       if let Some(p) = cli_path {
           return Ok(PathBuf::from(p));
       }
       let candidates = ["waf.toml", "waf.yaml", "configs/default.toml"];
       for c in &candidates {
           let p = PathBuf::from(c);
           if p.exists() { return Ok(p); }
       }
       anyhow::bail!("no config file found; provide -c <path> or place waf.toml in CWD")
   }
   ```

4. **Create wrapper script** at repo root `./waf`:
   ```sh
   #!/bin/sh
   exec "$(dirname "$0")/target/release/prx-waf" "$@"
   ```

5. **Add Makefile target** (or extend existing build script):
   ```makefile
   .PHONY: release
   release:
   	cargo build --release
   	cp target/release/prx-waf ./waf
   	chmod +x ./waf
   ```

6. **Create `waf.toml`** symlink or config at repo root:
   - Symlink: `ln -s configs/default.toml waf.toml`
   - Or: dedicated benchmark config with interop section

7. **Add `[interop]` section** to `configs/default.toml`:
   ```toml
   [interop]
   benchmark_secret = "waf-hackathon-2026-ctrl"
   audit_log_path = "./waf_audit.log"
   ```

### Validate

8. `./waf run` starts the WAF with auto-discovered config
9. `curl http://127.0.0.1:9527/health` returns 200
10. `./waf -c configs/default.toml run` still works (backward compat)
11. Docker build unaffected (uses `prx-waf` binary directly)

## Success Criteria

- [ ] `./waf run` starts the WAF and passes health check
- [ ] Config auto-discovery finds `waf.toml` → `waf.yaml` → `configs/default.toml`
- [ ] Explicit `-c` flag overrides auto-discovery
- [ ] Existing `prx-waf` binary name unchanged
- [ ] Docker/systemd deployments unaffected
- [ ] `./waf_audit.log` created on first request (Phase 3)
- [ ] `cargo check --workspace` passes

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Wrapper script not executable after git clone | Low | `.gitattributes` with `waf text eol=lf` + `chmod +x` in Makefile |
| YAML config support adds dependency | Medium | Only needed if user provides `waf.yaml`; skip for MVP, support TOML only |
| Symlink not portable on Windows | Low | Benchmark runs on Linux; Windows not in scope |
| Binary copy in Makefile gets stale | Low | Makefile target rebuilds before copy |
