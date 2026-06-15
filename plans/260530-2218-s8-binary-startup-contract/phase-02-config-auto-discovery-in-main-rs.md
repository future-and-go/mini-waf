---
phase: 2
title: "Config auto-discovery in main.rs"
status: pending
priority: P1
effort: "0.5d"
dependencies: [1]
---

# Phase 2: Config auto-discovery in main.rs

## Overview

Make `./waf run` work with no flags by walking a deterministic config search order when `-c/--config` is not provided. Search order: `./waf.toml` → `./configs/default.toml` → error. Explicit `-c <path>` always wins (zero behavioral change for existing flows). TOML-only — no YAML support per design decision.

## Context Links

- Contract §8: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 504–528
- Current CLI: `crates/prx-waf/src/main.rs:27-34` (the `Cli` struct's `config` arg with `default_value = "configs/default.toml"`)
- Config loader: `waf_common::config::load_config` (called at `main.rs:321`)

## Requirements

**Functional:**
- `./waf run` (no `-c`) starts with `./waf.toml` if present, else `./configs/default.toml`, else exits non-zero with a clear error.
- `./waf -c custom.toml run` (explicit) uses `custom.toml`. No search.
- Search is performed against the **current working directory** (the contract says "MUST exist in working directory"). Do NOT search the binary's parent dir or any other root.
- Search is performed once during `main()`, before `load_config()` is called.

**Non-functional:**
- All existing invocations (`prx-waf -c configs/default.toml run`, `prx-waf run`, every subcommand) must continue to work after the rename in Phase 1. Subcommands inherit the same config resolution.
- No new crate dependencies (no `serde_yaml`, no `figment`, no `config` crate).
- Error path for "no config found" emits a message that names the search order, so an operator can diagnose without source-diving.

## Architecture

### CLI surface change

`Cli::config` becomes `Option<String>`. The `clap` `default_value` is removed.

```rust
#[derive(Parser, Debug)]
#[command(name = "waf", version, about)]
struct Cli {
    /// Path to configuration file. If omitted, auto-discovered:
    /// ./waf.toml → ./configs/default.toml.
    #[arg(short, long)]
    config: Option<String>,

    #[command(subcommand)]
    command: Commands,
}
```

(Also flip `#[command(name = "prx-waf", ...)]` → `"waf"` so `--help` prints the new name. This is the only Rust-source rename needed for §8 — the crate name stays `prx-waf`.)

### Resolver function

A pure function — no I/O beyond `Path::exists()` — so it is straightforward to unit-test under `#[cfg(test)]` without touching the filesystem (use `tempfile`).

```rust
const CONFIG_SEARCH_PATHS: &[&str] = &["waf.toml", "configs/default.toml"];

fn resolve_config_path(cli_path: Option<&str>) -> anyhow::Result<PathBuf> {
    if let Some(p) = cli_path {
        return Ok(PathBuf::from(p));
    }
    for candidate in CONFIG_SEARCH_PATHS {
        let p = PathBuf::from(candidate);
        if p.exists() {
            tracing::info!(path = %p.display(), "config auto-discovered");
            return Ok(p);
        }
    }
    anyhow::bail!(
        "no config file found in CWD. Searched: {}. \
         Provide --config <path> or place waf.toml in the working directory.",
        CONFIG_SEARCH_PATHS.join(", ")
    )
}
```

### Wiring into `main()`

Replace `main.rs:321-324`:

```rust
// Before
let config = load_config(&cli.config).unwrap_or_else(|e| {
    tracing::warn!("Failed to load config from {}: {}. Using defaults.", cli.config, e);
    AppConfig::default()
});

// After
let config_path = resolve_config_path(cli.config.as_deref())?;
let config = load_config(config_path.to_str().context("config path is not valid UTF-8")?)
    .unwrap_or_else(|e| {
        tracing::warn!(path = %config_path.display(), error = %e, "failed to load config; using defaults");
        AppConfig::default()
    });
```

Behavioral note: `resolve_config_path` returns `Err` (process exit) only when no `-c` is given AND no candidate exists. If `-c <missing>` is given, the existing `load_config` failure path keeps applying (warn + defaults), preserving current behavior.

The downstream call `run_server(&config, &cli.config, …)` (main.rs:348) needs `&str` for the config-file path — pass `config_path.to_string_lossy().as_ref()` (or thread `PathBuf` through). The string is used inside `run_server` to resolve the panel config (`resolve_panel_config_path`). Verify no other call-site depends on the literal `&cli.config` string identity.

## Related Code Files

**Modify:**
- `crates/prx-waf/src/main.rs`
  - `Cli` struct: `config: Option<String>`, remove `default_value`
  - `#[command(name = "waf", …)]`
  - Add `resolve_config_path()` function (with `#[cfg(test)] mod tests`)
  - Update `main()` to call `resolve_config_path` before `load_config`
  - Update `run_server` call to pass resolved path

**Untouched:**
- `waf_common::config::load_config` (signature stays — still takes `&str`)
- `AppConfig` struct
- All subcommand handlers (they only use `&config`, not `&cli.config`)

## Implementation Steps

### TDD: tests first

1. **Write unit tests** in `crates/prx-waf/src/main.rs` under `#[cfg(test)] mod tests`:

   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       use tempfile::tempdir;

       #[test]
       fn explicit_path_bypasses_search() {
           let p = resolve_config_path(Some("/explicit/path.toml")).unwrap();
           assert_eq!(p, PathBuf::from("/explicit/path.toml"));
       }

       #[test]
       fn missing_explicit_path_still_returned() {
           // Explicit -c with non-existent path returns it; load_config handles fallback.
           let p = resolve_config_path(Some("/nope.toml")).unwrap();
           assert_eq!(p, PathBuf::from("/nope.toml"));
       }

       #[test]
       fn picks_waf_toml_when_present() {
           let dir = tempdir().unwrap();
           let original = std::env::current_dir().unwrap();
           std::env::set_current_dir(dir.path()).unwrap();
           std::fs::write("waf.toml", "").unwrap();
           let resolved = resolve_config_path(None).unwrap();
           std::env::set_current_dir(original).unwrap();
           assert_eq!(resolved, PathBuf::from("waf.toml"));
       }

       #[test]
       fn falls_back_to_configs_default_toml() {
           let dir = tempdir().unwrap();
           let original = std::env::current_dir().unwrap();
           std::env::set_current_dir(dir.path()).unwrap();
           std::fs::create_dir_all("configs").unwrap();
           std::fs::write("configs/default.toml", "").unwrap();
           let resolved = resolve_config_path(None).unwrap();
           std::env::set_current_dir(original).unwrap();
           assert_eq!(resolved, PathBuf::from("configs/default.toml"));
       }

       #[test]
       fn errors_when_no_config_exists() {
           let dir = tempdir().unwrap();
           let original = std::env::current_dir().unwrap();
           std::env::set_current_dir(dir.path()).unwrap();
           let result = resolve_config_path(None);
           std::env::set_current_dir(original).unwrap();
           let err = result.unwrap_err().to_string();
           assert!(err.contains("waf.toml"));
           assert!(err.contains("configs/default.toml"));
       }
   }
   ```

   **Concurrency note:** these tests mutate process CWD. Mark the test module `#[cfg(not(loom))]` is unnecessary, but consider serializing with a single `Mutex<()>` if cargo's default parallel test runner causes flakes. Simplest mitigation: gate the CWD-mutating tests behind a `serial_test::serial` attribute — already in `[dev-dependencies]` if present, else inline a static mutex helper. **Verify dep status first**; if not present, use a local `OnceLock<Mutex<()>>` rather than adding a dep.

2. Run `cargo test -p prx-waf` — confirm five new failing tests (the helper doesn't exist yet).

### Implement

3. **Define `CONFIG_SEARCH_PATHS` and `resolve_config_path`** as shown above. Place near the top of `main.rs` after the imports.

4. **Flip `Cli::config` to `Option<String>`** and remove `default_value`. Update `#[command(name = "waf", …)]`.

5. **Wire `main()`**: call `resolve_config_path(cli.config.as_deref())?` once, then call `load_config` against the resolved `PathBuf`. Convert to `&str` for the existing `load_config` signature. Stash the resolved path string for the existing `run_server(config, config_file_path, …)` call.

6. **`cargo test -p prx-waf`** — five tests pass.

7. **Smoke-test manually:**
   ```sh
   cd /tmp && cargo run --release -p prx-waf -- run
   # → exits with "no config file found in CWD. Searched: waf.toml, configs/default.toml. …"

   cd repo-root && cargo run --release -p prx-waf -- run
   # → finds configs/default.toml, starts.

   echo "" > /tmp/empty.toml && cd /tmp && cargo run --release -p prx-waf -- -c empty.toml run
   # → explicit path used; load_config fails → warn + defaults (existing behavior).
   ```

### Validate

8. **Backward-compat probe:** run every documented invocation:
   - `waf -c configs/default.toml run` (explicit)
   - `waf run` (auto)
   - `waf migrate` (auto)
   - `waf seed-admin` (auto)
   - `waf rules list` (auto)
   - `waf cluster status` (auto)

   Each must locate a config or fail gracefully with the helpful error.

9. **Pre-push formatting** per `CLAUDE.md`: `cargo fmt --all` and `cargo fmt --all -- --check`.

## Success Criteria

- [ ] `Cli::config` is `Option<String>`; no `default_value`
- [ ] `resolve_config_path` function exists with documented search order
- [ ] All 5 unit tests pass under `cargo test -p prx-waf`
- [ ] `./waf run` from a directory containing `waf.toml` starts the server
- [ ] `./waf run` from a directory containing only `configs/default.toml` starts the server
- [ ] `./waf run` from an empty directory exits with an error message naming both search paths
- [ ] `./waf -c <path> run` uses the explicit path with zero search
- [ ] `cargo check --workspace` clean; `cargo clippy --workspace -- -D warnings` clean
- [ ] No new dependency added to any `Cargo.toml`

## Risk Assessment

| Risk | Likelihood | Mitigation |
|---|---|---|
| CWD-mutating tests race in parallel runner | Medium | Single static mutex around the two CWD-mutating tests, or use `serial_test` if it's already a dev-dep; verify before adding any dep |
| Operators relying on the implicit `configs/default.toml` default get confused if the file moves | Low | Search order keeps `configs/default.toml` second — existing behavior preserved |
| `Path::exists()` race (file deleted between `exists()` and `load_config`) | Negligible | TOCTOU window is microseconds; `load_config` already returns `Err` → existing fallback applies |
| UTF-8 conversion of `PathBuf` fails on exotic filesystems | Negligible | `Context::context` produces a clear error |
| Forgetting to update `#[command(name = …)]` leaves `--help` showing "prx-waf" | Low | Step 4 is explicit; checked in success criteria via manual `./waf --help` smoke |
