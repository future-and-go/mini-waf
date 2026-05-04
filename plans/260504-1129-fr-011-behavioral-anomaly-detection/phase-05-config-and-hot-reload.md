---
phase: 5
title: "Config and Hot Reload"
status: completed
priority: P1
effort: "0.5d"
dependencies: [4]
---

# Phase 5: Config and Hot Reload

## Overview

Promote the stub `BehaviorConfig` from Phases 1-4 to a fully validated, hot-reloadable config block under `behavior:` in the existing `configs/device-fp.yaml`. Reuse the existing `device_fp::reload` watcher — no new file, no new admin API.

## Requirements

- **Functional:** Live edits to `configs/device-fp.yaml` `behavior:` block reflect in next request eval within 500 ms (200 ms debounce + parse + swap).
- **Non-functional:** Malformed YAML never crashes the gateway. Validation runs **before** the atomic swap; on failure, last-good config is retained and a warn log emitted.

## Architecture

The existing `device_fp::reload::DeviceFpReloader` already watches `configs/device-fp.yaml` and swaps `Arc<ArcSwap<DeviceFpConfig>>`. Add `behavior: BehaviorConfig` as a field of `DeviceFpConfig` — providers read `cfg.load().behavior.<sub>` per evaluation.

### YAML schema (excerpt — appended to existing file)

```yaml
behavior:
  window_size: 16              # 4..=64
  actor_ttl_secs: 600          # 60..=86400

  burst_interval:
    enabled: true
    threshold_ms: 50           # 1..=10000
    min_consecutive: 5         # 2..=window_size-1
    risk_delta: 15             # 0..=100

  regularity:
    enabled: true
    min_samples: 6             # 2..=window_size
    cv_threshold: 0.15         # (0.0, 1.0]
    min_mean_ms: 100           # 1..=60000
    risk_delta: 10

  zero_depth:
    enabled: true
    min_samples: 4
    critical_hits_required: 2  # 1..=min_samples
    risk_delta: 10

  missing_referer:
    enabled: true
    risk_delta: 5
    exempt_paths:    ["/", "/login", "/index", "/health"]
    exempt_prefixes: ["/static/", "/assets/", "/api/"]
```

### Validation table (run before swap)

| Field | Rule |
|---|---|
| `window_size` | 4 ≤ x ≤ 64 |
| `actor_ttl_secs` | 60 ≤ x ≤ 86_400 |
| `*.risk_delta` | 0 ≤ x ≤ 100 |
| `*.min_samples` | 2 ≤ x ≤ window_size |
| `burst_interval.threshold_ms` | 1 ≤ x ≤ 10_000 |
| `burst_interval.min_consecutive` | 2 ≤ x ≤ window_size − 1 |
| `regularity.cv_threshold` | 0.0 < x ≤ 1.0 |
| `regularity.min_mean_ms` | 1 ≤ x ≤ 60_000 |
| `zero_depth.critical_hits_required` | 1 ≤ x ≤ min_samples |
| `missing_referer.exempt_*` entries | non-empty, ≤ 256 chars each |

## Related Code Files

- **Modify:**
  - `crates/waf-engine/src/device_fp/config.rs` — add `behavior: BehaviorConfig` field with serde defaults.
  - `crates/waf-engine/src/device_fp/behavior/config.rs` — promote stub to full schema + `validate()` method returning `Result<(), ConfigError>`.
  - `crates/waf-engine/src/device_fp/reload.rs` — call `cfg.behavior.validate()` in the parse path before swap (mirror existing validation hooks).
  - `configs/device-fp.yaml` — add the `behavior:` block with shipped defaults.
  - All four providers — change `cfg: Arc<ArcSwap<BehaviorConfig>>` → `cfg: Arc<ArcSwap<DeviceFpConfig>>` and access via `cfg.load().behavior.<sub>`.

## Implementation Steps

1. Promote `BehaviorConfig` to full schema in `behavior/config.rs`. Use serde with `#[serde(default)]` per field — graceful YAML omission falls back to default.
2. Implement `BehaviorConfig::validate(&self) -> Result<(), ConfigError>` running every rule in the validation table.
3. Wire `validate()` into the reload path: read `crates/waf-engine/src/device_fp/reload.rs::reload`, after `from_path` parse but before `swap.store(...)`, call `parsed.behavior.validate()`. On `Err`, log `tracing::warn!` and return without swapping.
4. Update all four providers to read `cfg.load().behavior.<sub>` (drop the standalone `Arc<ArcSwap<BehaviorConfig>>` wiring — DRY: one swap, one config).
5. Update `configs/device-fp.yaml` with the `behavior:` block (shipped defaults).
6. Unit tests in `behavior/config.rs`:
   - parse round-trip (default YAML → default struct).
   - reject `window_size = 0`.
   - reject `cv_threshold = 1.5`.
   - reject `min_consecutive > window_size`.
   - reject empty exempt entry.
   - reject `critical_hits_required > min_samples`.
7. Reload integration test:
   - boot with valid YAML.
   - flip `burst_interval.risk_delta` 15→25 on disk.
   - within 500 ms, next eval emits +25.
   - write malformed YAML → next eval still emits +25 + warn line present.

## Success Criteria

- [ ] All validation unit tests pass.
- [ ] Reload integration test passes (15→25 propagation + malformed retains).
- [ ] Malformed YAML produces `tracing::warn!` with file path and parse error, no panic.
- [ ] Default YAML (full file) loads without warnings.
- [ ] `cargo clippy --all-targets -- -D warnings` clean.

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Validation runs after swap (live config corrupted) | Strict ordering: parse → validate → swap. Test enforces. |
| Float `cv_threshold` serde error on `0.15` (yaml interprets as string) | Test parse round-trip explicitly. |
| Editor save bursts cause double-reload | Existing 200 ms debounce in `DeviceFpReloader` already handles. |
| Default YAML drifts from `BehaviorConfig::default()` | Add a test that loads the shipped YAML and asserts equality with default struct. |

## Security Considerations

- Validation caps prevent config-injected DoS (e.g. `window_size: 1_000_000` would balloon memory).
- `risk_delta ≤ 100` cap prevents single-signal score saturation.
