# 2026-07-05 — GH-197: geo rules enforcement wiring (implementation)

## What

Wired the geo admin API to actual enforcement. Before this, geo rule CRUD
wrote `configs/geo-rules.yaml` that nothing loaded — the engine's `GeoCheck`
evaluated an always-empty map, and `lookup_ip` was a hardcoded stub.

- **`checks/geo_config.rs` (new):** `parse_geo_rules` deserializes the API's
  flat row shape (`{id, iso_code, action, scope, enabled, country_name}`) and
  maps it to per-host `Vec<GeoRule>`: block rows union into ONE `Block` rule,
  allow rows into ONE `AllowOnly` rule per host (`scope:"global"` → `"*"`),
  disabled rows skipped, iso codes uppercased. `apply_geo_rules` full-snapshot
  replaces the live `GeoCheck` and clears hosts absent from the file.
- **`checks/geo_reload.rs` (new):** `GeoReloader` — parent-dir `notify`
  watcher + debounced sync thread, copied from `ddos::reload`. Bad YAML keeps
  the previous rule set.
- **Engine:** `geo_reloader: OnceLock<GeoReloader>` field,
  `load_geo_rules(path)` (deterministic, test-friendly), `start_geo_watcher(path)`
  (initial load + watcher, fail-soft), `geoip_lookup(ip)` accessor over the
  `OnceLock<Arc<GeoIpService>>`. `GeoCheck::loaded_hosts()` added for
  absent-host clearing.
- **`main.rs`:** `start_geo_watcher` wired after the tx-velocity block,
  resolving `configs/geo-rules.yaml` with the same parent/parent logic as
  `geo_api::rules_path` — API CRUD hot-reloads enforcement via the file, no
  API→engine push call.
- **`geo_api.rs`:** `lookup_ip` now parses the IP (400 on invalid), reads
  `state.engine.geoip_lookup`, and falls back to the existing stub envelope
  when the service is unset or the lookup is empty (private IP / no xdb).

## How it was verified

- 30 geo unit tests green (`cargo test -p waf-engine --lib geo`): mapping
  (union, disabled-skip, scope→host, uppercase), apply (absent-host clear,
  bad-YAML retention), hot-reload swap.
- New integration tests (testcontainers, CI-run): 
  `waf-engine/tests/geo_rules_enforcement.rs` (block enforced via the real
  file→map→load path, delete clears, allow-union) and
  `waf-api/tests/handler_geo_rules.rs` (POST → file at `rules_path` parses via
  `parse_geo_rules` into the enforced Block rule; lookup stub + 400 paths).
  Added `start_test_server_with_main_config` fixture variant so the rules file
  lands in a test-owned tempdir.
- `cargo clippy -p waf-engine -p waf-api -p prx-waf --all-targets` clean;
  `cargo fmt --all --check` clean; waf-api lib suite 118 passed; waf-engine
  lib suite 1402 passed (6 failures are the pre-established docker-gated
  testcontainer tests — no docker socket locally, CI covers them).

## Gotchas

- **N separate AllowOnly rules would block everyone.** The engine evaluates
  rules independently, so per-row mapping of allow rows would make an
  allow-US rule block a CA visitor. Rows MUST union into a single AllowOnly
  rule per host. This is asserted by tests at both unit and engine level.
- **Path agreement is by construction, not by contract.** `main.rs` and
  `geo_api::rules_path` both resolve `main_config_file.parent().parent()/configs/geo-rules.yaml`;
  the handler integration test locks the API-writes ↔ engine-reads seam by
  parsing the file the handler actually wrote.
- Workspace clippy denies `indexing-slicing` even in tests → `#[allow]` on
  test mods; nursery `too_long_first_doc_paragraph` needs short first doc
  paragraphs.
