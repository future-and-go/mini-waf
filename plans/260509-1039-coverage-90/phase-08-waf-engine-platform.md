# Phase 08 — waf-engine: `logging/`, `plugins/`, `geoip*`, `community/`, `crowdsec/`, `relay/` gaps → 88%

## Context Links
- Baseline: `plans/260509-1039-coverage-90/plan.md`
- Crate: `crates/waf-engine/`
- Existing tests: `relay_*` (10+ files, strong), inline community/crowdsec tests.

## Overview
- **Priority:** P2
- **Status:** pending
- **Target:** 88% line for these submodules combined
- File ownership glob: `crates/waf-engine/src/{logging,plugins,community,crowdsec,relay}/**`, `crates/waf-engine/src/{geoip.rs,geoip_updater.rs}` AND new `crates/waf-engine/tests/{logging,plugins,geoip,community,crowdsec,relay_intel}_*.rs`.

## Key Insights
- **Lowest-coverage targets in workspace:**
  - `logging/vlogs_layer.rs` (186 regions, **8.06%**)
  - `logging/batch_buffer.rs` (215 regions, **28.37%**)
  - `logging/audit_sender.rs` (91 regions, **49.45%**)
  - `plugins/manager.rs` (425 regions, **46.59%**)
  - `geoip.rs` (185 regions, **47.03%**)
  - `geoip_updater.rs` (410 regions, **54.88%**)
- `relay/intel/asn_feed.rs` (58%), `relay/reload.rs` (78%), `relay/registry.rs` (80%) — mop-up.
- `community/` and `crowdsec/` baselines truncated from tail; expect mid-70s based on prior coverage-loop history.
- `vlogs_layer.rs` integrates `tracing_subscriber::Layer` — testable by capturing events with `tracing_subscriber::registry().with(layer)` and a JSON sink.
- `batch_buffer.rs` is the audit batching state machine — pure logic, no excuse not to be ≥90%.
- `geoip*`: needs xdb file — bundle a small fixture in `tests/fixtures/`.

## Requirements
- `logging/`: capture every log path (record buffered, flush on size, flush on time, flush on shutdown, drop on overflow).
- `plugins/manager.rs`: load valid WASM, reject invalid, hot-reload, isolation (one plugin failure does not crash others).
- `geoip.rs`: lookup hit, miss, malformed IP, IPv6, file not found, file corrupted.
- `geoip_updater.rs`: schedule, fetch (mock HTTP), checksum verify, atomic swap.
- `community/`: reporter throttle, enroll lifecycle, checker pre-existing 73-77% baseline → push to 88%.
- `crowdsec/`: bouncer cache miss/hit/expired, AppSec request roundtrip (httpmock), pusher buffer flush.
- `relay/intel/`: feed refresh + parse error + ASN classifier mop-up.

## Architecture
```
waf-engine/src/
├── logging/
│   ├── audit_sender.rs    ← 49% → 90%
│   ├── batch_buffer.rs    ← 28% → 92%
│   ├── vlogs_layer.rs     ← 8%  → 80% (Layer impl is the hard part)
│   └── mod.rs
├── plugins/
│   └── manager.rs         ← 46% → 85%
├── geoip.rs               ← 47% → 90%
├── geoip_updater.rs       ← 55% → 80%
├── community/             ← ~74% → 88%
├── crowdsec/              ← ~78% → 88%
└── relay/
    ├── intel/asn_feed.rs  ← 58% → 85%
    ├── intel/asn_feed_iptoasn.rs ← 63% → 85%
    ├── reload.rs          ← 78% → 90%
    └── registry.rs        ← 80% → 90%
```

## Related Code Files
**Modify (inline tests):**
- `crates/waf-engine/src/logging/{audit_sender.rs, batch_buffer.rs, vlogs_layer.rs, mod.rs}`
- `crates/waf-engine/src/plugins/manager.rs`
- `crates/waf-engine/src/geoip.rs`
- `crates/waf-engine/src/geoip_updater.rs`
- `crates/waf-engine/src/relay/{reload.rs, registry.rs}`, `relay/intel/{asn_feed.rs, asn_feed_iptoasn.rs}`

**Create:**
- `crates/waf-engine/tests/logging_batch_lifecycle.rs` — buffer fill, flush triggers, overflow drop
- `crates/waf-engine/tests/logging_vlogs_layer.rs` — tracing event capture + JSON serialization
- `crates/waf-engine/tests/logging_audit_sender.rs` — bounded channel, send-when-full, shutdown flush
- `crates/waf-engine/tests/plugins_wasm_lifecycle.rs` — load valid WAT (compiled to WASM in test), invalid bytes, hot-reload, panic isolation
- `crates/waf-engine/tests/geoip_lookup.rs` — using `tests/fixtures/geoip-mini.xdb` (bundle ~50KB sample)
- `crates/waf-engine/tests/geoip_updater_schedule.rs` — using `httpmock` for fetch
- `crates/waf-engine/tests/community_reporter_throttle.rs`
- `crates/waf-engine/tests/crowdsec_bouncer_cache.rs`
- `crates/waf-engine/tests/crowdsec_appsec_client.rs` (httpmock)
- `crates/waf-engine/tests/relay_intel_refresh_errors.rs` — fetch failure + parse failure paths

**Add fixture:**
- `crates/waf-engine/tests/fixtures/geoip-mini.xdb` — small (≤100KB) ip2region snapshot for tests. Source: extract sample from existing dataset OR generate synthetic.

## Implementation Steps
1. `batch_buffer.rs` inline: state machine — push N below threshold (no flush), push exactly threshold (flush), push past max (drop oldest), elapsed time (flush). Use `tokio::time::pause()`.
2. `audit_sender.rs` inline + integration: channel-bounded send returns Ok within capacity, returns Err / drops past capacity, shutdown drains buffer.
3. `vlogs_layer.rs` inline: install layer with `tracing_subscriber::registry`, emit `tracing::info!(...)`, assert JSON payload reaches sink within timeout.
4. `plugins/manager.rs`: build a tiny WAT in test (`wat::parse_str`) → bytes → `load`. Negative: malformed bytes → error variant. Hot-reload: load v1, replace, assert v2 active.
5. `geoip.rs` inline: lookup against `geoip-mini.xdb` → known IP returns expected country/region. Malformed IP → error. File-not-found at construction → error.
6. `geoip_updater.rs`: configure `httpmock` to serve XDB bytes; updater fetches, verifies checksum, atomic-swaps. Checksum mismatch → reject + keep old.
7. `community/`: extend existing inline tests; cover reporter throttle (1 per second), enroll happy + retry on 429.
8. `crowdsec/cache.rs`: insert decision with TTL → before TTL hit, after TTL miss; eviction.
9. `crowdsec/appsec.rs`: httpmock returns Block / Allow / Captcha → assert AppSecResult mapping.
10. `crowdsec/pusher.rs`: buffer N events, force flush, assert HTTP body.
11. `relay/intel/asn_feed.rs`: malformed CSV row → skip+log; well-formed → entries added; empty file → no entries.
12. `relay/reload.rs`: notify-driven swap with new config; rollback on validation fail.

## Todo List
- [ ] `logging/batch_buffer.rs` inline state machine tests
- [ ] `logging/audit_sender.rs` channel + shutdown
- [ ] `logging/vlogs_layer.rs` tracing → JSON capture
- [ ] `tests/logging_batch_lifecycle.rs`
- [ ] `tests/logging_vlogs_layer.rs`
- [ ] `tests/logging_audit_sender.rs`
- [ ] `plugins/manager.rs` inline + `tests/plugins_wasm_lifecycle.rs`
- [ ] `tests/fixtures/geoip-mini.xdb` (bundled)
- [ ] `tests/geoip_lookup.rs`
- [ ] `tests/geoip_updater_schedule.rs` (httpmock)
- [ ] `tests/community_reporter_throttle.rs`
- [ ] `tests/crowdsec_bouncer_cache.rs`
- [ ] `tests/crowdsec_appsec_client.rs`
- [ ] `tests/relay_intel_refresh_errors.rs`
- [ ] Inline mop-up: `relay/{reload,registry}.rs`, `relay/intel/asn_feed*.rs`
- [ ] Combined coverage of owned files ≥ 88%
- [ ] All new files ≤ 200 LOC
- [ ] No new fixture > 100KB

## Success Criteria
- Combined ≥ 88% line.
- `logging/vlogs_layer.rs` ≥ 80% (acknowledged ceiling — tracing internals are not fully steerable).
- `batch_buffer.rs` ≥ 92%, `audit_sender.rs` ≥ 90%.
- `geoip.rs` ≥ 90%, `geoip_updater.rs` ≥ 80%.
- All new tests pass under 5x rerun (no flake).

## Risk Assessment
- **Medium**: WASM test fixtures need `wat` dev-dep. Verify it compiles to deterministic bytes.
- **Medium**: `httpmock` startup adds latency per test — share via `OnceCell<MockServer>` per file.
- **Low**: tracing layer test requires careful `tracing_subscriber` registry scoping (use `with_default`).

## Security Considerations
- WASM plugin tests must verify panic ISOLATION — a panicking plugin must not poison other plugins or the engine.
- CrowdSec AppSec test fixtures must NOT include real customer payloads.
- GeoIP lookup must NOT leak server-side path info on file-not-found errors.

## Next Steps
- If `geoip-mini.xdb` cannot be reduced below 100KB, raise as unresolved and ship larger fixture (precedent: ip2region sample is typically ≤500KB).
