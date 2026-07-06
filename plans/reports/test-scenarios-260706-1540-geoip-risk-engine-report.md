# Test Scenarios — GeoIP & Risk Score Engine

Date: 2026-07-06 | Branch: main-harness | Author: intake for /test request
Scope: `crates/waf-engine/src/{geoip.rs, geoip_updater.rs, checks/geo*.rs}` and `crates/waf-engine/src/risk/**`.
Legend: ✅ covered (test exists) | 🔸 partial | ❌ gap. Priority: P0 security-critical, P1 correctness, P2 robustness.

## 1. GeoIP — lookup service (`geoip.rs`)

| ID | Scenario (Given / When / Then) | Expected | Cov | Pri |
|----|----|----|----|----|
| GEO-L1 | Both xdb paths missing / init | Service inits OK, `is_available()=false`, lookups return empty `GeoIpInfo` | ✅ `init_with_nonexistent_paths_succeeds_and_is_unavailable` | P1 |
| GEO-L2 | Corrupt xdb file / init | Warn + degrade, no panic | ✅ `init_with_corrupt_xdb_falls_back_gracefully` | P1 |
| GEO-L3 | IPv4 vs IPv6 address / lookup | Routed to correct family searcher | ✅ `lookup_ipv4/ipv6_address_routes_*` | P1 |
| GEO-L4 | Region string `Country\|Prov\|City\|ISP\|iso`; `"0"` sentinels | Parsed; `0`→empty; iso uppercased at parse time | ✅ unit `parse_*` | P1 |
| GEO-L5 | Reload with valid new files | Atomic swap, `Ok(true)`, readers never see torn state | ✅ `family_reload_swaps_*` (unit) | P1 |
| GEO-L6 | Reload fails while a **working searcher exists** | Old searcher preserved, `Err` naming family — service-level (unit `family_reload` covers logic only) | ❌ service-level test: load valid xdb → overwrite file with garbage → `reload()` → `Err` + lookups still work | P0 |
| GEO-L7 | Concurrent lookups during reload | No downtime / no panic (ArcSwap) | ❌ (P2 stress; optional) | P2 |

## 2. GeoIP — check evaluation (`checks/geo.rs`)

| ID | Scenario | Expected | Cov | Pri |
|----|----|----|----|----|
| GEO-C1 | Block rule, request iso matches (incl. lowercase rule codes) | `DetectionResult` Phase::GeoIp | ✅ `block_by_iso`, `lowercase_rule_iso_codes_match` | P0 |
| GEO-C2 | AllowOnly, listed country passes / unlisted blocked | pass / block | ✅ `allow_only_fail_closed_with_geo_data_matches_as_before` | P0 |
| GEO-C3 | AllowOnly fail-closed, geo `None` or empty | blocked, detail "geo data unavailable" | ✅ 2 tests | P0 |
| GEO-C4 | AllowOnly fail-open, geo unavailable | pass | ✅ | P0 |
| GEO-C5 | Block rule with `fail_closed=true`, geo unavailable | never fails closed (pass) | ✅ `block_rule_never_fails_closed` | P1 |
| GEO-C6 | **Match by country name only** (iso empty, `rule.countries` set, case-insensitive) | matched via name path (`geo_matches` second branch) | ❌ no test exercises `countries` set | P1 |
| GEO-C7 | **Host-specific vs global precedence**: host rules loaded but no match → global rules still evaluated; host match short-circuits global | host-first, fall through to `"*"` | ❌ all unit tests load only `"*"` | P1 |
| GEO-C8 | AllowOnly with iso empty but country name non-empty, not in list | blocked (condition `!geo.country.is_empty() \|\| !geo.iso_code.is_empty()`) | ❌ boundary of line 169 | P2 |
| GEO-C9 | Host has AllowOnly(fail-closed), global has Block; geo unavailable | host fail-closed wins before global consulted | ❌ | P1 |

## 3. GeoIP — config loader & hot reload (`geo_config.rs`, `geo_reload.rs`)

| ID | Scenario | Expected | Cov | Pri |
|----|----|----|----|----|
| GEO-F1 | Block rows union into one rule per host; iso uppercased | 1 Block rule | ✅ `block_rows_union_into_one_rule` | P1 |
| GEO-F2 | Allow rows union into ONE AllowOnly rule (per-row allow rules would block everyone) | 1 AllowOnly rule | ✅ | P0 |
| GEO-F3 | Any `fail_closed: true` allow row → whole host allowlist fail-closed | most-restrictive wins | ✅ | P0 |
| GEO-F4 | Disabled rows skipped; `scope: global` → `"*"`; host scope → host key | ✅ 3 tests | | P1 |
| GEO-F5 | Reload: host absent from new file cleared; bad YAML keeps previous rules | ✅ `apply_clears_hosts_absent...`, `apply_error_keeps_existing_rules` | | P0 |
| GEO-F6 | **Stale `action: challenge` row** (present in live `configs/geo-rules.yaml` id 4, IR): loader treats non-`allow` as block; API now rejects `challenge` on write | Document + test: legacy `challenge` row parses as **Block** (not dropped, not challenge). Decide if that's intended → data cleanup of live config | ❌ + config-data issue | P0 |
| GEO-F7 | File→enforcement e2e: rule added via file blocked, deleted → cleared | ✅ `block_rule_from_file_is_enforced_and_delete_clears_it` | | P0 |
| GEO-F8 | Log-only host: geo detection downgraded to LogOnly | ✅ `engine_late_log_only_geo.rs` | | P1 |

## 4. GeoIP — updater (`geoip_updater.rs`)

Covered well: missing-file short-circuit, 404 propagation, invalid xdb body leaves original untouched, duration parsing (✅ `geoip_updater_schedule.rs`). Remaining:

| ID | Scenario | Expected | Cov | Pri |
|----|----|----|----|----|
| GEO-U1 | Successful download → reload picks new file while serving | swap without downtime | 🔸 (download validated; combined download→`reload()` path not e2e) | P2 |

## 5. Risk — threshold gate (`threshold.rs`)

All bands covered ✅: `<allow`→Allow, `>=block`→Block 403, between→Challenge, pin override always blocks, degraded fail-open trusts cached score, degraded fail-close→503 regardless, `allow==block` boundary. **No gaps.**

## 6. Risk — score fold & clamp (`score.rs`, `state.rs`)

| ID | Scenario | Expected | Cov | Pri |
|----|----|----|----|----|
| RSK-S1 | Per-request positive deltas >100: oldest positives truncated, credits preserved | capped at `MAX_PER_REQUEST_DELTA` | ✅ `oversized_positive_batch_capped_and_credit_preserved` | P0 |
| RSK-S2 | Empty delta batch → clean_streak increments; non-empty resets streak | ✅ fold unit tests (score.rs) | | P1 |
| RSK-S3 | Credits drive raw below 0 | `clamped_score` floors at 0, no underflow | 🔸 verify `reclamp` unit test exists in state.rs; add scorer-level if missing | P1 |
| RSK-S4 | raw_score saturating at i32 extremes (hostile repeat max deltas) | no overflow panic | 🔸 saturating_add used; property test candidate | P2 |

## 7. Risk — decay (`decay.rs`)

Covered ✅: below-min-streak no decay, decay after streak, floor at `max_decay`, pinned skips decay, preview==apply. Gaps:

| ID | Scenario | Expected | Cov | Pri |
|----|----|----|----|----|
| RSK-D1 | `decay_rate: 0` disables decay entirely | 0 delta always | ❌ (doc says supported via `available` arithmetic) | P2 |
| RSK-D2 | Non-default config plumb: live `configs/risk.yaml` sets `min_clean_streak: 15`, `max_decay: 50` | runtime uses file values, not defaults | 🔸 check `config_yaml_regression.rs`; add if absent | P1 |

## 8. Risk — key & identity merge (`key.rs`, store)

Covered ✅: `fp_only_then_session_only_merges_to_max`, `ip_fp_session_blend_takes_max`, `apply_with_combined_key_unifies_indices`, `ip_collision_apply_progresses_score`, `phantom_actor_regression`, empty-key short circuits. Gap:

| ID | Scenario | Expected | Cov | Pri |
|----|----|----|----|----|
| RSK-K1 | `session_cookie` configured + cookie present → `build_key` adds session axis; absent cookie → IP(+fp) only | session axis populated from `ctx.cookies` | ❌ scorer-level (merge tested at store level only) | P1 |
| RSK-K2 | Attacker rotates IP but keeps fingerprint/session → score follows actor | merged state, high score persists | 🔸 implied by merge tests; add explicit scorer e2e | P1 |

## 9. Risk — seed layer L0 (`seed/`)

Covered ✅: whitelist short-circuits to Allow (incl. before canary), tor delta accrues, delta overrides, table swap on reload, reloader observes whitelist change, all-paths/none loading. Gaps:

| ID | Scenario | Expected | Cov | Pri |
|----|----|----|----|----|
| RSK-SE1 | Datacenter ASN + bad ASN class deltas (`datacenter_delta: 15`, `bad_asn_delta: 25`) through scorer | seed contributor with configured delta | 🔸 tor path tested; asn/datacenter scorer-path unclear | P1 |
| RSK-SE2 | Whitelisted IP hits canary path | Allow (whitelist wins — ordering in `score()`) | ❌ explicit ordering test | P0 |

## 10. Risk — canary honeypot (`canary.rs`)

Covered ✅: canary path forces Block+pin (`canary_path_forces_block_with_pin`), non-matching path skipped, no-layer no-op. Gaps:

| ID | Scenario | Expected | Cov | Pri |
|----|----|----|----|----|
| RSK-C1 | Canary hit inserts IP into DDoS dynamic ban table with configured TTL | ban entry present, TTL honored | 🔸 (`ddos_risk_bump_acceptance.rs` partial?) | P0 |
| RSK-C2 | **Pin expiry**: after `pinned_until_ms` passes and decay/credits lower score | actor un-blocks; decay resumes | ❌ scorer-level time-travel test | P1 |
| RSK-C3 | `canary.enabled: false` with paths configured | no block on canary path | 🔸 gating via cfg checked in code; add explicit test | P1 |

## 11. Risk — challenge credit (`challenge_credit/`)

Covered ✅: valid/invalid/expired/replay outcomes, binding mismatch, bad signature, malformed token, nonce replay, secret persistence/permissions/redaction, disabled-skips-verifier, in-band score, engine wiring e2e. Gap:

| ID | Scenario | Expected | Cov | Pri |
|----|----|----|----|----|
| RSK-CH1 | Valid credit (`valid_delta: -25`) lowers score across threshold boundary → next request downgrades Block→Challenge→Allow | action transition observed | 🔸 `challenge_in_band_score` may cover; verify boundary crossing | P1 |

## 12. Risk — L2 anomaly & velocity

Covered ✅: clean request no contributors, XFF violation delta, multiple anomalies, velocity breach at threshold, sequence violation (OTP w/o login), both violations, purge idle, `hard_burst_raises_scored_actor_state`, `soft_anomaly_preserves_severity`. Gaps:

| ID | Scenario | Expected | Cov | Pri |
|----|----|----|----|----|
| RSK-V1 | Sequence FSM happy path Login→OTP→Withdrawal with sane timing | **no** violation contributor | ❌ only violation paths tested at layer level | P1 |
| RSK-V2 | Velocity window slides: burst, then 60s quiet → counter resets, no delta | window expiry correctness | 🔸 window.rs unit? verify | P2 |
| RSK-V3 | JA4↔UA mismatch (+20) with real JA4 string vs curl UA through scorer | contributor emitted | 🔸 unit-level in ja4_ua_mismatch.rs; scorer path untested | P2 |

## 13. Risk — store & degradation (`store/`)

Covered ✅: memory conformance, purge_expired, reset_all, force_max pin, degraded fail-open (unknown allowed / cached high still blocks), degraded fail-close 503, healthy store ignores fail_close. Gaps:

| ID | Scenario | Expected | Cov | Pri |
|----|----|----|----|----|
| RSK-ST1 | Redis backend: breaker trips after `breaker_threshold` failures → degraded=true; recovery closes breaker | transitions both ways | 🔸 `redis.rs`/conformance — needs live redis; mark as feature-gated integration | P1 |
| RSK-ST2 | Redis/local cache coherence (`cache_capacity`) under actor churn | no stale-score block after clear | ❌ | P2 |
| RSK-ST3 | TTL purge: actor idle > `ttl_secs` (1810 live) removed by GC loop | entry gone; new request `is_new=true` | 🔸 store-level covered; engine GC loop timing untested | P2 |

## 14. Risk — config, gating, hot reload

| ID | Scenario | Expected | Cov | Pri |
|----|----|----|----|----|
| RSK-G1 | `enabled: false` (live config today!) → scorer returns Allow score 0, no store writes | ✅ `score_disabled_returns_allow` | | P0 |
| RSK-G2 | `risk_assessment` monitor mode: LogOnly detections keep own decision, suppress risk escalation | escalation only fires on plain Allow | 🔸 engine-level; verify `engine_late_pipeline.rs` | P0 |
| RSK-G3 | Hot reload risk.yaml (thresholds/deltas) via notify → next request uses new values without restart | ArcSwap snapshot | 🔸 `reload.rs` unit; e2e file-touch test valuable | P1 |
| RSK-G4 | `emit_header: true` → `X-WAF-Risk-Score` on response; false → absent | header contract | 🔸 accessors tested; gateway-level check in `waf_observability_headers.rs`? verify | P2 |
| RSK-G5 | Invalid config (e.g. `max_decay > 100`, allow>block thresholds) rejected by `validate()` | load error, previous config kept | 🔸 config.rs unit ~line 404; verify reload keeps old snapshot | P1 |

## Recommended implementation order

1. **P0 gaps**: GEO-F6 (challenge-action row — also decide live-config cleanup), GEO-L6 (reload preserve), RSK-SE2 (whitelist-vs-canary ordering), RSK-C1 (canary→ban-table TTL).
2. **P1 gaps**: GEO-C6/C7/C9 (country-name + host precedence), RSK-K1 (session cookie axis), RSK-C2 (pin expiry), RSK-V1 (FSM happy path), RSK-D2 (config plumb).
3. **P2**: property/stress items as time allows.

Suggested locations: geo unit gaps → `src/checks/geo.rs` `#[cfg(test)]`; scorer-level → `crates/waf-engine/tests/risk_scorer_extended.rs` (extend); GEO-L6 → `tests/geoip_lookup.rs`; GEO-F6 → `src/checks/geo_config.rs` tests.

## Unresolved questions

1. GEO-F6: should legacy `action: challenge` rows be (a) treated as block (current), (b) dropped, or (c) migrated on load? Live `configs/geo-rules.yaml` id 4 (IR) is affected right now — currently enforced as **block**, likely not the admin's intent.
2. Live `configs/risk.yaml` has `enabled: false` and `canary.enabled: false` — are the working-tree edits to both configs intentional test fixtures or pending changes? (Both files show as modified in git.)
3. RSK-ST1: is a live-Redis integration test acceptable in CI (docker-compose exists), or keep redis scenarios behind a feature flag / manual suite?
