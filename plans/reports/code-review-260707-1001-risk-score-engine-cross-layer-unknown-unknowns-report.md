# Risk Score Engine — Cross-Layer Unknown-Unknowns Review (round 2)

**Date:** 2026-07-07 10:01 · **Branch:** main-harness · **Mode:** codebase (advisory, no files changed)
**Scope:** risk score engine across UI (`web/admin-panel`), API (`waf-api`), engine (`waf-engine/src/risk` + `engine.rs`), file config (`configs/`), storage (memory/Redis stores, `waf-storage` models)
**Method:** 3 parallel `code-reviewer` subagents (engine core / data path+stores / API+UI+config edges); controller re-verified every load-bearing claim against source. Builds on `code-review-260705-1530-geoip-risk-engine-unknown-unknowns-report.md` (July 5) — does not repeat what that report covers unless status changed.

---

## TL;DR

Since July 5, PRs #234–#245 fixed the worst wiring gaps (seed/challenge layers, fp/rule deltas, credit sign, store races). The biggest remaining traps are:

1. **The tier-policies admin surface is a mirage** — UI+API read/write `configs/tier-policies.yaml`; the engine only ever reads `configs/tier-protection.toml`. Threshold/fail_mode edits in the panel never reach enforcement. (CRITICAL, verified)
2. **Redis backend can silently shed accumulated risk** via per-axis index-key TTL divergence — a behavior the memory backend cannot reproduce and the conformance suite doesn't test. (HIGH, verified in Lua source)
3. **Several config knobs are dead**: `emit_header`/`header_name` (header is contract-mandated always-on), `thresholds.challenge` (decide() ignores it), `store.redis.breaker_threshold` (breaker state is tracked but never consulted). Editing them changes nothing.
4. **Decay is clean-request-count driven, not time driven** — an idle actor never decays; TTL purge is the only idle forgiveness. Anyone "tuning decay" for idle actors is turning the wrong knob.

## July 5 findings — current status

| July 5 finding | Status |
| --- | --- |
| C1 seed/challenge never wired | FIXED #237 |
| C2 Add-credit 400s (sign) | FIXED #236 — contract now coherent UI→API→engine |
| H1 fp/rule deltas discarded | FIXED #241 |
| H7 memory TOCTOU / Redis reset non-atomic / cluster CROSSSLOT | FIXED #245 (cluster now guarded) |
| null-`canary.paths` 500 | FIXED #234/#235 |
| H3 store.backend PUT no-ops until restart | STILL OPEN (`engine.rs:474-479` warn-only) |
| H2 velocity purge never scheduled | STILL OPEN — `purge_idle` has no production caller (grep-verified) |
| H5 actors/metrics API stubs | STILL OPEN (`risk_api.rs:96,119` hardcoded `[]`/zeros) |
| H6 panel risk_allow/challenge/block orphaned | STILL OPEN, now subsumed by CRITICAL below |

## New findings (verified where marked)

### CRITICAL

**C1 — `tier-policies.yaml` is disconnected from enforcement.** [VERIFIED] Only `waf-api` reads/writes it (`tier_policies_api.rs:38,64,70`); the engine's tier watcher loads `config.tiered_protection.config_path` → `configs/tier-protection.toml`, TOML `[tiered_protection]` table (`main.rs:1441-1461`, `tier_config_watcher.rs:132-138`, `full-features.toml:127`). Values disagree (YAML all-tiers 20/60/85 vs TOML per-tier 20/50/70…50/80/95) and formats are incompatible (`cache_policy: no_cache` string vs tagged enum `{ mode = "..." }`, `tier.rs:36-44`) — the YAML could never parse engine-side even if pointed at. `default.toml`/`local-dev.toml` omit `config_path` entirely → every request is `catch_all` with hardcoded 30/70/90 (`tier.rs:83-94`). Dashboard `RiskBandPreview` renders the disconnected YAML numbers while its comment claims it "must show what the engine enforces" (`dashboard/index.tsx:189-190`). Operator edits thresholds/fail_mode → success toast → zero enforcement change.

### HIGH

**H1 — Redis index-TTL divergence sheds risk.** [VERIFIED in `redis_lua.rs:50-95`] `apply` refreshes TTL only on index keys for axes present in the *current* request; the owner state key is refreshed every apply. Actor seen as IP+fp, then active IP-only for > `ttl_secs` → `idx:fp` pointer expires while state persists → later fp-only request finds no candidate, mints a fresh score-0 owner. Memory backend structurally cannot do this (all axes share one Arc). Conformance suite doesn't cover it (`conformance.rs:484-487`). Product decision needed: is per-axis idle expiry intended?

**H2 — Circuit breaker is decorative.** [VERIFIED] `breaker_open()` (`redis.rs:147`) is called only from tests; no apply/read path consults it. Contrast `rate_limit/store/breaker.rs:36` which actually short-circuits. During a Redis outage every request pays full `op_timeout_ms`; `breaker_threshold` config (`config.rs:108`) implies protection that doesn't exist.

**H3 — Ingest worker silently drops deltas during degraded apply.** Degraded `apply` returns cached/zero state without folding new deltas (`redis.rs:311,414,419`); the sync path honors `result.degraded` (`scorer.rs:239`) but the async ingest worker discards the whole ApplyResult (`worker.rs:133`) with no degraded-drop metric. Device-fp/velocity signals during a Redis blip vanish invisibly.

**H4 — `PUT /api/risk/config` parses but never calls `validate()`.** (`risk_api.rs:89-92` vs engine load `config.rs:389-396`.) A parseable-but-invalid config (e.g. `max_decay > 100`; UI field has no max, `risk-scoring/index.tsx:498-502`) returns 200 + writes the file; hot-reload fails validate → warn + keep previous snapshot (`reload.rs:43-45`); **next restart, risk scoring silently stays disabled** (`engine.rs:465-467`). "Saved" ≠ valid ≠ active.

**H5 — risk.yaml hot-reload is partial.** Reload swaps only cfg snapshot + canary (`engine.rs:471-484`). Live: `enabled`, header/session opts, `seed.enabled`, `challenge.*`, canary. Restart-only, silently: `decay.*` (baked into store, `engine.rs:382`), `ttl_secs`/`gc_interval_secs` (purge loop, `engine.rs:385-386`), `store.*`. UI returns success for all of them, no restart hint.

**H6 — Velocity/sequence stores unbounded + evasion by key design.** (Carried H2 from July 5, still open.) DashMaps keyed by full `RiskKey` incl. attacker-controlled session/fp — cookie or fp rotation both starts a fresh rate window (evasion of the 60s window and the Login→OTP→Withdrawal sequence FSM) and grows memory without bound; `purge_idle` exists (`velocity/window.rs:148`, `sequence.rs:133`) but is never scheduled.

### MEDIUM — semantics a maintainer MUST know

- **Decay = clean-request-count, not time.** `clean_streak` bumps only on an empty-delta request, resets on ANY delta (`score.rs:16-21`); decay fires at `clean_streak >= min_clean_streak`; `now_ms` used only for pin check (`decay.rs:44-65`). Idle actors never decay; TTL purge (default 1800s) is the real forgiveness cliff.
- **`thresholds.challenge` is dead.** [VERIFIED] `decide()` uses only `allow`/`block`; challenge band is implicit `[allow, block)` (`threshold.rs:17-39`), yet `tier.rs:144-148` validates `allow < challenge < block`. Tightening `challenge` changes nothing.
- **`emit_header`/`header_name` are dead config.** [VERIFIED] Gateway unconditionally injects `X-WAF-Risk-Score` (all six `X-WAF-*` headers) per Interop Contract v2.3 §5 (`waf_observability_headers.rs:8,50` + contract test scaffold). The always-on client-visible score is *contractual*; the risk.yaml knobs are the lie. Note: score disclosure to clients is a deliberate contract choice — revisit only via contract change.
- **Two independent clamps.** Per-request positive-delta cap `MAX_PER_REQUEST_DELTA=100` truncating OLDEST positives, keeping negatives (`score.rs:38,68-103`) vs total-score reclamp 0..=100 (`state.rs:130-135`). Edit one without the other → broken accounting.
- **Triple-index unify = max-pick-and-discard, not merge.** Picks single max-score state, discards others, repoints only current-request axes; stale session index can keep pointing at an orphan state (`store/memory.rs:78-103`; `store_trait.rs:31-36` doc overstates "merge").
- **Seed hot-reload fail-opens to EMPTY.** Transient read error or Remove event → `load_or_empty` swaps in empty tables (`seed/reload.rs:143-166`): Tor/ASN scoring silently off AND whitelist emptied (previously-whitelisted actors start accruing risk).
- **Challenge-credit cluster trap.** Per-node HMAC secret, never rotates, default `/var/lib/waf/challenge-hmac.key` (`secret.rs:4`, `mod.rs:180`). Multi-node without a shared mounted key: token minted on node A = BadSignature on node B = +20 penalty for legit users. Nonce SETNX failure on Redis error → `ConsumedWithWarning` → treated Valid → −25 credit granted (replay window during outage). LRU eviction also re-opens replay (>100k nonces per token TTL).
- **Enforcement bypass surfaces:** risk runs only on `FastPath::Miss` (`engine.rs:944`); risk Block/Challenge replaces only a plain-Allow pipeline decision (`engine.rs:958-960`); monitor mode (LogOnly) suppresses ALL risk/canary escalation incl. honeypot bans; whitelist short-circuits before canary (`scorer.rs:129-169`).
- **Failure semantics are asymmetric by operation:** apply fail-open (degraded state, tier fail_mode decides), read fail-closed (`redis.rs:365` vs `414`), `force_max` canary pin failure = warn + not persisted, nonce = fail-open. No single "fail mode" — specify per-operation when prompting.
- **`redis_lua.rs` hand-mirrors `score.rs`/`decay.rs`/`state.rs`** incl. `string.gsub` byte-patch and hardcoded `'Decay'` contributor (`redis_lua.rs:143,181`). Highest-risk file to edit. Parity verified only when `REDIS_TEST_URL` set — CI does (`ci.yml:51-67`), local `cargo test` silently skips (green ≠ parity locally).
- **No `deny_unknown_fields` on `RiskConfig`/`TierConfig`** (`config.rs`): typo'd YAML key silently defaults; and since GET/PUT re-serialize the typed shape, any manual extra key/comment in `risk.yaml` is deleted on next UI save.
- **fp_hash is 64-bit SHA-256 truncation** (`key.rs:79`); collision + max-score-wins convergence = cross-actor contamination. Low probability, real by construction.
- **Signal weights:** unknown/typo'd signal key falls back to weight 10 (`signal_to_contributor.rs:66`); `DdosBurst` delta bypasses weights entirely (`:154`).
- **Tier-policy API validation thin** (`tier_policies_api.rs:44-62`): missing/non-int thresholds coerce to 0 via `unwrap_or(0)` and can spuriously pass `allow<challenge<block`.

### LOW

- JA4↔UA detector near-inert: placeholder cipher hashes, unknown inputs pass (`anomaly/ja4_ua_mismatch.rs:15-88`); `&ja4[..10]` slice panic-prone on non-ASCII [SPEC].
- Canary paths exact-match case-sensitive (`canary.rs:82-91`) — `/admin` ≠ `/admin/`.
- `reset_all` (Redis) uses blocking `KEYS` (`redis_lua.rs:339`).
- Memory GC purge caps 1000/axis/tick (~16/s at default interval).
- `ttl_ms()` overflow-prone for huge `ttl_secs` (`config.rs:435-437`).
- Caller-supplied `now_ms` trusted → multi-instance clock skew affects decay/pin.

### Working-tree warning (act before any commit)

Uncommitted diffs flip production-meaningful flags: `configs/risk.yaml` `enabled: true→false` + `ttl_secs: 1808→1809`; `configs/tier-policies.yaml` critical `fail_mode: close→open` (inert per C1, still misleading); `configs/ddos.yaml` `hot_reload: true→false` + critical tier populated. Pattern matches the known admin-panel-save round-trip artifact class (see `fix-260707-0322-ci-coverage-corrupt-shipped-configs-report.md`). Decide deliberately; don't sweep into an unrelated commit.

### What's solid (verified, don't "fix")

- Credit contract now coherent end-to-end: UI positive magnitudes → API `1..=100` gate → engine `-amount.abs()` (`index.tsx:689`, `risk_api.rs:139-147`, `engine.rs:511`).
- All risk/tier routes behind `require_auth` + `admin_ip_check` + `rate_limit` (`server.rs:330-338`).
- Constant-time HMAC verify before JSON parse (`token.rs:110-123`).
- Memory store `clear()` sweeps all shared indices; #245 closed the apply race and made Redis reset atomic.
- Score arithmetic parity memory↔Redis is solid; divergence lives in *lifecycle* (TTLs), *failure handling*, and *observability*.

---

## How to prompt better for this area

(Extends the July 5 guidance — "name the wiring seam, ban hand-wired tests, spell out cross-layer contracts" all still apply. New lessons:)

1. **Name the file enforcement actually reads.** For tier work say `configs/tier-protection.toml` (TOML, `[tiered_protection]`), not tier-policies.yaml; for risk say `configs/risk.yaml`. First ask in any config task: "which file does the engine watcher load?" — the admin API is not a reliable witness (C1).
2. **Classify the knob's lifecycle before asking for a change.** Four classes exist here: live hot-reload (`enabled`, canary, seed.enabled, challenge.*) / restart-only (store.*, decay.*, ttl, gc) / contract-fixed (X-WAF-* headers) / dead (emit_header, thresholds.challenge, breaker_threshold). Say which class you expect and require the PR to prove it ("editing X via PUT must change live behavior, or the API must say restart-required").
3. **For store changes, demand lifecycle parity, not just arithmetic parity.** Require: a conformance case covering TTL/index behavior on BOTH backends, the Lua mirror (`redis_lua.rs`) updated in the same PR as `score.rs`/`decay.rs`/`state.rs`, and a note that the test ran with `REDIS_TEST_URL` (local default silently skips).
4. **State decay semantics explicitly.** "Decay" here = clean-request-count streaks; if you mean time-based idle forgiveness, say TTL — or you'll get the wrong knob tuned.
5. **Specify fail-open/fail-closed per operation.** apply/read/force_max/nonce/seed-reload each has a different posture today. A prompt like "handle Redis outage" is ambiguous across five behaviors.
6. **Declare deployment topology.** Single-node vs multi-node changes correctness: shared challenge-HMAC key mount, Redis single-instance requirement, per-node memory store, per-node velocity maps. Say "assume N nodes" in any prompt touching challenge credit, stores, or bans.
7. **For save-path work, cite the pattern:** round-trip through engine structs AND call `validate()` (risk_api post-#234 is the closest pattern but itself skips validate — H4). Require "PUT must reject anything `RiskConfig::from_path` would reject."
8. **Ask reviewers to verify claims against the real artifact** (running Lua, actual contract tests) — this round, "risk header leak" downgraded from trust-boundary bug to contract-mandated behavior only after checking the Interop Contract test scaffold.

## Suggested fix ordering (if wanted)

1. C1 — pick one tier-policy source of truth (likely: point API/UI at `tier-protection.toml` or migrate engine to the YAML with schema round-trip). Highest operator-facing lie.
2. H4 — add `validate()` to PUT (one-liner class fix, prevents boot-time silent disable).
3. H3 + H2 — degraded-drop metric in ingest worker; either wire the breaker or delete the knob.
4. H1 — decide + fix index-TTL refresh policy (Lua change + conformance case).
5. H5 — restart-required signaling in PUT response + UI.
6. H6 — schedule `purge_idle` (copy risk-store purge loop pattern).
7. Dead-knob cleanup: emit_header/header_name, thresholds.challenge, breaker_threshold — delete or wire.

## Unresolved questions

1. C1: is `tier-policies.yaml` dead scaffolding to delete, or the intended future source the engine should migrate to?
2. H1: is per-axis index expiry (risk shedding after quiet axis) intended behavior or bug?
3. Is `X-WAF-Risk-Score` always-on disclosure still the desired contract (Interop v2.3 §5), given scores are now enforcement-relevant?
4. Multi-node: is a shared challenge-HMAC key provisioned anywhere (deploy compose/service files), or is single-node assumed?
5. `ttl_secs: 1809` + `enabled: false` in working tree — intentional, or test artifacts to revert?
6. Are `list_risk_actors`/`get_risk_metrics` implementations scheduled, or should the UI show explicit "not implemented"?
7. Should `thresholds.challenge` drive a real second boundary (allow/challenge/block as 3 cut-points) or be removed from schema+validation?
