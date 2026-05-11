# FR-006 Phase 4: Configuration Hot-Reload — ArcSwap + YAML + notify

**Date**: 2026-05-11 13:18
**Severity**: Medium
**Component**: waf-engine challenge/config module, challenge/reload module
**Status**: Resolved

## What Happened

Phase 4 delivered the infrastructure for hot-reloadable challenge configuration. Created YAML config layer (`configs/challenge.yaml`), config structs for difficulty/token/branding/nonce settings, and a lock-free reloader using `notify` file watcher + `ArcSwap` for atomic updates. Followed established patterns from FR-008 (risk/config.rs + risk/reload.rs). All 56 tests pass. Code review scored 7/10; one critical noted (config fields not yet wired to template—expected for Phase 4), naming collision with risk module flagged for future rename.

## The Brutal Truth

**Config exists in a vacuum right now.** We built the infrastructure but it's not connected to anything that matters. The `ChallengeConfig` struct has cookie settings (name, domain, secure flag, samesite) but they're ignored by the page template generator. Phase 5 will wire these fields to the HTML output, but shipping Phase 4 without that integration feels incomplete—the config loads, hot-reloads, passes tests, but doesn't change behavior. This is intentional scope creep minimization, but it's frustrating to implement something that has zero runtime effect.

**Naming collision waiting to explode.** We have `waf_engine::risk::config::ChallengeConfig` and now `waf_engine::challenge::config::ChallengeConfig` in the same crate. The compiler doesn't care because they're in different modules, but the second we import both, ambiguity. The plan notes this for Phase 5+, but it's a landmine. Should've renamed risk's version upstream.

## Technical Details

**config.rs Structure:**
- `ChallengeConfig`: top-level wrapper (version, difficulty, tokens, branding, nonce_store)
- `DifficultyConfig`: algorithm selection (pow_difficulty_bits), validation time range (min/max_ms)
- `TokenConfig`: generation (alphabet, length), validation (max_age, issue_timeout)
- `BrandingConfig`: copy + link for challenge page HTML
- `NonceStoreConfig`: backend selection (in_memory or redis), expiry, cleanup intervals
- Serde with `#[serde(deny_unknown_fields)]` to catch typos in YAML

**reload.rs Implementation:**
- `ChallengeReloader`: wraps `Arc<ArcSwap<ChallengeConfig>>`
- `notify::RecommendedWatcher` with debounce of 200ms (coalesces rapid edits)
- Bad YAML logs WARN, retains last-known-good snapshot (fail-soft)
- Spawns watch task only when `.start()` called
- Blocks replaced via `ArcSwap.store()` (lock-free, single CAS operation)

**configs/challenge.yaml:**
- Defaults: 20 difficulty bits, token length 32, 5min token validity, 30s nonce store TTL
- Self-documenting structure; no required fields (all have sensible defaults)

**Tests (56 total, all pass):**
- Config parsing (invalid YAML, missing fields, extra fields)
- Default values propagation
- Hot-reload behavior (write file, verify update)
- Error handling (bad syntax, filesystem permission denied)

## What We Tried

1. **Direct Mutex vs. ArcSwap:** Rejected Mutex (allows readers to block on writers). ArcSwap chosen: zero-cost reads, lock-free updates via atomic swap. Trade-off: updating readers must re-read the Arc pointer; acceptable because config reads are rare (per-request is cached at gateway).

2. **File Watcher Debounce:** Started with 50ms, bumped to 200ms. Reason: rapid saves (e.g., IDE on focus loss) were triggering multiple reloads. 200ms is imperceptible to operators but coalesces bursts.

3. **Bad Config Fallback:** Considered panicking on YAML parse error (strict fail). Rejected: production doesn't deserve to crash for malformed YAML. Now: logs WARN, keeps previous config. Operators fix the YAML without downtime.

## Root Cause Analysis

**Naming collision unresolved.** The risk module already claimed `ChallengeConfig` when FR-005 shipped. By the time Phase 4 started, the collision was locked in. Should have renamed risk's version in FR-005's Phase 5. Deferred because Phase 4 is infrastructure-only and Phase 5+ will be the painful part anyway.

**Config wiring gap expected but documented.** No runtime effect until Phase 5. This is intentional scope creep control (Phase 4 = infra, Phase 5 = wiring to template), but it creates a "build system nobody uses yet" feeling.

## Lessons Learned

**ArcSwap is the right primitive for config hot-reload in latency-critical paths.** Lock-free reads beat Mutex every time. The cost (re-reading the Arc pointer on each load) is negligible compared to clarity and zero contention.

**200ms debounce is practical for operator-paced config edits.** Instant reload (0ms) triggers thrashing; 1s feels unresponsive. 200ms is the sweet spot.

**Fail-soft on bad config beats fail-hard.** A misconfigured YAML shouldn't crash production. Log, retain, let ops fix. This is operational humility.

## Next Steps

- **Phase 5:** Wire `ChallengeConfig` fields to page template generator; verify HTTP responses change when YAML is edited
- **Phase 5+:** Rename risk module's `ChallengeConfig` to avoid ambiguity (blocker for public API)
- **Testing:** Add end-to-end test verifying config hot-reload affects gateway response (currently missing)
- **Commit:** 8290a02

Commit message: `feat(challenge): add configuration hot-reload with notify + ArcSwap`

All acceptance criteria green. Ready for Phase 5 wiring.
