---
phase: 3
title: "Add RiskConfig::validate wired into config load"
status: pending
effort: 1h
---

# Phase 3: Add RiskConfig::validate wired into config load

## Overview

Add `RiskConfig::validate(&self) -> anyhow::Result<()>` and call it inside
`from_path` so nonsensical config is rejected at the parse boundary. Operational
callers already fail-soft on the resulting `Err`, so no new error handling is needed
in the watcher.

## Verified Context

- `RiskConfig::from_path` (`risk/config.rs:375-383`) parses YAML → `Arc<RiskConfig>`,
  no validation.
- Fail-soft already wired: `reload.rs:33-42` — on `from_path` `Err` it logs
  "keeping previous snapshot" and does not swap. So validate-in-from_path makes the
  watcher reject invalid reloads for free.
- Real failure modes verified in code:
  - `gc_interval_secs` feeds `interval(Duration::from_secs(interval_secs))`
    (`store/memory.rs:47`) — `0` panics tokio's interval ("period must be non-zero").
  - `ttl_secs` → `ttl_ms()` (`config.rs:387`) → `purge_expired` treats every actor
    as idle-expired at `0` (`store/memory.rs:202`).
  - `ingest.channel_capacity` (`config.rs:243-244`) sizes the bounded ingest channel;
    `0` panics tokio mpsc (`channel(0)`). [RE-VERIFY the channel construction site at
    impl; the panic is a known tokio invariant.]
  - `store.backend` (`config.rs:78-79`) is matched as `"memory"`/`"redis"`; other
    values silently fall through.
  - `decay.max_decay` is the decay floor; `> 100` makes the floor unreachable and
    breaks the Phase 2 `u32 → i32` floor cast assumption.

## Key Decisions

- **What validate rejects** (KISS — only verified-harmful values):
  - `ttl_secs == 0`
  - `gc_interval_secs == 0`
  - `ingest.channel_capacity == 0`
  - `store.backend` not in `{"memory", "redis"}`
  - `decay.max_decay > 100`
  `decay.min_clean_streak == 0` and `decay.decay_rate == 0` are **valid** (rate 0 =
  decay disabled; streak 0 = decay eligible immediately). Do not reject them.
- **Out of scope — risk thresholds.** The issue's "thresholds out of order" example
  refers to allow/challenge/block, which live in `TierPolicy.risk_thresholds`
  (waf-common `decide()` at `risk/threshold.rs`), not `RiskConfig`. `RiskConfig::validate`
  cannot and does not check them. State this in the code doc-comment.
- **Error shape:** return `anyhow::Err` with a message naming the offending field and
  value (e.g. `"risk config: gc_interval_secs must be > 0"`). Collect all violations
  into one message if cheap, else fail on first — implementer's choice; single message
  is enough for the watcher/PUT.
- **Call site:** `from_path`, after successful parse, before `Ok(Arc::new(...))`.
  GH-196 Phase 3's admin PUT path will additionally call `validate()` (or `from_path`)
  before writing `risk.yaml` and return 400 on `Err` — cross-plan, not implemented here.

## Implementation Steps

1. Add `pub fn validate(&self) -> anyhow::Result<()>` on `RiskConfig` (in the existing
   `impl RiskConfig` block, `config.rs`).
2. In `from_path`, call `doc.risk.validate()?` (map/propagate the error with context)
   before wrapping in `Arc`.
3. Doc-comment validate: enumerate what it checks and explicitly note risk thresholds
   are validated elsewhere (TierPolicy).
4. Confirm the shipped `configs/risk.yaml` passes validate (it should — defaults are
   valid); `config_yaml_regression.rs:45` loads it through `from_path` and must stay green.

## Related Code Files

- Modify: `crates/waf-engine/src/risk/config.rs` (`validate` + `from_path` call)

## Success Criteria

- [ ] Unit tests: `validate()` rejects each bad value (ttl 0, gc 0, channel 0, bad
      backend, max_decay 101) and accepts a default config + `decay_rate: 0` +
      `min_clean_streak: 0`.
- [ ] `from_path` on a YAML with `gc_interval_secs: 0` returns `Err` (no panic).
- [ ] `config_yaml_regression` and `reload.rs` tests stay green.

## Risk Assessment

- Likelihood low / impact low. Additive validation at one call site.
- Regression risk: a currently-shipped or test-fixture config with a now-rejected
  value would start failing `from_path`. Mitigated by step 4 and by the narrow reject
  set. Re-grep test fixtures that build `risk.yaml` with `ttl_secs`/`gc_interval_secs`/
  `channel_capacity`/`backend` before finalizing.

## Rollback

Remove the `validate()?` call from `from_path` (keep the method) to restore prior
permissive loading.
</content>
