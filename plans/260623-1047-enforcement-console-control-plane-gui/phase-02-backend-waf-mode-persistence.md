---
phase: 2
title: "Backend WAF-Mode Persistence"
status: done
priority: P2
dependencies: []
effort: "M"
---

# Phase 2: Backend WAF-Mode Persistence

## Overview

Persist the effective enforcement mode (`enforce` / `log_only`) on each security
event and expose it on the events API, so the S5 correlation surfaces (Phase 6)
read a real value instead of inferring it client-side. Independent of the FE;
can run in parallel with Phases 1/3/4.

## Requirements

- Functional: every newly recorded security event stores `waf_mode`; the
  `GET /api/security-events` list and `GET /api/security-events/{id}` detail
  responses include `waf_mode`.
- Non-functional: backfill-safe default for existing rows; the persisted value is
  the **decision** mode (`decision.mode`), reflecting `ModeRegistry` precedence —
  NOT the static `host_config.log_only_mode` fallback (per scout CONCERN).

## Architecture

The X-WAF-Mode header is already derived from `ctx.waf_decision_meta.mode`
(an `InteropMode`) in `crates/gateway/src/waf_observability_headers.rs`. The event
is written via `log_security_event()` in `crates/waf-engine/src/engine.rs`
(~line 969) building a `CreateSecurityEvent` that currently omits mode. Thread
`decision.mode.as_contract_str()` into that struct and down to the SQL insert.

Data flow:
```
WafDecision.mode ──▶ CreateSecurityEvent.waf_mode ──▶ INSERT security_events.waf_mode
                                                  └──▶ SecurityEvent.waf_mode ──▶ /api/security-events*
```

## Related Code Files

- Create: `migrations/0018_security_events_waf_mode.sql` — add
  `waf_mode TEXT NOT NULL DEFAULT 'enforce'` to `security_events`
  (latest existing migration is `0017_tunnel_protocol.sql`).
- Modify: `crates/waf-storage/src/models.rs` — add `waf_mode: String` to
  `SecurityEvent` (~lines 105–118) and `CreateSecurityEvent` (~lines 305–317).
- Modify: `crates/waf-storage/src/repo.rs` — bind `waf_mode` in
  `create_security_event` (~lines 425–441) and any batch insert variant.
- Modify: `crates/waf-engine/src/engine.rs` — in `log_security_event()` set
  `waf_mode: decision.mode.as_contract_str().to_string()`.
- Reference: `crates/waf-common/src/types.rs` (`InteropMode::as_contract_str`),
  `crates/waf-api/src/server.rs:149-150` (events routes — no change if the model
  field serializes automatically).
- Tests: `crates/waf-storage` repo test for round-trip; engine test asserting a
  `log_only` decision writes `waf_mode="log_only"`.

## Implementation Steps

1. Write migration `0018_security_events_waf_mode.sql` with the new column +
   default. Confirm the migration runner picks up `0018` (follow how `0017` is
   wired).
2. Add `waf_mode` to `SecurityEvent` and `CreateSecurityEvent` (type `String`,
   values constrained to `enforce`/`log_only`).
3. Bind the column in `repo.rs` insert(s); update the column list + `VALUES`
   placeholders and any `#[derive(FromRow)]` ordering assumptions.
4. In `engine.rs::log_security_event()`, populate `waf_mode` from
   `decision.mode.as_contract_str()`.
5. Verify the events API serializes `waf_mode` (SecurityEvent is `Serialize`); no
   handler change expected. Add a field assertion to an API/integration test.
6. `cargo fmt`, `cargo clippy`, run storage + engine + api tests.

## Success Criteria

- [ ] Migration applies cleanly on a fresh DB and on a DB with existing events
      (existing rows default to `enforce`).
- [ ] A request evaluated under a `log_only` decision writes
      `waf_mode="log_only"`; an enforce decision writes `"enforce"`.
- [ ] `GET /api/security-events` and `/{id}` responses contain `waf_mode`.
- [ ] Persisted value matches the `X-WAF-Mode` header for the same request
      (both from `decision.mode`).
- [ ] `cargo test` green across waf-storage, waf-engine, waf-api.

## Risk Assessment

- **FromRow column-order mismatch** after adding a column. Mitigated by explicit
  column lists in queries and a round-trip test.
- **Header/DB divergence** if one path uses the host flag and the other the
  registry. Mitigated by sourcing both from `decision.mode`; add a test that
  asserts parity.
- **Migration ordering / numbering.** Mitigated by using the next sequential
  number `0018` and verifying against the runner.

Rollback: the column is additive with a default; reverting code leaves harmless
data. Provide a down-migration only if the project convention requires one.
