---
phase: 1
title: "Config + Role Tagger + Recorder"
status: pending
priority: P1
effort: "1d"
dependencies: []
---

# Phase 1: Config + Role Tagger + Recorder

## Overview

Scaffold module `checks/tx_velocity/`. Implement YAML config (hot-reload), endpoint role tagger (path → role), and recorder (DashMap + ring buffer + janitor). No classifiers yet — empty hook.

## Requirements

**Functional:**
- Parse YAML `tx_velocity` config (endpoint_roles, classifier params, signal_cooldown_ms)
- Map request path → `EndpointRole` enum
- Maintain per-`SessionKey` ring buffer (16 events)
- Janitor purges idle sessions (TTL 10 min)

**Non-functional:**
- Hot-reload via `ArcSwap<TxVelocityConfig>` + `notify`
- O(1) append; <50µs per request
- No `.unwrap()` in production (Iron Rule #1)

## Architecture

```
TxVelocityConfig (ArcSwap) ─► RoleTagger (regex compiled once)
                                    │
SessionKeyExtractor ──────────► TxStore = DashMap<SessionKey, ActorTx>
                                    │
                                    └─► append(Event) — bounded by ArrayVec<16>
Janitor task (tokio interval) ─► purge entries idle > TTL
```

`SessionKey = (host: SmolStr, ident: SessionIdent)`
`SessionIdent = Cookie(SmolStr) | Fingerprint(FpKey)`

## Related Code Files

**Create:**
- `crates/waf-engine/src/checks/tx_velocity/mod.rs`
- `crates/waf-engine/src/checks/tx_velocity/config.rs`
- `crates/waf-engine/src/checks/tx_velocity/role_tagger.rs`
- `crates/waf-engine/src/checks/tx_velocity/recorder.rs`
- `crates/waf-engine/src/checks/tx_velocity/session_key.rs`

**Modify:**
- `crates/waf-engine/src/checks/mod.rs` — register `tx_velocity` submodule

**Reference (read-only, do not modify):**
- `crates/waf-engine/src/checks/rate_limit/check.rs:90` — cookie extraction pattern
- `crates/waf-engine/src/device_fp/behavior/recorder.rs:37-130` — ring buffer + janitor template

## Implementation Steps

1. **Define types** in `mod.rs`:
   ```rust
   pub enum EndpointRole { Login, Otp, Deposit, Withdrawal, LimitChange, None }
   pub struct Event { pub role: EndpointRole, pub ts_ms: u64, pub ok: bool }
   ```

2. **Config schema** (`config.rs`) — serde derive:
   - `endpoint_roles: Vec<RoleRule { role: EndpointRole, path: String /*regex*/ }>`
   - `classifiers: ClassifierConfigs` (placeholder structs)
   - `signal_cooldown_ms: u64` (default 5000)
   - `session_ttl_secs: u64` (default 600)

3. **RoleTagger** (`role_tagger.rs`):
   - Compile regexes once at config load
   - `fn classify(&self, path: &str) -> EndpointRole`
   - Return first matching rule; `None` if no match

4. **SessionKey extractor** (`session_key.rs`):
   - Reuse cookie name from rate-limit config or new field `session_cookie_name`
   - Extract cookie value; if absent, use `FpKey` from existing fingerprint pipeline
   - Return `SessionKey` or `None` (skip tracking when neither available)

5. **Recorder** (`recorder.rs`):
   - `pub struct TxStore { map: DashMap<SessionKey, ActorTx> }`
   - `ActorTx { events: ArrayVec<Event, 16>, last_signal_ms: u64 }`
   - `fn record(&self, key: SessionKey, event: Event)` — push, drop oldest if full
   - Janitor: `tokio::spawn` interval task, scan idle entries, remove

6. **Hot-reload** — wrap config in `ArcSwap`, watch file via `notify` (mirror FR-004 pattern)

7. **Run** `cargo fmt && cargo clippy -p waf-engine -- -D warnings && cargo check` after each file

## Todo List

- [ ] Create module scaffold + types in `mod.rs`
- [ ] Implement `config.rs` with serde + defaults
- [ ] Implement `role_tagger.rs` regex compile + classify
- [ ] Implement `session_key.rs` cookie + fp fallback
- [ ] Implement `recorder.rs` DashMap + ArrayVec ring buffer
- [ ] Implement janitor task (tokio interval)
- [ ] Wire hot-reload via `ArcSwap` + `notify`
- [ ] `cargo fmt && cargo clippy -- -D warnings && cargo check` clean

## Success Criteria

- [ ] `cargo check -p waf-engine` passes
- [ ] `cargo clippy -p waf-engine -- -D warnings` clean
- [ ] No `.unwrap()` / `todo!()` / `unimplemented!()` outside `#[cfg(test)]`
- [ ] Unit test: config round-trip (parse YAML → struct → serialize)
- [ ] Unit test: role tagger maps known paths correctly
- [ ] Unit test: recorder appends and overflow drops oldest
- [ ] Janitor smoke test: idle entry purged after TTL

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Regex compile cost on hot-reload | Compile once into config struct; ArcSwap atomic swap |
| DashMap contention under high load | Default shards sufficient; benchmark in Phase 4 |
| Cookie name varies per backend | Make `session_cookie_name` configurable |

## Security Considerations

- Validate regex patterns at config load (reject ReDoS-prone patterns or set timeout)
- Never log session cookie values (Iron Rule: no secret logging)
- TTL purge prevents memory exhaustion DoS
