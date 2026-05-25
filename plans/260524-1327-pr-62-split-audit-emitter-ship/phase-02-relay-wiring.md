---
phase: 2
title: "PR-B: relay wiring — emit BOT-XFF / BOT-RELAY signals"
status: pending
priority: P2
effort: "1d"
dependencies: [1]
pr_branch: "feat/audit-emitter-relay-wiring-issue-60-b"
loc_estimate: 550
red_team_applied: F-S-3, F-S-5, F-A-3, F-F-10
---

# Phase 2: Relay wiring

## Overview

Wire `audit_emitter` (từ phase 01) vào relay signal pipeline. Khi relay fire `BOT-XFF-001`, `BOT-RELAY-001`, **`BOT-TOR-001`** (renamed từ `BOT-RELAY-TOR-001` per BP6 grammar) → 1 row vào `security_events` qua `audit_emitter`. Populate `FeedStatusRegistry` (skeleton đã ship phase 01). Tech guide update IN same PR (per BP1/F-F-10).

## Requirements

### Functional
- Relay signal hook tại `gateway/src/proxy.rs` post-host-resolve emit qua `audit_emitter` cho mỗi signal variant
- Mapping signal variant → (rule_id, rule_name, action, **structured JSON detail**) via `relay::audit_map::signal_to_audit`
- `client_ip` cho `AuditCtx` lấy từ `peer_addr` ONLY (F-S-3) — KHÔNG parse XFF cho đến khi sub-issue #74.3 `trust_xff_from` config land
- `detail` JSON: strip query-string khỏi path, escape HTML chars, cap 4KB per row (F-S-5)
- Populate `FeedStatusRegistry` (ship skeleton phase 01) khi relay startup load feeds
- Rule_id literals: `BOT-XFF-001`, `BOT-RELAY-001`, **`BOT-TOR-001`** (3-segment grammar per BP6)

### Non-functional
- Coverage ≥ 90% trên relay changes
- BP1 (no finding codes) applied
- Mock DB trong tests
- Smoke test trong Docker: send request với XFF spoof → assert row trong `security_events` với expected rule_id

## Architecture

```
proxy.rs request_filter
        │
        ├─ host resolve (effective_host_header → router.resolve)
        ├─ relay::evaluate(req) → Vec<Signal>
        │       │
        │       └─ for each signal:
        │             AuditEmitter::emit(ctx, signal_to_audit(s)…)
        │
        ├─ continue WAF pipeline
```

`FeedStatusRegistry` tách riêng — quản lý feed load state khi startup, infra cần cho `/api/reputation/status` (phase 04).

## Related Code Files

### Create
- `crates/waf-engine/src/relay/audit_map.rs` — `signal_to_audit(&Signal) -> (rule_id, rule_name, action, detail_json)` returns sanitised JSON string
- `crates/waf-engine/tests/relay_audit_map.rs` — unit tests cho mapping + sanitisation

(Note: `intel_status.rs` đã ship trong phase 01 per F-F-9. Phase 02 chỉ populate.)

### Modify
- `crates/waf-engine/src/relay/mod.rs` — re-export `audit_map`; wire `FeedStatusRegistry` populate trên load
- `crates/waf-engine/src/relay/signal.rs` — verify signal variants enumeration
- `crates/gateway/src/proxy.rs` — relay emit hook; `client_ip = peer_addr.to_string()` ONLY (F-S-3 — drop XFF parse)
- `crates/waf-engine/src/engine.rs` — propagate `set_audit_emitter` vào relay context
- `docs/PRX-WAF-TechnicalGuide-EN.md` + `docs/PRX-WAF-TechnicalGuide-VI.md` — update rule_id table: `BOT-RELAY-TOR-001` → `BOT-TOR-001` (F-A-3 rename) (per F-F-10: docs update IN same PR)

### Delete
None.

## Implementation Steps (TDD)

### Step 1 — Write failing tests

1.1. `tests/relay_audit_map.rs`:
- `bot_xff_signal_maps_to_bot_xff_001`
- `bot_relay_signal_maps_to_bot_relay_001`
- `tor_signal_maps_to_bot_tor_001` (renamed)
- `detail_strips_query_string`
- `detail_html_escapes_path_chars` (F-S-5: `<script>` → `&lt;script&gt;`)
- `detail_truncated_at_4kb_boundary_safe`
- `detail_is_compact_json`

1.2. Integration test (`tests/relay_emission_integration.rs`):
- `xff_header_does_not_change_client_ip_in_audit` (F-S-3: peer_addr only)
- `peer_addr_used_as_audit_client_ip`
- `multiple_signals_emit_distinct_rows`
- `disabled_emitter_short_circuits_no_db_write`
- `rate_limit_same_peer_addr_same_rule_id_collapses_per_window`
- `rotating_peer_addr_hits_global_token_bucket_layer_2` (F-S-4 from phase 01)

1.3. Mock DB trait already from phase 01 — reuse.

1.4. Run trong Docker — **all FAIL**.

### Step 2 — Implement

2.1. `relay/audit_map.rs` — pure mapping fn returning sanitised detail JSON via `audit_emitter::sanitize::sanitize_detail` (phase 01 helper). Rule IDs (3-segment grammar):
```rust
pub const BOT_XFF_RULE_ID: &str = "BOT-XFF-001";
pub const BOT_RELAY_RULE_ID: &str = "BOT-RELAY-001";
pub const BOT_TOR_RULE_ID: &str = "BOT-TOR-001";  // renamed từ BOT-RELAY-TOR-001 per F-A-3 + BP6

pub fn signal_to_audit(sig: &Signal) -> (&'static str, &'static str, &'static str, String) {
    // detail: strip query-string, html-escape, JSON-encode, cap 4KB
    let detail = sanitize_detail(sig);
    match sig {
        Signal::XffSpoof { .. } => (BOT_XFF_RULE_ID, "Relay: XFF spoof", "block", detail),
        // ... per variant
    }
}

fn sanitize_detail(sig: &Signal) -> String {
    // 1. strip ?.+ from path
    // 2. html_escape::encode_text on user strings
    // 3. serde_json::to_string
    // 4. truncate at 4096 bytes (boundary-safe)
}
```

2.2. (Skipped — `intel_status.rs` đã ship phase 01.) Phase 02 chỉ populate `FeedStatusRegistry` khi relay startup load feeds (Tor list, ASN list).

2.3. `proxy.rs` emit hook — read main fresh, verify line shift sau `effective_host_header()` ở `proxy.rs:416-423`. Insert:
```rust
if let Some(emitter) = ctx.audit_emitter.as_ref() {
    let audit_ctx = AuditCtx {
        host_code: &host_code,
        client_ip: &peer_addr.to_string(),  // F-S-3: peer_addr ONLY, no XFF
        method: method.as_str(),
        path: req.uri.path(),  // sanitize_detail strips query inside audit_map
    };
    for sig in &relay_signals {
        let (rule_id, rule_name, action, detail) = relay::audit_map::signal_to_audit(sig);
        emitter.emit(&audit_ctx, rule_id, rule_name, action, Some(detail));
    }
}
```

2.4. `engine.rs` propagate audit_emitter Arc tới relay context — verify existing access pattern (read main `engine.rs` 942 LOC trước).

2.5. Tech guide update — rename `BOT-RELAY-TOR-001` → `BOT-TOR-001` trong cả EN + VI guides; verify regex contract test (from phase 01 BP6) passes cho 3 constants.

2.5. Tests pass.

### Step 3 — Refactor + verify

3.1. `cargo fmt`, `cargo clippy` clean.
3.2. Coverage ≥ 90% trên modified files.
3.3. Grep gate (BP1): no finding codes.
3.4. Squash, push, PR.

### Step 4 — PR draft body

```markdown
## Summary

Wires the `audit_emitter` (phase 01) into the relay signal pipeline. When relay
detects an XFF spoof, proxy chain, or Tor exit, a row lands in `security_events`
tagged with the appropriate `rule_id`.

## Rationale

Tech guide documents `BOT-XFF-*`, `BOT-RELAY-*`, `BOT-RELAY-TOR-001` (renamed
to `BOT-TOR-001` in this PR — 3-segment grammar) as if they
already persist. They don't — relay signals are computed in-process but never
stored. Admin panel filters on these `rule_id` strings return empty. This PR
closes the gap.

## Changes

- New `relay/audit_map.rs` — `signal_to_audit(&Signal)` mapping fn + 3 rule_id
  constants matching docs.
- New `relay/intel/status.rs` — `FeedStatusRegistry` (feed load state snapshot).
  Used by the follow-up admin API PR; landed here so the relay module owns its
  status type.
- `gateway/src/proxy.rs` — emit hook after host resolution, one emit per signal.
- `waf-engine/src/engine.rs` — propagate `Arc<AuditEmitter>` to relay context.

## Tests

- Unit: 4 tests on `signal_to_audit` mapping
- Integration: 4 tests on end-to-end XFF→DB row, multi-signal fanout, disabled-
  emitter short-circuit, rate-limit collapse
- Mock DB for deterministic assertions
- Coverage ≥ 90% on modified files
```

## Success Criteria

- [ ] All tests in step 1 pass
- [ ] `cargo fmt --check`, `cargo clippy` clean
- [ ] Coverage ≥ 90%
- [ ] BP1 grep gate clean
- [ ] PR opened, CI green, NOT merged
- [ ] 1 squashed commit
- [ ] Tech guide (`docs/PRX-WAF-TechnicalGuide-*.md`) updated nếu detail format đổi (likely no change — keep existing rule_id table)

## Risk Assessment

| Risk | Mitigation |
|---|---|
| `proxy.rs:432` (PR #62 anchor) shifted sau commit `331efc43`/PR #103 | Step 2.3 re-read main `proxy.rs` (1401 LOC); search for `effective_host_header(` callsite + insert ngay sau resolved host_header is non-empty |
| Relay signal variants thay đổi giữa PR #62 (2026-05-18) và main hiện tại | Step 2.1 grep `enum Signal` trong main `relay/signal.rs`; map all variants |
| XFF parsing để get real client_ip cho audit_ctx — main proxy.rs có XFF trust config không? | Verify; if no `trust_xff_from` config exists trên main, use `req_header().remote_addr` fallback + flag trong PR description (cross-link sub-issue #74.3 trust_xff_from) |

## Next Phase

Phase 03 (tx_velocity wiring) — parallel (no shared files).
Phase 04 (admin API) — blocked by this phase merge (needs `FeedStatusRegistry`).
