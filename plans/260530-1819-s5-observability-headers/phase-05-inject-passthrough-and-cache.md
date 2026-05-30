---
phase: 5
title: "Inject on Passthrough + Cache-Hit"
status: pending
priority: P1
effort: "3h"
dependencies: [2, 3]
---

# Phase 5: Inject on Passthrough + Cache-Hit Paths

## Overview
Inject the 6 headers on allowed upstream responses (`response_filter`), access-bypass passthrough,
challenge-passed passthrough, and cache-HIT responses (`write_cached_entry`) — with the ordering
invariant that prevents FR-035 stripping and cache poisoning.

## Requirements
- Functional: passthrough + HIT responses carry all 6 headers; `X-WAF-Cache` accurate.
- Non-functional: X-WAF-* headers are per-request fresh — NEVER stored in a cache entry.

## Architecture
`response_filter` (proxy.rs:792): inject **as the final step**, AFTER (a) `response_chain.apply_all`,
(b) the FR-035 `header_filter` block (lines 910-930), AND (c) `begin_upstream_cache_capture`
(lines 935-943). Inject after line 943, before `Ok(())`. This guarantees FR-035 cannot strip them
and the cache snapshot never contains them (red-team F3 + F4). Read values from `ctx.waf_decision_meta`
(present for allow, bypass, challenge-passed) + `request_ctx.req_id` + `ctx.cache_status`
(`MISS` when filling, else `BYPASS`).

`write_cached_entry` (response_cache_integration.rs:12): bypasses `response_filter` entirely on HIT.
Inject AFTER the header-replay loop with `cache = HIT`, `req_id` from ctx, and `action`/risk/rule/mode
**from `ctx.waf_decision_meta`** (NOT hardcoded `allow` — red-team F9; preserves log_only intended action).
It needs `ctx` access — thread `&GatewayCtx` (or the resolved `WafHeaderValues`) into the call at proxy.rs:707.

**Mandatory cache-poison guard:** in `begin_upstream_cache_capture` (response_cache_integration.rs:51),
after `collect_response_headers`, unconditionally drop any header whose name starts with `x-waf-`
from `pending.headers`. Belt-and-suspenders with inject-last (red-team F3/F6). This is an
unconditional implementation step, not a "verify if needed".

Snapshot-None fallback: if `waf_decision_meta` is `None` (should not occur after Phase 3 sets it on
all outcomes), emit all 6 with `action="allow"`, `risk=0`, `rule_id=none`, `mode`=global default
(NOT hardcoded enforce — red-team F8). Still emit all 6 (contract: EVERY response).

## Related Code Files
- Modify: `crates/gateway/src/proxy.rs` (`response_filter` — inject as final step)
- Modify: `crates/gateway/src/response_cache_integration.rs` (`write_cached_entry` inject; `begin_upstream_cache_capture` x-waf-* strip)
- Read for context: `crates/gateway/src/filters/response_header_blocklist_filter.rs`, FR-035 block proxy.rs:906-930

## Implementation Steps
1. `response_filter`: after the cache-capture block, read req_id + meta + cache_status; inject.
2. `begin_upstream_cache_capture`: strip `x-waf-*` from `pending.headers` after collection (unconditional).
3. `write_cached_entry`: thread ctx/values; inject with `CacheStatus::Hit` and `action` from meta.
4. Integration tests:
   - (a) allowed proxied response: all 6 + `X-WAF-Cache: MISS`/`BYPASS`; assert FR-035 did NOT strip them.
   - (b) HIT: all 6 + `X-WAF-Cache: HIT` + a FRESH `X-WAF-Request-Id` differing from the fill request (proves no stale replay).
   - (c) access-bypass passthrough carries all 6 (`X-WAF-Action: allow`).
   - (d) the cached entry's stored headers contain NO `x-waf-*` (assert on the put payload / second-hit).

## Success Criteria
- [ ] Allowed/proxied + bypass + challenge-passed responses carry all 6 (FR-035 does not strip them)
- [ ] HIT carries all 6, `X-WAF-Cache: HIT`, fresh per-request `X-WAF-Request-Id`, action from meta
- [ ] MISS/BYPASS report correct `X-WAF-Cache`
- [ ] Stored cache entry contains no `x-waf-*` (no stale replay)
- [ ] `cargo test -p gateway` green; clippy clean

## Risk Assessment
- Risk: injecting before FR-035/capture → strip or poison. Mitigation: inject-last invariant + capture strip (tested).
- Risk: `write_cached_entry` signature change ripples to call site/tests → update both.

## Security Considerations
- Cache MUST NOT replay one client's `X-WAF-Request-Id`/score to another (privacy + §5 correlation).
- `X-WAF-Cache: BYPASS` holds for auth/cookie/non-allow routes (Phase 3 cache_status logic).
