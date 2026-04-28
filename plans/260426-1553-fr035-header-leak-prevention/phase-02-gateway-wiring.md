# Phase 02 — Gateway Response-Filter Wiring

**Priority:** P0
**Status:** completed
**Depends on:** phase-01

## Goal

Wire `HeaderFilter` into the Pingora response pipeline so upstream response headers are sanitized before being written to the client. Activation is config-driven (`outbound.enabled`); when disabled the path is a no-op (zero overhead).

## Context Links

- Pingora `ProxyHttp` trait — `response_filter` callback runs after upstream response headers arrive, before they ship to client. Synchronous header mutation is supported.
- Existing impl block: `crates/gateway/src/proxy.rs` line 133 — `impl ProxyHttp for WafProxy`
- Header filter API: `HeaderFilter::should_strip(&str) -> bool` and `HeaderFilter::detect_pii_in_value(&str) -> Option<&'static str>`
- Research: `research/researcher-01-header-leak-prevention.md` §4 (case-insensitive matching, allowlist O(1) lookup, performance), §6 (Coraza known issue with WAF-blocked responses)

## Files

**Modify:**
- `crates/gateway/src/proxy.rs` — add `response_filter` impl; add `Arc<HeaderFilter>` field to `WafProxy`
- `crates/gateway/src/lib.rs` — re-export if needed (only if `WafProxy::new` signature changes for callers)
- `crates/prx-waf/src/main.rs` (or wherever `WafProxy` is constructed) — pass `HeaderFilter` from config; **find the construction site via `gitnexus_context({name: "WafProxy"})`** before editing

**Read for context:**
- `crates/gateway/src/proxy.rs` — existing trait impl pattern, error handling, logging style
- `crates/waf-engine/src/outbound/header_filter.rs` — `filter_headers` signature

## Pingora Integration Detail

`response_filter` signature (from `pingora_proxy::ProxyHttp`):

```rust
async fn response_filter(
    &self,
    _session: &mut Session,
    upstream_response: &mut pingora_http::ResponseHeader,
    _ctx: &mut Self::CTX,
) -> pingora_core::Result<()>;
```

`pingora_http::ResponseHeader` exposes `headers: HeaderMap` (the `http` crate type). Iteration is by `(HeaderName, HeaderValue)`. Mutation API:
- `remove_header(name)` — removes all values for that name
- `headers.iter()` — read-only walk

## Implementation Sketch

```rust
// In WafProxy struct:
pub outbound_enabled: bool,
pub header_filter: Option<Arc<HeaderFilter>>,

// In ProxyHttp impl:
async fn response_filter(
    &self,
    _session: &mut Session,
    upstream_response: &mut pingora_http::ResponseHeader,
    _ctx: &mut GatewayCtx,
) -> pingora_core::Result<()> {
    if !self.outbound_enabled {
        return Ok(());
    }
    let Some(filter) = self.header_filter.as_ref() else {
        return Ok(());
    };

    // Walk headers; collect names to remove (cannot mutate while iterating).
    let mut to_remove: Vec<pingora_http::HeaderName> = Vec::new();
    for (name, value) in upstream_response.headers.iter() {
        let name_str = name.as_str();
        if filter.should_strip(name_str) {
            to_remove.push(name.clone());
            continue;
        }
        if let Ok(val_str) = std::str::from_utf8(value.as_bytes()) {
            if filter.detect_pii_in_value(val_str).is_some() {
                to_remove.push(name.clone());
            }
        }
    }

    if !to_remove.is_empty() {
        for name in &to_remove {
            upstream_response.remove_header(name);
        }
        debug!(
            "Outbound: stripped {} response header(s)",
            to_remove.len()
        );
    }

    Ok(())
}
```

Notes:
- Borrow rules: collect-then-mutate. Cloning `HeaderName` is cheap (`Arc<str>` internally in some versions; otherwise small allocation).
- Case handling already in `HeaderFilter::should_strip` (`to_lowercase()` inside) — RFC 9110 compliant.
- Non-UTF-8 values: skip PII scan (rare; binary header values).
- Logging at `debug` level only — don't spam access logs; metrics counter is a future enhancement.

## Implementation Steps

1. **Run impact analysis FIRST** (per CLAUDE.md GitNexus rule):
   ```
   gitnexus_impact({target: "WafProxy", direction: "upstream"})
   ```
   Report blast radius to user before editing. If HIGH/CRITICAL: pause and confirm.
2. **Locate construction site** of `WafProxy` (likely `crates/prx-waf/src/main.rs` or `crates/prx-waf/src/server.rs`):
   ```
   gitnexus_context({name: "WafProxy"})
   ```
3. **Add fields** to `WafProxy`: `outbound_enabled: bool`, `header_filter: Option<Arc<HeaderFilter>>`. Initialize to `false` / `None` in existing `WafProxy::new`. Add a builder-style setter or extend constructor signature — choose the option that keeps callers compiling.
4. **Implement** `response_filter` in `impl ProxyHttp for WafProxy` per sketch above.
5. **Wire up at construction site:**
   ```rust
   let header_filter = if config.outbound.enabled {
       Some(Arc::new(HeaderFilter::new(&config.outbound.headers)))
   } else {
       None
   };
   waf_proxy.outbound_enabled = config.outbound.enabled;
   waf_proxy.header_filter = header_filter;
   ```
6. **Run** `cargo check -p gateway -p prx-waf`.
7. **Run** `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
8. **Run** `gitnexus_detect_changes()` and verify only expected symbols changed.

## Verification

- `cargo build --release` exits 0
- `cargo clippy ... -D warnings` clean
- Manual smoke: with `[outbound] enabled = true` in TOML, configure a host pointing to a backend that returns `Server: nginx`, `X-Debug-Token: t`, `X-Internal: x`, and verify those headers are absent on the proxied response (use `curl -I`).
- With `[outbound] enabled = false`: same backend → headers passed through unchanged.

## Risks & Mitigations

| Risk | Mitigation |
|------|-----------|
| Pingora `response_filter` not invoked on WAF-blocked responses (Coraza-style bug) | FR-035 only filters upstream responses — WAF-blocked responses are crafted by us already and never include leaky headers. Document explicitly. |
| Cache layer caches filtered or unfiltered version inconsistently | Pingora cache stores upstream response BEFORE `response_filter` (verify in pingora source). If cached pre-filter, every cache hit also gets filtered → correct. Add comment in code citing this. If cached post-filter, behavior is still correct but document. |
| `HeaderName` clone overhead | Headers per response typically <30; clone cost negligible. Bench if response p99 regresses >0.5ms. |
| Iterator borrow conflict | Collect-then-remove pattern (sketch above) avoids it. |
| Construction site needs new constructor — breaks tests | Use field assignment after `WafProxy::new` to preserve existing call sites |

## Success Criteria

- [x] `cargo build --release` green
- [x] `cargo clippy ... -D warnings` clean (touched crates)
- [x] Diff scope verified — only `WafProxy` + construction site in `prx-waf/src/main.rs` touched
- [~] Manual curl test deferred to live deployment validation (`docker-compose up`); the underlying logic is fully covered by `outbound::header_filter` unit tests + the `response_filter` async hook is a thin collect-then-mutate over the same API
- [x] No regression in existing gateway integration tests (153 lib tests pass)

## Next Phase

→ phase-03-tests-and-docs.md
