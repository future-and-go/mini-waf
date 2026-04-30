# Phase 02 — Gateway Wiring (GatewayCtx + response_body_filter Hook)

**Goal:** Wire `BodyRedactor` into Pingora's `ProxyHttp` impl. Buffering lives in `GatewayCtx`; filtering happens in `response_body_filter`. Phase 01 must be merged/stable before starting.

**Status:** todo
**Depends on:** Phase 01 (`BodyRedactor`, `BodyRedactorConfig`, `is_json_content_type`)

## Files Touched

| File | Change |
|------|--------|
| `crates/gateway/src/proxy.rs` | Add `body_redactor: Option<Arc<BodyRedactor>>` to `WafProxy`; extend `GatewayCtx` (buffer + skip flag + content-type cache); implement `response_body_filter` |
| `crates/gateway/src/<wherever WafProxy is constructed>` | Construct `body_redactor` from `OutboundConfig::body_redactor` (mirror existing `header_filter` construction) |

**No** changes to `waf-engine` or `waf-common` in this phase.

## 1. `GatewayCtx` Extension

Locate the existing `GatewayCtx` struct in `crates/gateway/src/proxy.rs`. Add two fields with **safe-by-default polarity** (red-team C3 fix):

```rust
pub struct GatewayCtx {
    // ... existing fields ...

    /// FR-034 — buffered upstream JSON response bytes pending redaction.
    /// `Some` only after `response_filter` decided this response is JSON +
    /// uncompressed and worth redacting. `None` = skip path (default).
    pub response_body_buf: Option<bytes::BytesMut>,

    /// FR-034 — guard. `true` = no redaction work to do (default, safe).
    /// Flipped to `false` ONLY by `response_filter` when it has affirmatively
    /// opted this response in (JSON + no Content-Encoding + redactor present).
    /// Once redaction completes (or fails open), flipped back to `true`.
    /// Polarity inversion intentional: any code path that bypasses
    /// `response_filter` (early errors, WAF self-emitted block pages,
    /// future cache wiring that doesn't run response_filter on hits)
    /// inherits the safe `true` default and we never try to redact a
    /// non-opted-in response. (red-team C3.)
    pub body_redactor_done: bool,
}
```

Default in `new_ctx()` / wherever `GatewayCtx::default()` lives:
```rust
response_body_buf: None,
body_redactor_done: true,   // safe-by-default; response_filter flips to false on opt-in
```

The earlier draft had a separate `body_redactor_skip_reason` field — dropped. The skip decision collapses into "did `response_filter` opt this response in?" which is fully expressed by the two fields above.

## 2. `WafProxy` Field

Mirror existing `header_filter` field (line ~37 in `proxy.rs`):

```rust
pub struct WafProxy {
    // ... existing ...
    pub header_filter: Option<Arc<HeaderFilter>>,        // FR-035 (existing)
    pub body_redactor: Option<Arc<BodyRedactor>>,        // FR-034 (NEW)
}
```

Construction site (search for `header_filter:` in current proxy bootstrap — mirror exactly):
```rust
body_redactor: BodyRedactor::from_config(&cfg.outbound.body_redactor),
```

## 3. `response_filter` — Affirmative Opt-In

Extend the existing `response_filter` hook (currently strips headers). After header stripping, decide once whether body filtering should run for this response. With safe-by-default polarity (`body_redactor_done = true` at construction), this hook ONLY flips it to `false` on affirmative JSON+uncompressed opt-in:

```rust
async fn response_filter(
    &self,
    _session: &mut Session,
    upstream_response: &mut pingora_http::ResponseHeader,
    ctx: &mut GatewayCtx,
) -> pingora_core::Result<()> {
    // ... existing header_filter logic unchanged ...

    // FR-034 — opt this response in only if the redactor exists AND the
    // response is JSON AND uncompressed. Default ctx.body_redactor_done==true
    // covers every other path safely.
    if let Some(redactor) = self.body_redactor.as_ref()
        && response_is_redactable(upstream_response)
    {
        ctx.response_body_buf = Some(bytes::BytesMut::with_capacity(
            redactor.body_cap().min(8192)   // start small, grow on demand
        ));
        ctx.body_redactor_done = false;     // affirmative opt-in
    } else if self.body_redactor.is_some() {
        // Log skip reason for operator visibility (silent-leak surface — red-team M1).
        if upstream_response.headers.get("content-encoding").is_some() {
            tracing::info!("FR-034: skipping compressed response (Content-Encoding present)");
        }
    }

    Ok(())
}

/// True iff response is JSON (or +json) AND has no Content-Encoding.
/// Phase-1 compression strategy is hard-coded skip; future plans may
/// introduce a `compression_policy` config knob (red-team M1).
fn response_is_redactable(resp: &pingora_http::ResponseHeader) -> bool {
    if resp.headers.get("content-encoding").is_some() {
        return false;
    }
    let ct = resp.headers
        .get("content-type")
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
        .unwrap_or("");
    waf_engine::BodyRedactor::is_json_content_type(ct)
}
```

`Content-Length`-based skip is intentionally NOT here — Pingora may serve chunked or unknown-length responses. The 256 KiB cap in the body filter is the real budget.

## 4. `response_body_filter` Hook (NEW)

Insert directly after `response_filter` in the `ProxyHttp` impl block.

**Return type:** `pingora_core::Result<()>` — matches the existing `request_body_filter` at `crates/gateway/src/proxy.rs:284-290`. NOT `Result<Option<Duration>>` (red-team C1 — that signature would silently shadow the trait method via `async-trait`).

```rust
async fn response_body_filter(
    &self,
    _session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut GatewayCtx,
) -> pingora_core::Result<()> {
    // 1. Fast path: redactor disabled, response_filter decided to skip,
    //    or already finished this request. (Default `body_redactor_done = true`
    //    means we are SAFE BY DEFAULT — only `response_filter` flips it false
    //    after explicit JSON+uncompressed opt-in. See GatewayCtx defaults.)
    let Some(redactor) = self.body_redactor.as_ref() else { return Ok(()); };
    if ctx.body_redactor_done {
        return Ok(());
    }
    let Some(buf) = ctx.response_body_buf.as_mut() else {
        // Should not happen when body_redactor_done==false, but defensive.
        ctx.body_redactor_done = true;
        return Ok(());
    };

    let cap = redactor.body_cap();

    // 2. Append (and steal) the chunk from the proxy stream so we can re-emit.
    if let Some(chunk) = body.take() {
        if buf.len().saturating_add(chunk.len()) > cap {
            // Over cap — fail-open: drain accumulated buf + this chunk back into stream.
            tracing::warn!(
                buffered = buf.len(),
                chunk = chunk.len(),
                cap = cap,
                "FR-034: body over cap, passing through unredacted"
            );
            let mut joined = bytes::BytesMut::with_capacity(buf.len() + chunk.len());
            joined.extend_from_slice(buf);
            joined.extend_from_slice(&chunk);
            *body = Some(joined.freeze());
            ctx.body_redactor_done = true;
            ctx.response_body_buf = None;
            return Ok(());
        }
        buf.extend_from_slice(&chunk);
        // chunk is now consumed — caller sees None until end_of_stream OR cap reached.
    }

    // 3. Emit when EOS OR buffer at exact cap (defensive against unreliable
    //    end_of_stream — see researcher-02 §10 / Pingora GH#220). Reaching
    //    exact cap means the next chunk will trigger over-cap drain anyway,
    //    so flush early.
    if !end_of_stream && buf.len() < cap {
        return Ok(());
    }

    // 4. Final emission — try redaction.
    let buffered = std::mem::take(buf);
    ctx.body_redactor_done = true;
    ctx.response_body_buf = None;

    let final_bytes: Bytes = match redactor.redact_bytes(&buffered) {
        Some(redacted) => {
            tracing::debug!(
                original = buffered.len(),
                redacted = redacted.len(),
                "FR-034: body redacted"
            );
            Bytes::from(redacted)
        }
        None => {
            // Either no field matched or JSON malformed. Pass through original.
            buffered.freeze()
        }
    };

    *body = Some(final_bytes);
    Ok(())
}
```

### Why steal-and-replay (not redact in place)

`response_body_filter` may be invoked many times. Pingora forwards what's in `*body` after we return. To buffer, we must take the chunk out (set `*body = None`) so the proxy doesn't double-emit. On the final call we replace `*body` with the redacted (or pass-through) full body. Pingora handles `Content-Length` / `Transfer-Encoding` adjustment automatically (researcher-02 §4) — confirmed by integration test in Phase 03.

### Caching consideration (decided)

`response_body_filter` runs **after** Pingora's cache store. So:
- The cache holds **unredacted** bytes (intended — single source of truth).
- Every cache hit still walks this hook → still redacted.
- No special cache integration needed.

### Idempotency

`body_redactor_done` guards against the (unlikely but documented) case of `end_of_stream=true` firing twice (Pingora GH issue #220 cited by researcher-02). Once true, every subsequent invocation is a no-op pass-through.

## 5. Construction Site

Find where `header_filter:` is set on `WafProxy` (currently in the binary or `gateway` lib). Add a sibling line:

```rust
let body_redactor = waf_engine::BodyRedactor::from_config(&app_cfg.outbound.body_redactor);
let proxy = WafProxy {
    // ... existing ...
    header_filter,
    body_redactor,
};
```

Both fields are `Option<Arc<…>>` — symmetry preserved.

## Pre-Edit Impact Check

Before editing `proxy.rs`:
```
gitnexus_impact({target: "WafProxy", direction: "upstream"})
gitnexus_impact({target: "GatewayCtx", direction: "upstream"})
gitnexus_impact({target: "response_filter", direction: "upstream"})
```
The proxy is the request-path hot module — verify no surprise consumers before extending the struct. If risk = HIGH, pause and report.

## Build Verification (gate before Phase 03)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo build --release
cargo test -p gateway
```

All clean. No new clippy warnings on `proxy.rs` (must keep -D warnings).

## Success Criteria

- `WafProxy` compiles with new field; default constructor / config-loader paths set `body_redactor`.
- With `enabled=false` (default): hook is a no-op (`Some(redactor)` is `None`); zero allocation, zero behaviour change.
- With `enabled=true`: a non-JSON or compressed response is buffered for ZERO chunks (skip set in `response_filter`); a JSON response is buffered up to cap and redacted on `end_of_stream`.
- Existing FR-035 header-filter integration tests still pass.
- `cargo clippy` clean across `waf-common`, `waf-engine`, `gateway`.

## Out of Scope (Phase 02)

- TOML defaults — Phase 03.
- E2E tests with real backend — Phase 03.
- Compression handling beyond skip — out of plan entirely.
- Per-route policy — out of plan.
