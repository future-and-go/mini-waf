# Pingora Streaming Response-Body Filtering Research
**Date:** 2026-04-28 | **Topic:** FR-034 Sensitive JSON Field Redaction via Response Body Filter API
**Scope:** Pingora 0.8 response-body filtering mechanics, cache interaction, compression handling

---

## Executive Summary

**Verdict:** Pingora's `response_body_filter` + optional `upstream_response_body_filter` can implement streaming JSON field redaction for FR-034. The API is streaming-native (chunk-by-chunk) but **requires full buffering for JSON parsing**. Two critical constraints: (1) `end_of_stream` may be unreliable (GH issue #220, closed), (2) Content-Length recalculation is automatic but requires chunked encoding if body size changes. Caching implications differ: modifications in `upstream_response_filter` (headers) get cached; modifications in `response_body_filter` do not. **Recommended placement: `response_filter` for headers + `response_body_filter` for body**, mirroring existing FR-035 pattern.

---

## 1. API Signatures (Pingora 0.8)

### ProxyHttp Trait Method Signatures

Per [Cloudflare Pingora ProxyHttp trait documentation](https://docs.rs/pingora/latest/pingora/prelude/trait.ProxyHttp.html):

```rust
// Provided method (optional override)
async fn response_filter(
    &self,
    session: &mut Session,
    upstream_response: &mut pingora_http::ResponseHeader,
    ctx: &mut Self::CTX,
) -> pingora_core::Result<()>
```

**Signature:** Filters response headers after cache retrieval, runs for cached + freshly-fetched responses.

```rust
// Provided method (optional override)
async fn response_body_filter(
    &self,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut Self::CTX,
) -> pingora_core::Result<()>
```

**Signature:** Called per-chunk for response body. Parameters:
- `session: &mut Session` — HTTP session, read response headers via `session.resp_header()`
- `body: &mut Option<Bytes>` — Current chunk; `None` if no data. Mutable; can replace/truncate in-place
- `end_of_stream: bool` — `true` when this is final chunk (or stream interrupted). **CAUTION:** [Issue #220](https://github.com/cloudflare/pingora/issues/220) reported this may be unreliable in streaming scenarios
- `ctx: &mut Self::CTX` — Per-request context (e.g., `GatewayCtx`). Can persist buffer state across calls
- **Return:** `pingora_core::Result<()>` — `Err(_)` calls `fail_to_proxy()` and terminates request

Alternative (less-used):

```rust
async fn upstream_response_body_filter(
    &self,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut Self::CTX,
) -> pingora_core::Result<()>
```

**Signature:** Same as `response_body_filter` but runs on **upstream** response before cache storage. Modifications here are **stored in cache**; `response_body_filter` modifications are **not** cached.

### Request-Side Counterpart (for reference)

```rust
async fn request_body_filter(
    &self,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut Self::CTX,
) -> pingora_core::Result<()>
```

Similar signature, called for inbound request chunks before proxying to upstream.

---

## 2. Lifecycle & Phase Ordering

### Complete Request-Response Cycle (Pingora 0.8)

Per [Life of a request phases guide](https://github.com/cloudflare/pingora/blob/main/docs/user_guide/phase.md):

```
Request IN:
  early_request_filter()
    ↓
  request_filter()
    ↓
  upstream_peer()  ← Must return peer address
    ↓
  connect to upstream
    ↓
  connected_to_upstream()
    ↓
  upstream_request_filter()  ← Modify request headers before sending
    ↓
  request_body_filter()  ← Per-chunk buffering for inbound request body
    ↓
  [UPSTREAM PROCESSES REQUEST]

Response IN:
  upstream_response_filter()  ← Sync, headers only, BEFORE cache
    ↓
  upstream_response_body_filter()  ← Per-chunk, BEFORE cache (mods are stored)
    ↓
  [HTTP CACHE STORE if enabled]
    ↓
  response_filter()  ← Headers, AFTER cache (cache hits also see this)
    ↓
  response_body_filter()  ← Per-chunk, AFTER cache (mods not stored)
    ↓
  logging()
```

### Key Timeline for FR-034

1. **`upstream_response_filter()`** (line ~372 in existing crates/gateway/src/proxy.rs):
   - Runs once per response, headers only
   - Runs **BEFORE** cache store → modifications **ARE** cached
   - Already used for FR-035 (header stripping)
   - Safe place to strip sensitive headers *before* they're cached

2. **`upstream_response_body_filter()`** (not yet used):
   - Runs per chunk, for response body, **BEFORE** cache
   - If you buffer & modify body here, modified body is **cached**
   - ⚠️ Problem: For redaction, you usually want to **not cache** the redacted body (compliance issue if cache is breached)

3. **`response_filter()` → headers only** (existing code):
   - Runs per response (including cache hits), headers only
   - Modifications **NOT** cached

4. **`response_body_filter()`** (not yet used):
   - Runs per chunk, for response body, **AFTER** cache
   - Modifications **NOT** cached
   - **RECOMMENDED for FR-034** if you want: (a) cached body is unredacted (security-in-depth), (b) redaction happens on every response regardless of cache origin

### Caching Implication Summary

| Phase | Headers | Body | Cached? | Cache Hit? |
|-------|---------|------|---------|-----------|
| `upstream_response_filter` | ✅ | ❌ | **YES** (headers stored) | No (runs before cache) |
| `upstream_response_body_filter` | ❌ | ✅ | **YES** (body stored) | No (runs before cache) |
| `response_filter` | ✅ | ❌ | ❌ (after cache) | **YES** (runs on all) |
| `response_body_filter` | ❌ | ✅ | ❌ (after cache) | **YES** (runs on all) |

**Decision for FR-034:** Use `response_body_filter` to ensure **all** responses (cache hit or fresh) are redacted, and **cache stores unredacted** body (better security posture).

---

## 3. Compression Handling

### Does Pingora Decompress Automatically?

**No.** Pingora does **not** auto-decompress `Content-Encoding: gzip/br/deflate/zstd` responses.

Per [GitHub Issue #523](https://github.com/cloudflare/pingora/issues/523) (Compression of Response Body):
- Upstream response with `Content-Encoding: gzip` arrives to `response_body_filter` **still gzipped**
- Body chunks passed to filter are **raw compressed bytes**
- You receive gzip stream as-is; Pingora does **not** unwrap it

### Approach for JSON Redaction in Compressed Responses

**Option A: Skip compressed (Recommended for MVP)**
```rust
if let Some(encoding) = session.resp_header().get("content-encoding") {
    // Skip body redaction if compressed
    return Ok(());
}
```
Rationale: Gzip streaming decompression is complex; most APIs should compress on-demand (not pre-gzipped from upstream). If upstream sends gzip, likely rare case.

**Option B: Full decompress-redact-recompress (Higher complexity)**
Requires:
1. Detect `Content-Encoding: gzip` in response headers
2. In `response_body_filter`, accumulate ALL chunks
3. On `end_of_stream==true`, decompress entire body using `flate2` crate
4. Parse decompressed JSON, redact fields
5. Re-serialize, re-compress to gzip
6. Update `Content-Length` or strip it (use `Transfer-Encoding: chunked`)
7. Restore `Content-Encoding: gzip` header
8. Return modified compressed body

⚠️ Trap: If upstream sends `Transfer-Encoding: chunked + Content-Encoding: gzip`, you must:
- Remove both headers after recompressing (set chunked manually)
- Let Pingora send new `Content-Length` if body size changed

**Option C: Force upstream to not compress**
Add to `upstream_request_filter`:
```rust
session.req_header_mut().insert_header("accept-encoding", "identity")?;
```
Pros: Avoids recompression complexity. Cons: Adds bandwidth if upstream respects it (most do).

**Recommendation:** Start with **Option A** (skip compressed). Add Option B if real-world traffic shows upstream gzip. Document rationale in rules.

---

## 4. Content-Length & Transfer-Encoding Behavior

### Auto-Recalculation

**Pingora automatic behavior per RFC 9112:**

When you modify `body` in `response_body_filter`:
- If `Content-Length` header exists:
  - Pingora **validates** it matches actual bytes on read
  - If you change body size (redaction shortens, repadding lengthens), Pingora **removes** `Content-Length`
  - Pingora **automatically** switches to `Transfer-Encoding: chunked`
- If `Transfer-Encoding: chunked` header exists:
  - Pingora **removes** `Content-Length` (RFC rule: chunked XOR content-length)
  - Your body mutations are framed as chunks downstream

### What You Must Do

**In `response_filter` (headers):** No action needed; Pingora handles removal/replacement.

**In `response_body_filter` (body):** No action needed; Pingora recalculates framing. Just modify the body:
```rust
if let Some(body_chunk) = body {
    *body = Some(redact_json_fields(body_chunk));
    // Pingora will recompute Content-Length or switch to chunked
}
```

### Caveat: Trailers & Chunked Extensions

If upstream response has `Transfer-Encoding: chunked` with trailers (e.g., `X-Checksum-SHA256` trailer):
- Pingora preserves trailers through `response_body_filter`
- Your modifications don't affect trailer bytes (they come after body)
- This is safe

---

## 5. Buffering Pattern for JSON Parsing

### Why Buffering is Required

Pingora's `response_body_filter` is **streaming** (chunk-by-chunk), but JSON parsing is **random-access**.

You **cannot** parse JSON incrementally on partial chunks. Example:
```
Chunk 1: {"user":"alice","email":"alice@
Chunk 2: example.com","ssn":"123-45-6789"}
```
Only on Chunk 2 (with `end_of_stream==true`) can you have valid JSON.

### Buffer Storage in GatewayCtx

**Current implementation (request body, from crates/gateway/src/context.rs):**
```rust
pub struct GatewayCtx {
    pub body_buf: BytesMut,  // Accumulates first 64 KiB
    pub body_inspected: bool,
}

pub const BODY_PREVIEW_LIMIT: usize = 64 * 1024;  // 64 KiB request limit
```

**For response body, add parallel fields:**
```rust
pub struct GatewayCtx {
    // ... existing ...
    
    // Response body buffering for redaction
    pub response_body_buf: BytesMut,      // Accumulates response chunks
    pub response_body_redacted: bool,     // Set true after redacting once
}
```

### Buffering Algorithm

```rust
async fn response_body_filter(
    &self,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut GatewayCtx,
) -> pingora_core::Result<()> {
    // Skip if no body or already redacted
    if ctx.response_body_redacted {
        return Ok(());
    }
    
    // Skip if no content-type or not JSON
    if !is_json_content_type(session) {
        return Ok(());
    }
    
    // Skip if gzip/deflate (for MVP)
    if has_compression(session) {
        return Ok(());
    }
    
    // Accumulate chunk
    if let Some(chunk) = body {
        ctx.response_body_buf.extend_from_slice(chunk);
    }
    
    // Only redact on end_of_stream
    if !end_of_stream {
        return Ok(());
    }
    
    ctx.response_body_redacted = true;
    
    // Parse and redact accumulated JSON
    let redacted = redact_json(&ctx.response_body_buf)?;
    *body = Some(Bytes::from(redacted));
    
    Ok(())
}
```

### Size Cap Decision

Per prx-waf architecture (inline WAF, low latency), recommend:

| Cap | Rationale |
|-----|-----------|
| **256 KiB** | Default. Covers most JSON API responses (e.g., user profiles, search results). Exceeding → skip redaction, pass through unredacted (log warning). |
| **1 MiB** | If API responses commonly exceed 256 KiB (rare for JSON). Increases memory pressure per request. |
| **8 KiB** | If only redacting small objects (e.g., error messages). Wastes less memory. |

**Recommendation:** Start with **256 KiB**. Tune based on metrics (monitor `response_body_buf` peak allocation).

Memory calculation: If 1000 req/sec concurrent with 256 KiB each → 256 MB heap per second; tokio async tasks can queue, so worst-case ~5-10 GiB if response processing stalls. Keep buffer size reasonable.

---

## 6. Skip Conditions & Content-Type Detection

### Recommended Skip Logic

```rust
fn is_json_content_type(session: &Session) -> bool {
    session
        .resp_header()
        .get("content-type")
        .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
        .map(|s| s.contains("application/json") || s.contains("application/ld+json"))
        .unwrap_or(false)
}

fn has_compression(session: &Session) -> bool {
    session
        .resp_header()
        .get("content-encoding")
        .is_some()
}
```

### When to Skip

1. **No `Content-Type: application/json`** → Not JSON, skip
2. **Has `Content-Encoding: gzip/br/deflate/zstd`** → Compressed, skip (Option A)
3. **Status code 304 Not Modified** → No body, skip
4. **Status code 204 No Content / 1xx / 3xx** → No body, skip
5. **Content-Type: application/octet-stream** → Binary, skip
6. **Response body exceeds 256 KiB** → Log warning, pass through unredacted (fail-open, not fail-closed)

### Integrating with Existing Response Headers

`response_body_filter` receives `session: &mut Session`, which has:
```rust
session.resp_header()        // Returns &ResponseHeader (immutable)
session.resp_header_mut()    // For mutations (if needed)
```

Example:
```rust
let content_type = session.resp_header()
    .get("content-type")
    .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
    .unwrap_or("");

if !content_type.contains("application/json") {
    return Ok(());
}
```

---

## 7. Failure Modes & Safe Defaults

### What Happens When Body Filter Returns Error

Per Pingora design:

```rust
// In pingora proxy loop:
match response_body_filter(session, body, eos, ctx).await {
    Ok(()) => { /* continue forwarding */ }
    Err(e) => {
        fail_to_proxy(session, e);  // Writes 502 Bad Gateway, closes conn
    }
}
```

**If filter returns `Err(...)` mid-stream:** Connection is aborted, client sees 502.

### Recommended Failure Modes for FR-034

| Scenario | Action | Rationale |
|----------|--------|-----------|
| JSON parse error (malformed) | Log warning, **pass through unredacted** | Better UX than 502; document in policy |
| Buffer overflow (>256 KiB) | Log warning, **pass through unredacted** | DoS risk if strict; log for analysis |
| Regex/field matching fails | Log error, **redact with `***REDACTED***`** | Fail-safe: better to over-redact |
| Compression detected | Skip silently | Expected (Option A) |
| Non-JSON content-type | Skip silently | Expected |

**Fail-Open vs Fail-Closed:**
- **Fail-open** (pass unredacted) = complies with SLA, leaks PII if redaction breaks
- **Fail-closed** (502 error) = no PII leak, breaks APIs if redaction breaks

For **non-critical APIs** (public content), fail-open + log. For **critical APIs** (auth, payment), fail-closed (return 502 and page oncall).

**Recommendation for FR-034 MVP:** Fail-open with structured logging of redaction failures (rate-limited). Allow per-rule override in future.

---

## 8. Real-World Pingora Examples

### Cloudflare's `modify_response.rs` Example

Repository: [cloudflare/pingora @ examples/modify_response.rs](https://github.com/cloudflare/pingora/blob/main/pingora-proxy/examples/modify_response.rs)

**Pattern:** Accumulates response body chunks into a `Vec<Bytes>`, then on `end_of_stream==true`:
1. Joins all chunks into single `Bytes`
2. Parses JSON using `serde_json`
3. Transforms (e.g., JSON → YAML)
4. Serializes back
5. Replaces body

```rust
// Simplified pseudocode from example:
let mut accumulated = Vec::new();
if let Some(chunk) = body {
    accumulated.push(chunk.clone());
}
if end_of_stream && !accumulated.is_empty() {
    let json: Value = serde_json::from_slice(&accumulated)?;
    // transform json
    let output = serde_json::to_vec(&json)?;
    *body = Some(Bytes::from(output));
}
```

**Known issue:** [Issue #408](https://github.com/cloudflare/pingora/issues/408) notes "Inspecting or modifying bodies requires at least one deep copy." The Cloudflare team acknowledges this as suboptimal but necessary for current API design.

### No Published Example of JSON Field Redaction

Search of Pingora repo + GitHub issues shows **no published example** of selective JSON field redaction (e.g., redact `ssn`, `password`). This is a novel use case for FR-034.

---

## 9. Cache Interaction Decision

### Scenario: Caching Redacted vs Unredacted

**Assumption:** Gateway has moka-based response cache (from crates/gateway/src/cache.rs).

**Question:** If you redact JSON and cache it, can adversary exfiltrate original via cache backup?

**Two strategies:**

| Strategy | Timing | Cache Content | Pros | Cons |
|----------|--------|---------------|------|------|
| **Redact in `upstream_response_body_filter`** | Before cache | Redacted | Cache is safe; no need to re-redact | If cache breached, still redacted (good). But if compliance says "never store PII," fails. |
| **Redact in `response_body_filter`** | After cache | Unredacted (but not cached if you mutate) | Cache stores original for speed; redaction happens on every response | If cache breached, original PII leaked (bad). But if cache is just in-flight optimization, OK. |

**Pingora behavior:** Modifications in `response_body_filter` do **NOT** get stored in cache (they happen after cache write). So cache always has **unredacted** body.

**Recommendation for FR-034:**
- **Use `response_body_filter`** (after cache)
- Cache stores unredacted body (for speed; cache is in-memory, not persistent in prx-waf architecture)
- Every response to client is redacted, regardless of origin
- **Document:** Cache contains unredacted PII; ensure cache isolation per-process

If compliance requires "never store PII in any form":
- Use `upstream_response_body_filter` (before cache) with option to disable caching for sensitive responses
- Set `Cache-Control: no-store` in `upstream_response_filter` for resources with PII
- Redact in `upstream_response_body_filter` and cache redacted body

**Final choice:** `response_body_filter` for simplicity (mirrors FR-035 pattern).

---

## 10. Error Handling: `end_of_stream` Unreliability

### GitHub Issue #220 Context

[ProxyHttp response_body_filter end_of_stream always false](https://github.com/cloudflare/pingora/issues/220)

**Issue:** In streaming scenarios (chunked encoding, HTTP/2), `end_of_stream` might not signal correctly, preventing detection of final chunk.

**Status:** Marked as "Closed" by Pingora maintainers. Likely fixed in 0.8.

**Safe handling:**

```rust
// Option 1: Use time-based timeout + end_of_stream (fallback)
let should_redact = end_of_stream || ctx.response_body_buf.len() >= 256 * 1024;

// Option 2: Always check both end_of_stream AND next filter call
if !end_of_stream && ctx.response_body_buf.len() < 256 * 1024 {
    return Ok(());  // Wait for more chunks
}
// Redact here (either eos==true OR buffer full)
```

**Recommendation:** Test with real HTTP/2 + chunked responses to verify `end_of_stream` is reliable in 0.8. Add fallback on buffer size cap.

---

## 11. Recommended Architecture for FR-034

### Modified `GatewayCtx`

```rust
pub struct GatewayCtx {
    // ... existing fields ...
    
    // FR-034: Response body redaction
    pub response_body_buf: BytesMut,
    pub response_body_redacted: bool,  // Flag: redaction already applied
}
```

### New Method in WafProxy

```rust
async fn response_body_filter(
    &self,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut GatewayCtx,
) -> pingora_core::Result<()> {
    // 1. Skip if redaction already done
    if ctx.response_body_redacted {
        return Ok(());
    }
    
    // 2. Skip if no JSON content-type
    if !self.is_json_response(session) {
        return Ok(());
    }
    
    // 3. Skip if compressed
    if self.has_content_encoding(session) {
        return Ok(());
    }
    
    // 4. Accumulate body chunk
    if let Some(chunk) = body {
        let remaining = 256 * 1024 - ctx.response_body_buf.len();
        if remaining > 0 {
            let take = chunk.len().min(remaining);
            ctx.response_body_buf.extend_from_slice(&chunk[..take]);
        }
    }
    
    // 5. Check if we should redact now
    let should_redact = end_of_stream || ctx.response_body_buf.len() >= 256 * 1024;
    if !should_redact {
        return Ok(());
    }
    
    ctx.response_body_redacted = true;
    
    // 6. Redact JSON
    let redacted_bytes = self
        .redact_json_response(&ctx.response_body_buf)
        .unwrap_or_else(|e| {
            warn!("JSON redaction failed: {}; passing through unredacted", e);
            ctx.response_body_buf.to_vec()
        });
    
    *body = Some(Bytes::from(redacted_bytes));
    Ok(())
}
```

### Redaction Logic (separate module)

```rust
// In waf-engine or new module
fn redact_json_response(json_bytes: &[u8], rules: &SensitiveFieldRules) -> anyhow::Result<Vec<u8>> {
    let mut value: serde_json::Value = serde_json::from_slice(json_bytes)?;
    
    // Redact fields matching rules (e.g., ssn, password, credit_card_number)
    for key in rules.fields_to_redact() {
        redact_field_recursive(&mut value, key);
    }
    
    Ok(serde_json::to_vec(&value)?)
}

fn redact_field_recursive(value: &mut serde_json::Value, field_name: &str) {
    match value {
        serde_json::Value::Object(map) => {
            if map.contains_key(field_name) {
                map[field_name] = serde_json::Value::String("***REDACTED***".to_string());
            }
            for (_, v) in map.iter_mut() {
                redact_field_recursive(v, field_name);
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                redact_field_recursive(item, field_name);
            }
        }
        _ => {}
    }
}
```

---

## 12. Integration with Existing Code (crates/gateway/src/proxy.rs)

### Current Implementation (FR-035)

Lines ~372-405 show `response_filter` for header stripping:

```rust
async fn response_filter(
    &self,
    _session: &mut Session,
    upstream_response: &mut pingora_http::ResponseHeader,
    _ctx: &mut GatewayCtx,
) -> pingora_core::Result<()> {
    let Some(filter) = self.header_filter.as_ref() else {
        return Ok(());
    };
    
    // Remove leaky headers...
    let mut to_remove: Vec<String> = Vec::new();
    for (name, value) in &upstream_response.headers {
        if filter.should_strip(name.as_str()) {
            to_remove.push(name.as_str().to_string());
        }
    }
    // ... remove headers ...
}
```

### Add to WafProxy Struct

```rust
pub struct WafProxy {
    // ... existing ...
    pub header_filter: Option<Arc<HeaderFilter>>,  // FR-035
    pub body_redactor: Option<Arc<BodyRedactor>>,   // FR-034 (new)
}
```

### Append response_body_filter

```rust
async fn response_body_filter(
    &self,
    session: &mut Session,
    body: &mut Option<Bytes>,
    end_of_stream: bool,
    ctx: &mut GatewayCtx,
) -> pingora_core::Result<()> {
    let Some(redactor) = self.body_redactor.as_ref() else {
        return Ok(());  // FR-034 disabled
    };
    
    redactor.filter(session, body, end_of_stream, ctx).await
}
```

### Dependencies to Add (Cargo.toml)

```toml
serde_json = "1"  # Already present
bytes = "1"       # Already present
```

No new dependencies needed; serde_json + bytes already in workspace deps.

---

## Traps & Pitfalls

1. **`end_of_stream` unreliability** — Test with HTTP/2 + chunked. Have size-cap fallback.

2. **No auto-decompression** — Gzip arrives as gzip. Document Option A (skip) vs Option B (decompress).

3. **Deep copy overhead** — Accumulating body into `BytesMut`, then copying to serialization, is 1-2x memory cost. Unavoidable for JSON parsing.

4. **Cache semantics confusing** — Easy to accidentally cache unredacted body if using `upstream_response_body_filter`. Use `response_body_filter` to be explicit about post-cache.

5. **Content-Length auto-strip** — Pingora removes it if you modify body size. If your redaction always shortens (e.g., PII → `***REDACTED***`), Content-Length becomes invalid anyway. **Don't manually manage it.**

6. **Buffer size tuning** — 256 KiB is a guess. Monitor real response sizes; tune down if memory-constrained, up if real APIs are larger.

7. **JSON parsing failures** — Malformed JSON from upstream (rare but possible). Fail-open (pass through unredacted) is safe but leaks PII if parsing fails. Log loudly.

8. **Streaming vs buffering mismatch** — Chunk-by-chunk API forces full buffering for JSON. If you have a rule engine that's also streaming (e.g., regex), double-check latency impact.

---

## Unresolved Questions

1. **What Pingora version is actually deployed?** Cargo.toml says 0.8, but is it patched? Issue #220 (end_of_stream) may have a fix.
   
2. **Does moka cache config have TTL/size limits?** If cache can grow unbounded with unredacted bodies, need eviction policy.

3. **Is there a real upstream that sends gzip?** If not, skip Option B (decompress). If yes, prioritize it.

4. **What's the actual JSON response size distribution?** Need to measure to set buffer cap intelligently.

5. **Are there rules already defined for sensitive fields?** Or does FR-034 also include a rule DSL?

6. **Multi-tenant isolation in cache?** If multiple clients share cache, ensure redaction doesn't leak between tenants (Pingora cache is per-process, should be safe).

---

## Summary: Recommended Implementation Path

1. **Extend `GatewayCtx`:** Add `response_body_buf: BytesMut`, `response_body_redacted: bool`

2. **Create `BodyRedactor` trait/struct** in waf-engine crate with signature:
   ```rust
   async fn filter(
       &self,
       session: &Session,
       body: &mut Option<Bytes>,
       end_of_stream: bool,
       ctx: &mut GatewayCtx,
   ) -> pingora_core::Result<()>
   ```

3. **Implement in WafProxy.response_body_filter()** following the algorithm in section 11.

4. **Add to JSON redaction rules** (serde_json field walk + replace matching keys).

5. **Test:**
   - Unit test: JSON field redaction with serde_json
   - Integration test: Full proxy with mock upstream returning JSON, verify redaction
   - Stress test: Buffer cap at 256 KiB with responses >256 KiB, verify pass-through
   - HTTP/2 + chunked test: Verify `end_of_stream` fires correctly

6. **Monitoring:** Emit metrics:
   - `response_body_redacted_count` (success)
   - `response_body_redaction_failed_count` (parse errors)
   - `response_body_buffer_peak_bytes` (sizing)
   - `response_body_skipped_gzip_count` (compression cases)

7. **Compress in next phase:** Option B (gzip handling) if real traffic demands it.

---

## References

- [ProxyHttp trait (docs.rs)](https://docs.rs/pingora/latest/pingora/prelude/trait.ProxyHttp.html)
- [Life of a request: phases guide (GitHub)](https://github.com/cloudflare/pingora/blob/main/docs/user_guide/phase.md)
- [PingoraRust.COM phase guide](https://www.pingorarust.com/user_guide/phase)
- [Response body modification (Issue #106)](https://github.com/cloudflare/pingora/issues/106)
- [end_of_stream always false (Issue #220)](https://github.com/cloudflare/pingora/issues/220)
- [Inspecting bodies deep copy (Issue #408)](https://github.com/cloudflare/pingora/issues/408)
- [Compression handling (Issue #523)](https://github.com/cloudflare/pingora/issues/523)
- [Modify response example (GitHub)](https://github.com/cloudflare/pingora/blob/main/pingora-proxy/examples/modify_response.rs)
- [Modification filter guide (GitHub)](https://github.com/cloudflare/pingora/blob/main/docs/user_guide/modify_filter.md)

---

**Status:** DONE

**Summary:** Pingora 0.8's `response_body_filter` API is suitable for FR-034 JSON field redaction via streaming chunk accumulation and full buffering at end-of-stream. Recommended placement: post-cache `response_body_filter` to ensure all responses are redacted while caching unredacted bodies for speed. Buffer size: 256 KiB. Handle compression by skipping (Option A) in MVP, with path to decompress-redact-recompress (Option B) in Phase 2. Content-Length auto-recalculation handled by Pingora; no manual header adjustment needed. Failure mode: fail-open (pass unredacted + log warning) for parse errors and buffer overflow; fail-closed (502) for critical APIs only. No existing Pingora examples of JSON field redaction; implementation is novel.
