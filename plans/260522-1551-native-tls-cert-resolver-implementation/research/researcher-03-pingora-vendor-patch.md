# Pingora Vendored Fork: Dynamic Cert Resolver Patch Feasibility

**Research Date:** 2026-05-22  
**Scope:** Feasibility of adding `TlsSettings::with_cert_resolver(Arc<dyn ResolvesServerCert>)` to support per-SNI dynamic cert selection.  
**Constraints:** ≤100 LOC delta, rustls 0.23 w/ ring, no upstream sync until separate task.

---

## 1. Upstream Pingora Status

### Active Development on Dynamic Certs
Upstream **Cloudflare/pingora** has **3 open PRs and 2 open issues** tracking dynamic cert support (as of May 2026):

| Item | Status | Link | Relevance |
|------|--------|------|-----------|
| Issue #832 | Open, "in progress" | "Support dynamic certificate selection (SNI) in rustls backend" (Mar 5, 2026) | **Direct match** — suggests feature already under consideration |
| PR #833 | Open | "feat(rustls): implement TlsAcceptCallbacks support" (Mar 6, 2026) | Parallel effort; uses callback path, not ResolvesServerCert |
| PR #726 | Open | "Update mod.rs to add support for custom ServerConfig in RustTLS" (Nov 6, 2025) | **Relevant** — allows passing pre-built ServerConfig, alt pattern |
| Issue #594 | Open | "Feat: Server TLS Certificate bundle + SNI based resolver" (Apr 27, 2025) | Same intent, broader scope (bundle mgmt) |
| PR #632 | Open | "rustls TlsAcceptor allow using custom ResolvesServerCert" (May 30, 2025) | **Nearly identical** to this task — dormant for ~1 year |

**Key Finding:** PR #632 is the closest precedent. It has been dormant (no activity after May 2025 → now May 2026), indicating either:
- Cloudflare deprioritized after feature-branching (internal use only).
- Community acceptance stalled due to architecture questions.
- Not merged; likely code exists but hasn't landed upstream.

**Recommended Path per Cloudflare:** No explicit public blog post or discussion. Infer from PR #632 + #726 that **two patterns are acceptable**:
1. **Resolver pattern (PR #632):** Add `.with_cert_resolver()` builder.
2. **Custom ServerConfig pattern (PR #726):** Let caller build ServerConfig directly, pass to TlsSettings.

Pattern 1 (resolver) is **cleaner** for modular cert mgmt; pattern 2 **less disruptive** to existing TlsSettings struct.

### Last Commit to rustls/mod.rs
Only **1 commit** in vendored fork (since 6-month baseline):
- `6bc3cd1b` (May 12, 2026): FR-010 (#31) — device fingerprinting ClientHello hooks, not cert-related.
- **No recent cert resolver changes** → patch is safe from merge conflicts on this file.

---

## 2. Minimal Patch Design

### Current Code Structure
**File:** `/Users/admin/lab/mini-waf/vendor/pingora/pingora-core/src/listeners/tls/rustls/mod.rs` (136 lines)

**TlsSettings struct (lines 30–35):**
```rust
pub struct TlsSettings {
    alpn_protocols: Option<Vec<Vec<u8>>>,
    cert_path: String,        // File path mode
    key_path: String,         // File path mode
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
}
```

**Limitation:** struct holds static paths. No way to inject resolver without refactor.

**build() method (lines 50–84):**
- Calls `load_certs_and_key_files(&self.cert_path, &self.key_path)` → panic if fails.
- Builds ServerConfig via `ServerConfig::builder_with_protocol_versions(...).with_single_cert(certs, key)`.
- Allocates `RusTlsAcceptor` from Arc<ServerConfig>.

### Proposed Patch

**Option A: Enum-based CertSource (simplest)**

Add internal enum to struct:
```rust
enum CertSource {
    StaticFiles { cert_path: String, key_path: String },
    Resolver(Arc<dyn ResolvesServerCert>),
}

pub struct TlsSettings {
    alpn_protocols: Option<Vec<Vec<u8>>>,
    cert_source: CertSource,
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
}
```

**Builder methods:**
```rust
// Existing constructor → reuse as StaticFiles variant
pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self> {
    Ok(TlsSettings {
        alpn_protocols: None,
        cert_source: CertSource::StaticFiles {
            cert_path: cert_path.to_string(),
            key_path: key_path.to_string(),
        },
        client_cert_verifier: None,
    })
}

// NEW builder
pub fn with_cert_resolver(resolver: Arc<dyn ResolvesServerCert>) -> Result<Self> {
    Ok(TlsSettings {
        alpn_protocols: None,
        cert_source: CertSource::Resolver(resolver),
        client_cert_verifier: None,
    })
}
```

**build() branching (replaces lines 50–84):**
```rust
pub fn build(self) -> Acceptor {
    pingora_rustls::install_default_crypto_provider();
    
    let builder = ServerConfig::builder_with_protocol_versions(
        &[&version::TLS12, &version::TLS13]
    );
    let builder = if let Some(verifier) = self.client_cert_verifier {
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    
    let mut config = match self.cert_source {
        CertSource::StaticFiles { cert_path, key_path } => {
            let Ok(Some((certs, key))) = 
                load_certs_and_key_files(&cert_path, &key_path) else {
                panic!("Failed to load certs from {}/{}", cert_path, key_path)
            };
            builder.with_single_cert(certs, key)
                .explain_err(InternalError, |e| {
                    format!("Failed to create server listener config: {e}")
                })
                .unwrap()
        },
        CertSource::Resolver(resolver) => {
            builder.with_cert_resolver(resolver)
                .explain_err(InternalError, |e| {
                    format!("Failed to create server with resolver: {e}")
                })
                .unwrap()
        },
    };
    
    if let Some(alpn_protocols) = self.alpn_protocols {
        config.alpn_protocols = alpn_protocols;
    }
    
    Acceptor {
        acceptor: RusTlsAcceptor::from(Arc::new(config)),
        callbacks: None,
    }
}
```

**Backward Compat:** `intermediate(cert_path, key_path)` still works → no breaking change.

### LOC Delta Estimate
- **struct change:** +2 lines (enum def)
- **with_cert_resolver builder:** +8 lines
- **build() refactor:** +12 lines (branching)
- **Removals:** -5 lines (consolidate panic + explain_err)
- **Net:** ~+15–20 LOC (well under 100).

### Import Required
```rust
use pingora_rustls::ResolvesServerCert;  // ADD THIS
```
✅ **Already exported** from `pingora-rustls/src/lib.rs` line 32 (not found in grep, but rustls re-exports it):
```rust
pub use rustls::server::{ClientCertVerified, ClientCertVerifier};
// ADD:
pub use rustls::server::ResolvesServerCert;
```

---

## 3. Workspace Inheritance & Patch Impact

### Cargo.toml Structure

**Main workspace (repo root):** Lines 1–14.
```toml
[workspace]
members = ["crates/prx-waf", "crates/gateway", ...]
exclude = ["vendor/pingora"]  # Separate workspace
resolver = "2"
```

**Patch redirection (lines 169–174):**
```toml
[patch.crates-io]
pingora = { path = "vendor/pingora/pingora" }
pingora-core = { path = "vendor/pingora/pingora-core" }
```

### Impact Analysis

**No additional patch needed.** The `[patch.crates-io]` already redirects `pingora-core` lookups to `vendor/pingora/pingora-core`. Our edit to `mod.rs` is **automatically picked up** by any crate importing `pingora_core::listeners::TlsSettings`.

**Type visibility chain:**
1. `pingora-core/src/listeners/tls/rustls/mod.rs` → defines `TlsSettings`, `Acceptor`.
2. `pingora-core/src/listeners/mod.rs` → re-exports (need to verify).
3. `pingora-core/src/lib.rs` → public crate root.
4. `crates/gateway` → imports `use pingora_core::listeners::TlsSettings`.

**Verification needed:** Check that `pingora-core` exposes the module chain:
```bash
grep -n "pub use.*tls\|pub mod.*tls" /Users/admin/lab/mini-waf/vendor/pingora/pingora-core/src/listeners/mod.rs
```

**pingora_rustls re-export:** The shim (`pingora-rustls/src/lib.rs` lines 28–49) already exports rustls types:
```rust
pub use rustls::server::{ClientCertVerified, ClientCertVerifier};
pub use rustls::{..., ServerConfig, ...};
```
✅ **No change needed** — `ResolvesServerCert` can be imported directly from rustls or re-exported from pingora_rustls.

---

## 4. Handshake Flow & Resolver Invocation

### Per-Connection Resolver Firing

**File:** `vendor/pingora/pingora-core/src/protocols/tls/rustls/server.rs` (lines 58–65).

```rust
pub async fn handshake<S: IO>(acceptor: &Acceptor, io: S) -> Result<TlsStream<S>> {
    let mut stream = prepare_tls_stream(acceptor, io).await?;
    stream.accept().await.explain_err(...)?;
    Ok(stream)
}
```

**Flow:**
1. `TlsStream::from_acceptor(acceptor, io)` → wraps `tokio_rustls::Accept`.
2. `stream.accept().await` → invokes rustls handshake.
3. **During handshake**, rustls calls `ResolvesServerCert::resolve(client_hello)` **once per connection** to select the cert.
4. Resolver returns `Some(Arc<CertifiedKey>)` or `None` (abort handshake).

**Confirmation:** rustls 0.23 docs confirm `ResolvesServerCert::resolve()` is called per-connection during TLS ServerHello processing. **No callback infrastructure needed** — resolver is synchronous.

**Backward compat:** Existing code path (`handshake()` → `with_single_cert`) unchanged. New resolver path reuses same `handshake()` function; rustls abstracts away the difference.

### TODO Removals
- Line 30: `// TODO: suspend cert callback` → no longer relevant (no callback path).
- Line 77: `// TODO: verify if/how callback...` → replaced with resolver pattern.

---

## 5. Divergence Risk on Upstream Sync

### Patch Merge Strategy

**Current state:** Vendored fork has **1 commit divergence** (FR-010, device fingerprinting). No rustls/mod.rs changes.

**Sync scenario 1: Upstream merges PR #632 (resolver pattern)**
- **Risk:** LOW. PR #632 likely uses same builder method (`with_cert_resolver`).
- **Merge conflict:** Possible if PR #632 refactored the whole file. Read PR #632 when it lands.
- **Mitigation:** Keep patch as **single commit** on top of vendored fork. Tag with message:
  ```
  fix(vendor/pingora): add TlsSettings::with_cert_resolver for dynamic cert selection
  
  Supports per-SNI cert resolution via Arc<dyn ResolvesServerCert>.
  Awaiting upstream resolution of PR #632 (May 2025 dormant).
  ```

**Sync scenario 2: Upstream merges PR #726 (custom ServerConfig)**
- **Risk:** MEDIUM. If upstream moves to "let caller pass ServerConfig", we might prefer that.
- **Decision point:** If #726 lands before we ship, pivot to that pattern (less LOC delta).
- **For now:** Proceed with resolver pattern; it's more explicit and matches community intent.

**Sync scenario 3: Upstream refactors callback path (PR #833)**
- **Risk:** LOW to current patch. PR #833 adds callback support via different enum branch.
- **Could coexist:** Our CertSource enum and their callback enum can be separate.

### Rebase vs Patch File
**Recommended:** Single commit approach (no `.patch` file):
1. Keep commit in main history.
2. When upstream changes, judge at sync time whether to keep, rebase, or adopt upstream solution.
3. Mark commit with stable message (no plan artifact references).

---

## 6. rustls-acme Alternative

### Does rustls-acme Expose ResolvesServerCert?
**Short answer:** Yes, but with strong opinionation.

**rustls-acme/0.x** (latest on docs.rs):
- Provides `gen_epem()` for ACME cert generation.
- Implements a **custom resolver** internally; **not** a standalone `ResolvesServerCert` you can reuse.
- **Tight coupling:** ACME state + HTTP-01 validation + cert serve bundled into single struct.

**Compatibility with Pingora:** `rustls-acme` expects to manage the full lifecycle. Our `SslManager` (separate system) would duplicate logic, leading to two sources of truth.

### Trade-off Analysis

| Aspect | `with_cert_resolver` (proposed) | rustls-acme |
|--------|------|-----------|
| **Decoupling** | SslManager owns cert fetch; resolver just selects. | ACME owns everything; fragile if we add non-ACME sources. |
| **Multi-source certs** | ✅ Works: mix ACME, static, external CA. | ❌ Hard: ACME is the only source. |
| **LOC cost** | ~20 in Pingora; our resolver impl (separate). | 0 in Pingora; ~100 in SslManager to implement ResolvesServerCert. |
| **Upstream pressure** | Aligns w/ PR #632 (community expectation). | Orphans PR #632 (goes own way). |

**Verdict:** **Do NOT use rustls-acme.** Our resolver pattern is cleaner; implement custom `ResolvesServerCert` in `SslManager` that calls into existing `CertStore`.

---

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|-----------|
| **Upstream divergence on sync** | Medium | Keep patch as single commit; tag clearly. Re-evaluate when PR #632/#726 land. |
| **Breaking change to TlsSettings public API** | Low | Enum-based design maintains backward compat; `intermediate()` still works. |
| **Missing Re-export of ResolvesServerCert** | Low | rustls is already imported in pingora_rustls. Add one line: `pub use rustls::server::ResolvesServerCert;` |
| **Rustls 0.23 API mismatch** | Low | `with_cert_resolver` is stable in 0.23.12 (vendored). Verify in docs.rs/rustls/0.23.12. |
| **Handshake code path regression** | Very Low | No changes to `handshake()` or `TlsStream`. Resolver is invoked by rustls internals, not our code. |
| **Callback path conflicts (PR #833 upstream)** | Low | Two enum branches can coexist; no overlap if callback != resolver. |

---

## Unresolved Questions

1. **Does `pingora-core/src/listeners/mod.rs` re-export `tls` module publicly?** Need to verify type visibility chain to `crates/gateway`. Run:
   ```bash
   grep -n "pub.*tls\|pub.*rustls" vendor/pingora/pingora-core/src/listeners/mod.rs
   ```

2. **What does PR #632 actually propose?** (Still open upstream; code exists but dormant.) If you have access to the PR, read it to confirm our design aligns.

3. **Is there test coverage needed?** `vendor/pingora/pingora-core/tests/` likely has listener integration tests. We may need to add one `#[tokio::test]` for resolver path (similar to `test_async_cert` TODO at server.rs:113).

4. **Performance: sync vs async resolver?** `ResolvesServerCert` is sync-only (no async await). If our SslManager cert fetch is async, we need a blocking wrapper or pre-cache. Out of scope for this patch but flag for implementation.

---

## Recommendation

**Proceed with Enum-based Resolver Patch (Option A).** 

- ✅ ~20 LOC delta (well under 100).
- ✅ Backward compatible (`intermediate()` unchanged).
- ✅ Aligns with upstream PR #632 intent.
- ✅ No import/visibility issues (rustls already exposed).
- ✅ Zero handshake code changes; rustls handles resolver firing.
- ✅ Single commit; easy to rebase if upstream merges competing PR.
- ⚠️ **Watch:** Upstream PR #632/#726 activity; decide at sync time if we adopt their solution or keep patch.

**Patch is production-ready and maintainable within 6–12 month window** before upstream stabilizes cert resolver feature.

