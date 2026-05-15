# Code Safety Patterns & Conventions

Detailed safety and operational patterns for the mini-waf codebase. For core rules (Seven Iron Rules, formatting, and error handling), see [code-standards.md](./code-standards.md).

---

## SQL Safety

### Parameterized Queries Only

**Use sqlx macros for compile-time checking**

```rust
// ✅ Safe: parameters bound separately
let user = sqlx::query_as::<_, User>(
    "SELECT * FROM users WHERE id = $1"
)
.bind(user_id)
.fetch_one(&db.pool)
.await?;

// ✅ Safe macro (compile-time checked)
let user = sqlx::query_as!(
    User,
    "SELECT * FROM users WHERE id = ?",
    user_id
)
.fetch_one(&db.pool)
.await?;

// ❌ NEVER string concatenation
let sql = format!("SELECT * FROM users WHERE id = {}", user_id);
sqlx::query(&sql).fetch_one(&pool).await?;
```

### Dynamic Identifiers

If you must accept table/column names from input:

```rust
// Validate against allowlist
fn validate_identifier(name: &str) -> anyhow::Result<&str> {
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        anyhow::bail!("invalid identifier: {}", name);
    }
    if name.starts_with(|c: char| !c.is_ascii_alphabetic() && c != '_') {
        anyhow::bail!("identifier must start with letter or underscore");
    }
    Ok(name)
}

// Regex pattern (more strict)
lazy_static::lazy_static! {
    static ref IDENTIFIER_PATTERN: Regex = 
        Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$").unwrap();
}

fn validate_identifier(name: &str) -> anyhow::Result<()> {
    if !IDENTIFIER_PATTERN.is_match(name) {
        anyhow::bail!("invalid identifier: {}", name);
    }
    Ok(())
}
```

---

## Mutex & Synchronization

### Sync Code: parking_lot::Mutex

**Why**: No poisoning, no unwrap needed, faster than std::sync::Mutex

```rust
use parking_lot::Mutex;

let data = Mutex::new(vec![]);
{
    let mut guard = data.lock();  // No .unwrap() needed
    guard.push(42);
}  // Guard dropped, lock released
```

### Async Code: tokio::sync::Mutex

**Use for async lock contention**

```rust
use tokio::sync::Mutex;

let data = Mutex::new(vec![]);
{
    let mut guard = data.lock().await;
    guard.push(42);
}
```

### Lock-Free Reads: arc-swap

**For frequent reads, rare writes (like NodeState)**

```rust
use arc_swap::ArcSwap;

let state = ArcSwap::new(Arc::new(current_state));

// Reader (no lock)
let snapshot = state.load_full();  // Arc clone, instant

// Writer (CAS loop)
let new_state = Arc::new(updated_state);
state.store(new_state);
```

---

## No Secret Logging

**Never log tokens, keys, passwords, or sensitive PII**

```rust
// ❌ Banned
tracing::info!("API key: {}", api_key);
tracing::info!("Auth header: {}", auth_header);
println!("Database URL: {}", db_url);

// ✅ Sanitize before logging
fn sanitize_url(url: &str) -> String {
    if let Ok(parsed) = url::Url::parse(url) {
        format!("{}://{}", parsed.scheme(), parsed.host().unwrap_or_default())
    } else {
        "[invalid URL]".to_string()
    }
}

tracing::info!("Connecting to {}", sanitize_url(&db_url));
```

---

## Unsafe Code

**Policy: Unsafe blocks forbidden except with explicit justification**

If unsafe is absolutely necessary:

```rust
// ✅ Required SAFETY comment
unsafe {
    // SAFETY: This pointer came from a stable Arc clone and is valid for the Arc lifetime.
    // The Arc is held as a field in `self`, ensuring the pointer remains valid.
    let ptr = Arc::as_ptr(&self.data);
    std::ptr::addr_of_mut!((*ptr).field)
}
```

**Better**: Use safe abstractions (Arc, Mutex, channels) instead.

---

## Logging & Tracing

### Structured Logging (tracing crate)

```rust
use tracing::{info, warn, error, debug, trace};

// ✅ Structured events with context
tracing::info!(
    rule_id = rule.id,
    severity = %rule.severity,
    action = %decision.action,
    "Rule matched"
);

// ✅ Error with context
tracing::error!(
    error = %err,
    request_id = %req_id,
    "Request processing failed"
);
```

### Log Levels

- **error**: Unrecoverable failures (crashes, database offline)
- **warn**: Degraded functionality (missing rule, invalid config, silent error)
- **info**: Important state changes (startup, shutdown, role change)
- **debug**: Detailed operation info (rule eval, connection events)
- **trace**: Very detailed (every packet, every allocation)

---

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_ipv4_cidr() {
        assert!(validate_cidr("192.168.0.0/16").is_ok());
        assert!(validate_cidr("invalid").is_err());
        assert!(validate_cidr("256.256.256.256/32").is_err());
    }

    #[tokio::test]
    async fn handles_database_timeout() {
        // Test timeout + retry behavior
        let result = timeout(Duration::from_millis(100), slow_query()).await;
        assert!(result.is_err());
    }
}
```

### Integration Tests

```rust
// tests/integration_tests.rs
#[tokio::test]
async fn cluster_node_election() {
    let (node_a, node_b) = setup_test_cluster().await;
    
    // Kill main
    node_a.shutdown().await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    
    // Verify worker promoted to main
    let state = node_b.cluster_state().await;
    assert_eq!(state.role, NodeRole::Main);
}
```

### Property-Based Tests

Use `proptest` for fuzzing rules:

```rust
#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn regex_pattern_never_panics(input in ".*") {
            // Ensure rule evaluation handles any input
            let _ = rule_engine.check(&input);
        }
    }
}
```

---

## Commit Style

Follow conventional commits:

```
feat(waf-engine): add SSRF validation with DNS rebinding guard

- Implement url_validator module with validate_public_url() and validate_scheme_only()
- Add RFC-1918 / loopback / link-local IP blocking
- Cache resolved IP addresses to prevent time-of-check / time-of-use attacks
- Add 30s timeout for DNS resolution to prevent DoS

Fixes #123
```

**Format**: `type(scope): subject`

- **type**: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`
- **scope**: affected crate(s)
- **subject**: imperative, no period, <50 chars

---

## Code Review Checklist

Before submitting a PR:

- [ ] Passes `cargo fmt --all -- --check`
- [ ] Passes `cargo clippy -- -D warnings`
- [ ] No `unwrap()`, `expect()`, `panic!()` in production code
- [ ] No `todo!()`, `unimplemented!()`
- [ ] All error cases handled (? operator or explicit match)
- [ ] No dead code (unused imports, variables, functions)
- [ ] Meaningful comments for complex logic
- [ ] Tests added/updated
- [ ] Integration tests pass
- [ ] Performance-sensitive code profiled
- [ ] No secrets in logs
- [ ] Documentation updated (README, docs/)

---

## Pre-Commit Hook (Optional)

Save as `.git/hooks/pre-commit` (make executable):

```bash
#!/bin/bash
set -e

echo "Running pre-commit checks..."

cargo fmt --all -- --check || {
    echo "❌ Code formatting failed. Run: cargo fmt --all"
    exit 1
}

cargo clippy --workspace --all-targets -- -D warnings || {
    echo "❌ Clippy lint failed. Fix warnings above."
    exit 1
}

cargo test --all || {
    echo "❌ Tests failed."
    exit 1
}

echo "✅ All checks passed. Ready to commit."
```

---

## Modularized Rule Organization

**Pattern**: Split large rule evaluation into focused modules

**Good** (sql_injection_patterns.rs)
```rust
// Each pattern file contains 3-6 related regex rules
pub static SQLI_001: Lazy<Regex> = Lazy::new(|| {
    // Classic UNION-based SQLi
    Regex::new(r"(?i)union.*select").unwrap()
});

#[allow(unsafe_code)]  // Scoped: build-time regex compilation only
pub static SQLI_BLIND: Lazy<Regex> = Lazy::new(|| {
    // Blind SQLi inference patterns
    Regex::new(r"(?i)(and|or)\s*\d+\s*=\s*\d+").unwrap()
});
```

**Why**: 
- Each pattern file self-documents its category
- Hot-path rule eval stays allocation-free
- Regex compilation (expensive) happens once at startup
- Scoped `#[allow(unsafe_code)]` signals intentionality, not sloppiness

---

## Minimal Allocations in Hot Paths

**Bad** (rule evaluation path)
```rust
fn check_sqli(body: &str) -> bool {
    let lower = body.to_lowercase();  // ❌ Allocates
    SQLI_PATTERN.is_match(&lower)     // ❌ Re-allocates
}
```

**Good**
```rust
fn check_sqli(body: &str) -> bool {
    SQLI_PATTERN.is_match_ignore_case(body)  // ✅ Zero allocation
}

// Or use Cow for conditional allocation:
fn validate_header(s: &str) -> Cow<'_, str> {
    if s.contains('\\') {
        Cow::Owned(s.replace('\\', ""))  // ✅ Only allocate if needed
    } else {
        Cow::Borrowed(s)  // ✅ Zero-copy reference
    }
}
```

---

## Redis Store Backend Conventions (FR-025 Phase 7)

### When to Use Memory vs Redis

**Use Memory backend when:**
- Single-node deployment (<100 RPS)
- Development / testing environment
- Risk state loss on restart is acceptable
- Redis dependency unwanted

**Use Redis backend when:**
- Multi-node cluster deployment
- High-volume traffic (>100 RPS)
- Risk state must persist across restarts
- Centralized risk tracking across nodes required
- Incident response (merge scores across nodes via Lua script)

### Key Design Patterns

**Key Namespace Hygiene**
```rust
// All risk store keys use prefix for isolation
const KEY_PREFIX: &str = "waf:risk:";
const STATE_KEY_FORMAT: &str = "waf:risk:state:{}";    // owner_id
const IP_INDEX_KEY_FORMAT: &str = "waf:risk:idx:ip:{}";   // ip
const FP_INDEX_KEY_FORMAT: &str = "waf:risk:idx:fp:{}";   // fp_hash
const SID_INDEX_KEY_FORMAT: &str = "waf:risk:idx:sid:{}"; // session_id
```

**TTL Management via Redis EXPIRE**
```rust
// All state keys expire per config.ttl_secs
let ttl_seconds = config.ttl_secs;
redis_client.expire(state_key, ttl_seconds).await?;

// Index keys also expire (no stale indices)
redis_client.expire(ip_index_key, ttl_seconds).await?;
```

**Atomic Lua Scripts**
- Always use Lua scripts for multi-step operations
- Single RTT consistency: fetch + decay + merge + expire
- Example: `apply_script` in `risk/store/redis_lua.rs`
- Never use pipeline for critical operations (non-atomic)

**Error Handling in Hot Path**
```rust
// Apply with timeout
match timeout(config.op_timeout, redis_apply()).await {
    Ok(Ok(result)) => result,           // Success
    Ok(Err(e)) => {
        tracing::warn!("redis apply error: {e}");
        breaker.record_failure();
        fallback_to_lru_cache(key)        // Fail-open
    },
    Err(_timeout) => {
        breaker.record_failure();
        fallback_to_lru_cache(key)        // Timeout = failure
    }
}
```

### Testing

**Integration Tests with Redis**
```bash
# Run with local Redis (requires redis-server running)
REDIS_TEST_URL=redis://127.0.0.1:6379 cargo test --features redis-store

# Or use test container
docker run -d -p 6379:6379 redis:7-alpine
REDIS_TEST_URL=redis://127.0.0.1:6379 cargo test --all
```

**Conformance Tests**
- Memory and Redis backends must pass identical conformance suite
- File: `crates/waf-engine/src/risk/store/conformance.rs`
- Tests: decay, collision merge, TTL expiry, circuit breaker fallback
- Run: `cargo test --all risk::store::conformance`

---

## FR-025 Risk Delta Convention

Rules can contribute to cumulative risk scoring via the optional `risk_delta` field.
Per-request deltas are clamped to `[0, 100]` to prevent score explosion.

### Risk Delta Table

| Attack Category       | risk_delta | Rationale                              |
|-----------------------|------------|----------------------------------------|
| RCE (command exec)    | 60         | Direct system compromise               |
| SSTI                  | 60         | Template injection → RCE               |
| Deserialization       | 60         | Object injection → RCE                 |
| XXE                   | 60         | Entity injection → file read / RCE     |
| Webshell upload       | 60         | Persistent backdoor                    |
| SSRF                  | 55         | Internal network / cloud metadata      |
| LFI                   | 50         | Local file inclusion                   |
| Prototype pollution   | 50         | JS object prototype manipulation       |
| Path traversal        | 45         | Directory escape                       |
| SQLi                  | 40         | Database compromise                    |
| XSS                   | 35         | Client-side script injection           |
| Scanner UA            | 20         | Recon activity                         |
| Suspicious header     | 15         | Anomalous but not definitive           |

### Rule YAML Example

```yaml
- id: "ADV-SSTI-001"
  name: "SSTI - Generic Expression Evaluation"
  category: "ssti"
  severity: "critical"
  field: "all"
  operator: "regex"
  value: "(?i)\\$\\{\\s*[0-9]+\\s*\\*\\s*[0-9]+\\s*\\}"
  action: "block"
  risk_delta: 60          # FR-025: contributes to cumulative score
  risk_action: "block"    # Optional: override to immediate block
  tags: ["ssti", "rce"]
```

### Clamping Behavior

When multiple rules match in a single request:
1. All positive deltas are summed
2. If sum > 100, oldest positive deltas are truncated (newest kept)
3. Negative deltas (credits) are always preserved
4. `X-WAF-Rule-Id` header set to dominant contributor (max |delta|)

---

## Vendored Dependencies

### Pingora Patch (FR-010)

`vendor/pingora/` is a pinned fork carrying the L4 inspector traits used
by `device_fp::capture` (ClientHello bytes + H2 frames pre-END_HEADERS).
Wired via `[patch.crates-io]` in the workspace `Cargo.toml`.

**Upgrade SOP:**
1. Rebase the fork on the upstream tag; resolve only inspector-trait
   conflicts. Do not pull unrelated changes into the patch.
2. Run `cargo test -p waf-engine --all-features` and the device_fp
   conformance suite (`identity::conformance`).
3. Run `cargo bench -p waf-engine --bench device_fp_pipeline` and
   compare p99 against the previous nightly artifact (`device-fp-bench`).
4. Update `docs/device-fingerprinting.md` "last verified" date.
5. PR description must list upstream commit range and the conformance /
   bench deltas.

A failed inspector hook is fail-open: capture goes empty, providers run
on UA only. Never gate the pipeline on hook success.
