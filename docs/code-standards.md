# Code Standards & Safety Rules

## Seven Iron Rules (Non-Negotiable)

These rules are enforced via linting, code review, and CI checks. **Zero exceptions in production code.**

### 1. NO .unwrap() / .expect() in Production

**Rationale**: Panics crash the process. WAF must fail gracefully, never crash.

**Banned**
```rust
let x = result.unwrap();           // ❌
let x = result.expect("msg");      // ❌
let x = option.unwrap();           // ❌
```

**Allowed (Test-Only)**
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn example() {
        let x = result.unwrap();  // ✅ In tests, OK to panic
    }
}
```

**Correct Approaches**
```rust
// Option 1: ? operator (recommended)
fn check_config() -> anyhow::Result<String> {
    let val = parse_config()?;  // ✅ Propagate error
    Ok(val)
}

// Option 2: unwrap_or_default
let val = result.unwrap_or_default();  // ✅

// Option 3: if let
if let Ok(val) = result {
    // ✅ Handle only success case
}

// Option 4: match
match result {
    Ok(val) => { /* success */ },
    Err(e) => { /* handle error */ }
}

// Option 5: .ok() with logging
let val = result.ok().map_err(|e| {
    tracing::warn!("Config parse failed: {e}");
    e
})?;
```

### 2. NO Dead Code

**Rationale**: Unmaintained code accumulates bugs, confuses readers, increases compilation time.

**Banned**
```rust
#[allow(dead_code)]  // ❌ Never suppress
fn unused_function() {}

let unused_var = 42;  // ❌
let _unused_var = 42;  // Still triggers warning (good)
```

**Correct**
```rust
// Remove unused code. If keeping for future: add a TODO comment.
// TODO: implement after v1.0

// Use wildcard if all args needed for documentation:
#[allow(unused_variables)]
fn signature_example(a: i32, b: String, c: bool) {
    // ✅ Document the signature
}

// But for actual implementations: use all args or remove them
fn validate_input(a: i32, b: String) -> bool {  // ✅ Only used args
    a > 0 && !b.is_empty()
}
```

**CI Check**
```bash
cargo clippy --all-targets -- -D warnings -D clippy::all
```

### 3. NO Incomplete Implementations

**Rationale**: Placeholder code masks bugs, fails silently, breaks tests. Incomplete = untested = unsafe.

**Banned**
```rust
fn process_request(req: Request) -> Response {
    todo!()                        // ❌
}

fn handle_error(e: Error) {
    unimplemented!()               // ❌
}

fn validate_input(x: i32) -> bool {
    // TODO: implement validation
    true  // ❌ Placeholder return
}

match role {
    Role::Admin => { /* implemented */ },
    Role::User => { /* implemented */ },
    Role::Guest => { /* will add later */ }  // ❌ Missing arm or unreachable!()
}
```

**Correct**
```rust
fn process_request(req: Request) -> anyhow::Result<Response> {
    // ✅ Real implementation or returning error
    Ok(Response::ok())
}

fn validate_input(x: i32) -> anyhow::Result<()> {
    if x < 0 {
        anyhow::bail!("input must be >= 0");  // ✅ Explicit error
    }
    Ok(())
}

match role {
    Role::Admin => admin_action(),
    Role::User => user_action(),
    Role::Guest => guest_action(),  // ✅ All arms handled
}
```

### 4. Business Logic Must Be Verifiable

**Rationale**: Verifiable = testable + compilable. Pass `cargo check` without panics.

**Requirement**
```bash
# Before commit, all business logic must pass:
cargo check --all
cargo check --all --all-targets  # includes tests
# Zero warnings from clippy
cargo clippy --workspace --all-targets -- -D warnings
```

**Example: URL Validation**
```rust
// ✅ Verifiable: compiles, handles all cases, no panics
fn validate_public_url(url: &str) -> anyhow::Result<()> {
    let parsed = url::Url::parse(url)
        .context("invalid URL")?;
    
    let domain = parsed.host()
        .context("URL must have hostname")?;
    
    // Check for RFC-1918
    if is_private_ip(&domain) {
        anyhow::bail!("RFC-1918 address not allowed");
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn validates_public_urls() {
        assert!(validate_public_url("https://example.com").is_ok());
        assert!(validate_public_url("http://192.168.1.1").is_err());
    }
}
```

### 5. Validate with cargo check + cargo fix

**Rationale**: `cargo run` and `cargo build` might hide issues. `cargo check` and `cargo fix` catch them early.

**Pre-Commit Checklist**
```bash
# 1. Format
cargo fmt --all -- --check

# 2. Check for obvious errors
cargo check --all
cargo check --all --all-targets

# 3. Lint (pedantic + nursery warnings)
cargo clippy --workspace --all-targets -- -D warnings \
    -W clippy::pedantic \
    -W clippy::nursery

# 4. Fix some issues automatically
cargo fix --allow-dirty --all

# 5. Test
cargo test --all
```

### 6. Explicit Error Handling

**Rationale**: Never silently ignore errors. Validate external inputs. Always propagate or log.

**Banned**
```rust
let result = db.query(sql);  // ❌ What if it fails?
let json = serde_json::from_str(data).ok();  // ❌ Silently None
request.headers.get("host").and_then(|h| h.to_str().ok());  // ❌ Silent None
```

**Correct**
```rust
// Option 1: Propagate (recommended for library/internal functions)
let rows = db.query(sql).context("query failed")?;

// Option 2: Handle explicitly
let json: Value = match serde_json::from_str(data) {
    Ok(j) => j,
    Err(e) => {
        tracing::warn!("JSON parse failed: {e}");
        return Err(e).context("invalid JSON");
    }
};

// Option 3: Log before discarding
let host = request.headers
    .get("host")
    .and_then(|h| h.to_str().ok())
    .unwrap_or_else(|| {
        tracing::info!("missing or invalid Host header");
        "unknown"
    });
```

### 7. Minimize Allocations

**Rationale**: WAF handles 1000s of requests/sec. Every allocation matters.

**Patterns**
```rust
// ❌ Allocates unnecessarily
fn check_rule(input: String) -> bool {
    input.to_uppercase().contains("ADMIN")  // allocates String
}

// ✅ Avoid allocation
fn check_rule(input: &str) -> bool {
    input.to_uppercase().contains("ADMIN")  // still allocates (case conversion)
}

// ✅ Better: case-insensitive comparison
fn check_rule(input: &str) -> bool {
    input.to_ascii_uppercase().contains("ADMIN")  // or use regex with case flag
}

// ✅ Best: compiled regex (already in engine)
lazy_static::lazy_static! {
    static ref ADMIN_PATTERN: Regex = Regex::new("(?i)admin").unwrap();
}
fn check_rule(input: &str) -> bool {
    ADMIN_PATTERN.is_match(input)  // zero allocation
}
```

**Rules of Thumb**
- Prefer `&str` over `String`
- Prefer `Cow<str>` over `String` when ownership unclear
- Prefer `Arc<T>` over cloning large structs
- Reuse buffers (bytes::BytesMut) in loops
- Avoid `.clone()` in hot paths

---

## Rust Edition & Formatting

### Edition
- **Rust 2024 Edition** (minimum MSRV: 1.86)
- Update `Cargo.toml`: `edition = "2024"`

### Formatting (rustfmt)

**Config: `rustfmt.toml`**
```toml
edition = "2024"
max_width = 120
tab_spaces = 4
use_small_heuristics = "Default"
reorder_imports = true
normalize_doc_attributes = true
```

**Pre-Commit**
```bash
cargo fmt --all -- --check
```

### Linting (Clippy)

**Policy: -D warnings + pedantic + nursery**

```bash
cargo clippy --workspace --all-targets --all-features -- \
    -D warnings \
    -W clippy::pedantic \
    -W clippy::nursery
```

**workspace Cargo.toml**
```toml
[lints.rust]
unsafe_code = "deny"           # Deny unsafe blocks (except with SAFETY comment)
unused_must_use = "deny"       # Deny ignoring Result/Option
unused_variables = "deny"      # Deny unused vars

[lints.clippy]
all = "warn"
pedantic = "warn"
nursery = "warn"
```

---

## Error Handling Patterns

### anyhow + context

**Use in binary/app code** (when there's a caller to report to)

```rust
fn load_config(path: &str) -> anyhow::Result<AppConfig> {
    let content = std::fs::read_to_string(path)
        .context("failed to read config file")?;
    
    let config = toml::from_str(&content)
        .context("invalid TOML syntax")?;
    
    Ok(config)
}

// Caller handles:
match load_config("config.toml") {
    Ok(cfg) => { /* use cfg */ },
    Err(e) => eprintln!("Error: {e:?}"),
}
```

### thiserror + custom enum

**Use in library code** (when errors have semantic meaning)

```rust
#[derive(thiserror::Error, Debug)]
pub enum WafError {
    #[error("rule not found: {0}")]
    RuleNotFound(String),
    
    #[error("invalid rule format: {0}")]
    InvalidRuleFormat(String),
    
    #[error("database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
}

fn load_rule(id: &str) -> Result<Rule, WafError> {
    rules.get(id)
        .ok_or_else(|| WafError::RuleNotFound(id.to_string()))
}
```

### No silent failures

```rust
// ❌ Silent failure
let _: Result<_, _> = expensive_operation();

// ❌ Silently None
let val = fallible_operation().ok();
if val.is_some() { /* might be never */ }

// ✅ Explicit logging
let val = expensive_operation()
    .inspect_err(|e| tracing::warn!("operation failed: {e}"))
    .ok();

// ✅ Or propagate
let val = expensive_operation()?;
```

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

### 6. Modularized Rule Organization

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

### 7. Minimal Allocations in Hot Paths

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
