# Code Standards & Core Rules

Core standards for mini-waf development. For detailed safety patterns, testing strategies, and operational conventions, see [code-safety-patterns.md](./code-safety-patterns.md).

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

## Hot-Reload Patterns (Lock-Free Updates)

### ArcSwap Pattern (Recommended)

Use `ArcSwap` for atomic, lock-free reads of configuration snapshots during request processing.

**Setup**:
```rust
use arc_swap::ArcSwap;
use std::sync::Arc;

pub struct Config { /* ... */ }
pub struct Router {
    config: Arc<ArcSwap<Config>>,
}

impl Router {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(ArcSwap::new(Arc::new(config))),
        }
    }
    
    // Hot-reload: atomically swap config, no lock held during reads
    pub fn reload(&self, new_config: Config) {
        self.config.store(Arc::new(new_config));
    }
    
    // Request path: cheap load (one atomic read)
    pub fn classify(&self, req: &Request) -> Decision {
        let cfg = self.config.load_full();  // Arc clone, no lock
        cfg.classify(req)
    }
}
```

**Why ArcSwap**:
- ✓ Zero-copy atomic swap (no garbage collection)
- ✓ Lock-free reads (no mutex in hot path)
- ✓ No panics (Arc semantics are infallible)
- ✓ Supports multi-threaded reload without request interruption

**Typical integration**:
- File watcher (notify crate) detects file changes
- Background thread parses new config (≤500ms)
- On validation success: `router.reload(new_config)` swaps atomically
- On validation failure: retry or log warn; old config persists

### File Watcher Integration

```rust
use notify::{Watcher, RecursiveMode, Result as NotifyResult};

pub fn watch_config<F>(path: &str, on_change: F) -> NotifyResult<()>
where
    F: Fn(&Path) + Send + 'static,
{
    let mut watcher = notify::recommended_watcher(move |event| match event {
        Ok(notify::Event {
            kind: notify::EventKind::Modify(_),
            paths,
            ..
        }) => {
            for path in paths {
                on_change(&path);
            }
        }
        _ => {}
    })?;
    
    watcher.watch(std::path::Path::new(path), RecursiveMode::NonRecursive)?;
    std::mem::forget(watcher);  // Keep alive
    Ok(())
}
```

**Debounce pattern** (suppress editor burst saves):
```rust
use std::sync::Mutex;
use std::time::Instant;

pub struct DebouncedReloader {
    last_reload: Mutex<Instant>,
    debounce_ms: u64,
}

impl DebouncedReloader {
    pub fn maybe_reload(&self, path: &Path) -> bool {
        let mut last = self.last_reload.lock().unwrap();
        if last.elapsed().as_millis() > self.debounce_ms as u128 {
            *last = Instant::now();
            true  // Proceed with reload
        } else {
            false  // Skip (within debounce window)
        }
    }
}
```

### Data File Hot-Reload (DataFileRegistry)

For `.data` files (external dictionaries, Aho-Corasick patterns):

```rust
// Load automaton from .data file with caching
let registry = DataFileRegistry::new();
let automaton = registry.load_or_get("rules/patterns.data")?;
// File changed? notify watcher triggers re-cache

// File watcher detects change → registry invalidates cache key
// Next load_or_get() recompiles from disk
```

**Size validation**:
- Soft warn: ≥50k entries (log at WARN level)
- Hard reject: ≥500k entries (parse error, config rollback)

---

## Related Documentation

For additional safety patterns, testing strategies, operational conventions, and feature-specific guidance, see:

- [code-safety-patterns.md](./code-safety-patterns.md) — SQL safety, synchronization, logging, testing, commit style, code review checklist, modularization patterns, Redis conventions, and FR-025 risk scoring
