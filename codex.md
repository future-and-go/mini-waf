# codex.md — prx-waf Production Standards

## Rust Edition: 2024

## Seven Iron Rules
1. NO .unwrap()/.expect() in production — use ?, unwrap_or, if let, explicit error returns
2. NO dead code — zero unused variables/params/imports, zero warnings
3. NO todo!()/unimplemented!()/placeholder returns/empty match arms
4. All code must pass cargo check — no speculative interfaces
5. Validate with cargo check + cargo fix
6. Explicit error handling — validate inputs, never panic for errors
7. Minimize allocations — &str > String, Cow > clone, Arc > deep copy

## Build
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --release
```

## Docker
```bash
podman-compose down && podman-compose up -d --build
```

## More Rules
- Parameterized SQL only (sqlx bind)
- parking_lot::Mutex for sync, tokio::sync::Mutex for async — NEVER std::sync::Mutex
- Every unsafe needs // SAFETY: comment
- Never log secrets/tokens
- English in code and commits
