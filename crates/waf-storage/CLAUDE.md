# waf-storage

Persistence layer for the WAF. Wraps `sqlx` and exposes typed models + repositories used by the API, engine, and cluster crates.

## Features
- **Database access**: connection pool setup and migrations via `sqlx`.
- **Models**: strongly-typed records for rules, users, events, tunnels, plugins, etc.
- **Repositories**: CRUD-style query helpers, parameterized only (no string-built SQL).
- **Error type**: unified `StorageError` for upstream `?` propagation.

## Folder Structure
```
src/
├── lib.rs       # Public re-exports
├── db.rs        # Pool + connection management
├── models.rs    # Row structs and enums
├── repo.rs      # Repository functions (queries, inserts, updates)
└── error.rs     # StorageError type
```

## Dependencies
`sqlx`, `tokio`, `serde`, `chrono`, `uuid`, `thiserror`, `tracing`. No dependency on other workspace crates.
