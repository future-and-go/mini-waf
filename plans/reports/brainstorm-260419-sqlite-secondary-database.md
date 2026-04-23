# Brainstorm: SQLite as Secondary Database

**Date:** 2026-04-19  
**Status:** Design Complete  
**Scope:** Enable PRX-WAF standalone mode with SQLite for edge/embedded deployment

---

## Problem Statement

PRX-WAF currently requires PostgreSQL 16+ for all deployments. This creates friction for:
- Edge/embedded deployments on resource-constrained devices
- Air-gapped environments without network database access
- IoT gateways and small VPS where PostgreSQL overhead is prohibitive

**Goal:** Support SQLite as production-grade alternative for single-node deployments.

---

## Requirements Summary

| Requirement | Decision |
|-------------|----------|
| Primary use case | Edge/embedded deployment |
| Database selection | Compile-time feature flags |
| Cluster support | No (PostgreSQL required for clustering) |
| Expected scale | 100K+ events/day |
| Migration strategy | Separate migration sets per DB |
| Feature handling | Hybrid (JSON for complex, normalized for queries) |
| Data retention | Configurable TTL (default 7 days) |

---

## Technical Analysis

### PostgreSQL Features Requiring Adaptation

| Feature | PostgreSQL | SQLite Adaptation |
|---------|------------|-------------------|
| `INET` | Native IP type with CIDR ops | `TEXT` + app-level IP validation |
| `JSONB` | Binary JSON with indexing | `TEXT` + `json_extract()` |
| `gen_random_uuid()` | DB-side UUID | App-generated before INSERT |
| `TIMESTAMPTZ` | Timezone-aware | `TEXT` ISO 8601 format |
| `ON CONFLICT DO UPDATE` | Upsert | `INSERT OR REPLACE` / two-step |
| `RETURNING *` | Return inserted row | Supported in SQLite 3.35+ |
| Connection pooling | Built-in with sqlx | WAL mode + limited connections |

### SQLite Production Considerations (100K+ events/day)

1. **WAL Mode** - Required for concurrent reads during writes
2. **Busy timeout** - Set 5-10s to handle write contention
3. **PRAGMA optimizations** - `journal_mode=WAL`, `synchronous=NORMAL`, `cache_size=-64000`
4. **Single writer** - SQLite allows only one writer; use app-level queue for batch inserts
5. **Auto-vacuum** - Enable `PRAGMA auto_vacuum=INCREMENTAL` + periodic cleanup
6. **Connection limit** - Max 2-4 connections (1 writer, 1-3 readers)

### Feature Flag Design

```toml
# Cargo.toml feature flags
[features]
default = ["postgres"]
postgres = ["sqlx/postgres"]
sqlite = ["sqlx/sqlite"]
```

**Binary variants:**
- `prx-waf` (default) - PostgreSQL backend
- `prx-waf-sqlite` - SQLite backend (via `--no-default-features --features sqlite`)

---

## Recommended Architecture

### Approach: Trait-Based Abstraction

```
crates/waf-storage/
├── src/
│   ├── lib.rs              # Re-exports
│   ├── db.rs               # Database struct (refactored)
│   ├── error.rs            # StorageError (unchanged)
│   ├── models.rs           # Shared models (mostly unchanged)
│   ├── repo.rs             # Repository methods dispatch to backend
│   └── backend/
│       ├── mod.rs          # AnyPool enum, shared traits
│       ├── postgres.rs     # PostgreSQL-specific implementations
│       └── sqlite.rs       # SQLite-specific implementations
```

### Pool Abstraction

```rust
// backend/mod.rs
pub enum AnyPool {
    #[cfg(feature = "postgres")]
    Postgres(sqlx::PgPool),
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::SqlitePool),
}

impl AnyPool {
    pub async fn connect(url: &str, max_conn: u32) -> Result<Self, StorageError>;
    pub async fn migrate(&self) -> Result<(), StorageError>;
}
```

### Query Strategy

**Option A: Separate query modules** (Recommended for large divergence)
```rust
// repo.rs dispatches based on feature
impl Database {
    pub async fn create_host(&self, req: CreateHost) -> Result<Host, StorageError> {
        #[cfg(feature = "postgres")]
        return self.pg_create_host(req).await;
        
        #[cfg(feature = "sqlite")]
        return self.sqlite_create_host(req).await;
    }
}
```

**Option B: SQL macros for minor differences**
```rust
macro_rules! sql {
    (postgres: $pg:expr, sqlite: $sl:expr) => {{
        #[cfg(feature = "postgres")] { $pg }
        #[cfg(feature = "sqlite")] { $sl }
    }};
}
```

---

## Migration Strategy

### Directory Structure

```
migrations/
├── postgres/
│   ├── 0001_initial.sql
│   ├── 0002_security_events.sql
│   └── ...
└── sqlite/
    ├── 0001_initial.sql
    ├── 0002_security_events.sql
    └── ...
```

### SQLite Schema Adaptations

```sql
-- PostgreSQL
CREATE TABLE hosts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    remote_ip INET,
    defense_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- SQLite equivalent
CREATE TABLE hosts (
    id TEXT PRIMARY KEY,  -- UUID as TEXT
    remote_ip TEXT,       -- IP as TEXT
    defense_json TEXT,    -- JSON as TEXT
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### Migration Execution

```rust
impl AnyPool {
    pub async fn migrate(&self) -> Result<(), StorageError> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(pool) => {
                sqlx::migrate!("../../migrations/postgres").run(pool).await?;
            }
            #[cfg(feature = "sqlite")]
            Self::Sqlite(pool) => {
                sqlx::migrate!("../../migrations/sqlite").run(pool).await?;
            }
        }
        Ok(())
    }
}
```

---

## Data Retention System

### TTL-Based Cleanup (Background Task)

```rust
pub struct RetentionConfig {
    pub attack_logs_ttl_days: u32,      // Default: 7
    pub security_events_ttl_days: u32,  // Default: 7
    pub audit_log_ttl_days: u32,        // Default: 30
    pub request_stats_ttl_days: u32,    // Default: 90
    pub cleanup_interval_secs: u64,     // Default: 3600 (hourly)
}
```

### Cleanup Queries

```sql
-- Delete old attack logs
DELETE FROM attack_logs 
WHERE created_at < datetime('now', '-7 days');

-- Delete old security events
DELETE FROM security_events 
WHERE timestamp < datetime('now', '-7 days');

-- Run VACUUM after large deletions
PRAGMA incremental_vacuum(1000);
```

### Config Integration

```toml
# configs/default.toml
[storage.retention]
enabled = true
attack_logs_ttl_days = 7
security_events_ttl_days = 7
audit_log_ttl_days = 30
cleanup_interval_secs = 3600
```

---

## Cluster Mode Handling

SQLite mode explicitly disables cluster features:

```rust
// In main.rs or config validation
#[cfg(feature = "sqlite")]
fn validate_config(config: &AppConfig) -> Result<(), ConfigError> {
    if config.cluster.enabled {
        return Err(ConfigError::IncompatibleFeature(
            "Cluster mode requires PostgreSQL. Disable cluster or use postgres feature."
        ));
    }
    Ok(())
}
```

Compile-time enforcement:
```rust
// waf-cluster/Cargo.toml
[dependencies]
waf-storage = { path = "../waf-storage", features = ["postgres"] }
```

---

## Performance Optimizations for SQLite

### Connection Setup

```rust
pub async fn connect_sqlite(path: &str) -> Result<SqlitePool, StorageError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(4)  // Limited for SQLite
        .after_connect(|conn, _meta| Box::pin(async move {
            // Enable WAL mode
            sqlx::query("PRAGMA journal_mode=WAL").execute(conn).await?;
            // Reasonable sync for durability/perf balance
            sqlx::query("PRAGMA synchronous=NORMAL").execute(conn).await?;
            // 64MB cache
            sqlx::query("PRAGMA cache_size=-65536").execute(conn).await?;
            // Temp tables in memory
            sqlx::query("PRAGMA temp_store=MEMORY").execute(conn).await?;
            // Busy timeout for concurrent access
            sqlx::query("PRAGMA busy_timeout=5000").execute(conn).await?;
            Ok(())
        }))
        .connect(path)
        .await?;
    Ok(pool)
}
```

### Batch Insert for High-Volume Logs

```rust
pub async fn batch_create_attack_logs(
    &self, 
    events: Vec<CreateAttackLog>
) -> Result<usize, StorageError> {
    // SQLite: Use transaction + prepared statement
    let mut tx = self.pool.begin().await?;
    let mut count = 0;
    for event in events {
        sqlx::query("INSERT INTO attack_logs (...) VALUES (?, ?, ...)")
            .bind(...)
            .execute(&mut *tx)
            .await?;
        count += 1;
    }
    tx.commit().await?;
    Ok(count)
}
```

---

## Implementation Phases

### Phase 1: Infrastructure (~2 days)
- Create backend/ module structure
- Implement AnyPool enum with feature gates
- Refactor Database struct to use AnyPool
- Update Cargo.toml with feature flags

### Phase 2: Migrations (~1 day)
- Create migrations/sqlite/ directory
- Port all 8 migrations to SQLite-compatible SQL
- Update migration runner for dual paths

### Phase 3: Repository Layer (~3 days)
- Create backend/postgres.rs with existing queries
- Create backend/sqlite.rs with adapted queries
- Add dispatch logic in repo.rs
- Handle INET, JSONB, UUID differences

### Phase 4: SQLite Optimizations (~1 day)
- Implement WAL mode and PRAGMA setup
- Add connection pool configuration
- Implement batch insert helpers

### Phase 5: Retention System (~1 day)
- Add RetentionConfig to AppConfig
- Implement background cleanup task
- Add CLI command for manual cleanup

### Phase 6: Testing & Validation (~2 days)
- Create SQLite-specific integration tests
- Test high-volume insert (100K events)
- Validate cleanup performance
- Test edge cases (concurrent access, crash recovery)

**Total Estimate:** ~10 days

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| SQLite write contention at scale | Medium | High | Batch inserts, connection limiting, event buffering |
| Query compatibility issues | Medium | Medium | Separate query modules, comprehensive tests |
| Migration drift between DBs | Low | High | CI tests for both backends, migration version tracking |
| Missing SQLite 3.35+ features | Low | Medium | Document minimum SQLite version (3.35.0) |

---

## Success Criteria

1. **Functional Parity:** All API endpoints work identically with SQLite
2. **Performance:** Handle 100K events/day without degradation
3. **Data Integrity:** WAL mode + fsync ensures crash safety
4. **Clean Builds:** Both `--features postgres` and `--features sqlite` compile cleanly
5. **Migration Coverage:** All tables/indexes present in both schemas
6. **Retention Working:** Background cleanup runs hourly, respects TTL config

---

## Decisions

| Question | Decision |
|----------|----------|
| SQLite file location | `./data/prx-waf.db` (configurable via `storage.database_url`) |
| Backup strategy | Document sqlite3 `.backup` command in deployment guide |
| In-memory mode | Support `sqlite::memory:` for testing only |

---

## Next Steps

1. **Approve design** → Create implementation plan with phases
2. **Create feature branch** → `feat/sqlite-backend`
3. **Start Phase 1** → Infrastructure and AnyPool abstraction
