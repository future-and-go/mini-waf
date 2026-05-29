---
phase: 3
title: "JSONL Interop Audit Writer (§6)"
status: pending
priority: P1
effort: "1d"
dependencies: [1]
---

# Phase 3: JSONL Interop Audit Writer (§6)

## Overview

Implement a file-based JSONL audit logger that writes to `./waf_audit.log` in the contract-required schema. **VictoriaLogs remains the primary logging system** — this JSONL writer is a secondary, interop-contract-only output. Additive only; no changes to the VictoriaLogs pipeline.

## Context Links

- Contract §6: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 414–466
- Contract §10 (IP semantics): same file lines 548–559
- Gap report §6: `plans/reports/contract-gap-analysis-260527-1133-waf-interop-v23-report.md` lines 86–109
- Current audit: `crates/waf-engine/src/logging/` (AuditEvent, BatchSender → VictoriaLogs)
- RequestCtx: `crates/waf-common/src/types.rs`

## Requirements

**Functional (contract §6):**

| Field | Type | Constraint |
|-------|------|-----------|
| `request_id` | UUID v4 string | Must match `X-WAF-Request-Id` header |
| `ts_ms` | integer | Unix epoch milliseconds (NOT RFC3339) |
| `ip` | string | TCP peer_addr — NOT XFF. IPv4 dotted decimal |
| `method` | string | Uppercase HTTP method |
| `path` | string | Request path including query string |
| `action` | string | One of 6 contract decision classes |
| `risk_score` | integer 0–100 | Score at decision time |
| `mode` | string | `enforce` or `log_only` |

**Behavioral:**
- Append-only, one JSON object per line (JSONL)
- File: `./waf_audit.log` (configurable path in TOML config)
- `reset_state` (Phase 4) MUST NOT modify this file
- File created on first request, not on startup
- Buffered writes with periodic flush (100ms or 64KB — whichever first)
- **User decision:** Config toggle — `[interop] audit_log_enabled = true` (default true). When false, JSONL writer skipped; VictoriaLogs (primary) unaffected.
- **User decision:** VictoriaLogs is the primary logging system. JSONL is secondary, interop-contract output only.

**Non-functional:**
- VictoriaLogs pipeline unchanged — primary logging, no modifications
- Writer must be async-safe (`tokio::fs` or background writer thread)
- Backpressure: if write queue full (>10K pending), drop oldest with warn log

## Architecture

### Trait-Based Design for Extensibility

```rust
// crates/waf-engine/src/logging/audit_writer.rs
#[async_trait]
pub trait AuditWriter: Send + Sync {
    async fn write(&self, entry: &InteropAuditEntry) -> anyhow::Result<()>;
    async fn flush(&self) -> anyhow::Result<()>;
    fn name(&self) -> &'static str;
}
```

### InteropAuditEntry (contract-compliant schema)

```rust
// crates/waf-engine/src/logging/interop_audit_entry.rs
#[derive(Serialize)]
pub struct InteropAuditEntry {
    pub request_id: String,
    pub ts_ms: u64,
    pub ip: String,       // TCP peer_addr only
    pub method: String,
    pub path: String,
    pub action: String,   // contract action string
    pub risk_score: u16,
    pub mode: String,     // "enforce"|"log_only"
    // Teams MAY add extra fields (contract §6 additional fields)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
}
```

### JsonlFileWriter Implementation

```rust
// crates/waf-engine/src/logging/jsonl_file_writer.rs
pub struct JsonlFileWriter {
    sender: tokio::sync::mpsc::Sender<InteropAuditEntry>,
}
```

Background task pattern:
1. `mpsc::channel(10_000)` — bounded to prevent memory blowup
2. Background tokio task receives entries, serializes to JSON, appends `\n`
3. Uses `tokio::io::BufWriter<tokio::fs::File>` with `OpenOptions::append(true).create(true)`
4. Flushes every 100ms via `tokio::time::interval` OR when buffer hits 64KB
5. On channel full (backpressure), `try_send` fails → warn log, drop entry

### Audit Dispatch (VictoriaLogs primary + JSONL secondary)

```rust
// crates/waf-engine/src/logging/audit_dispatcher.rs
pub struct AuditDispatcher {
    primary: Arc<BatchSender>,         // VictoriaLogs — unchanged
    interop_writer: Arc<JsonlFileWriter>, // secondary, interop-only
}
```

The dispatcher converts the existing `AuditEvent` into `InteropAuditEntry` and sends to the JSONL writer **after** the primary VictoriaLogs send. VictoriaLogs call site unchanged; JSONL writer is appended as a secondary sink.

### IP Field: TCP peer_addr Only (RT-01 Fix)

Contract §6 + §10: `ip` field MUST be TCP peer_addr. Current `client_ip` may come from XFF when `trust_proxy_headers=true`.

**Red-team finding RT-01:** `RequestCtx` does NOT have a separate `peer_addr` field. Only `client_ip` exists, which is XFF-resolved. Phase 1 adds `socket_ip: IpAddr` to `RequestCtx`, populated from `peer_addr.ip()` in `request_ctx_builder.rs:79`.

Solution: Use `request_ctx.socket_ip` (added in Phase 1) for the JSONL `ip` field. This is always the TCP peer address, never XFF-resolved.

## Related Code Files

**Create:**
- `crates/waf-engine/src/logging/audit_writer.rs` — AuditWriter trait
- `crates/waf-engine/src/logging/interop_audit_entry.rs` — contract-aligned entry struct
- `crates/waf-engine/src/logging/jsonl_file_writer.rs` — file-based JSONL writer

**Modify:**
- `crates/waf-engine/src/logging/mod.rs` — export new modules
- `crates/waf-engine/src/logging/audit_sender.rs` — append JSONL secondary writer alongside existing BatchSender (primary unchanged)
- `crates/waf-common/src/config.rs` — add `audit_log_path` config field (default: `"./waf_audit.log"`)
- `crates/prx-waf/src/main.rs` — initialize JsonlFileWriter and inject into engine

## Implementation Steps

### TDD: Write Tests First

1. **Unit test for `InteropAuditEntry` serialization**:
   - Verify JSON output matches contract schema exactly
   - `ts_ms` is integer, not string
   - `ip` is IPv4 dotted decimal
   - `action` is one of 6 contract strings
   - `mode` is `"enforce"` or `"log_only"`
   - Extra fields present when set, absent when None

2. **Unit test for `JsonlFileWriter`**:
   - Write 3 entries → read file back → each line is valid JSON parseable to `InteropAuditEntry`
   - Lines separated by `\n` (no trailing newline on empty file)
   - File created lazily on first write

3. **Unit test for IP semantics**:
   - Given `trust_proxy_headers=true` and XFF header present
   - `InteropAuditEntry.ip` MUST be TCP peer_addr, NOT the XFF-resolved IP

4. **Unit test for backpressure**:
   - Fill channel to capacity → verify `try_send` returns error → writer continues working after drain

5. **Integration test for audit dispatch**:
   - Send audit event through dispatcher → verify VictoriaLogs (primary) receives entry AND JSONL file (secondary) receives entry

### Implement

6. **Add config field** in `crates/waf-common/src/config.rs`:
   ```rust
   pub audit_log_path: Option<String>, // default: "./waf_audit.log"
   ```

7. **Create `InteropAuditEntry`** struct with serde derive

8. **Create `AuditWriter` trait** — async write + flush + name

9. **Create `JsonlFileWriter`**:
   - Constructor takes file path
   - Spawns background task with mpsc receiver
   - BufWriter + periodic flush
   - `write()` sends entry to channel via `try_send`
   - `flush()` sends a flush signal

10. **Add conversion** from existing audit context to `InteropAuditEntry`:
    - Map `WafAction` → contract action string via `as_contract_str()` (Phase 1)
    - Map `InteropMode` → "enforce"/"log_only"
    - Use `peer_addr` for `ip` field (NOT `client_ip`)
    - Convert timestamp to epoch milliseconds

11. **Wire JSONL secondary** at the existing audit emission point:
    - After the existing `BatchSender::send()` call (VictoriaLogs primary, unchanged), also send to `JsonlFileWriter`
    - JSONL send is fire-and-forget; VictoriaLogs path untouched

12. **Initialize in main.rs**:
    - Read `audit_log_path` from config (default `"./waf_audit.log"`)
    - Create `JsonlFileWriter` and inject into engine/audit layer

### Validate

13. `cargo check --workspace`
14. `cargo test --workspace`
15. `cargo clippy --workspace -- -D warnings`
16. Manual test: send requests → verify `./waf_audit.log` contains valid JSONL entries
17. Verify `cat waf_audit.log | python3 -c "import sys,json; [json.loads(l) for l in sys.stdin]"` succeeds

## Success Criteria

- [ ] `./waf_audit.log` created on first request
- [ ] Each line is valid JSON matching contract schema
- [ ] `request_id` matches `X-WAF-Request-Id` header
- [ ] `ts_ms` is integer Unix epoch milliseconds
- [ ] `ip` is TCP peer_addr, NOT XFF
- [ ] `action` is one of 6 contract strings
- [ ] `mode` is `enforce` or `log_only`
- [ ] VictoriaLogs (primary) audit continues working unchanged (no regression)
- [ ] Buffered writes with periodic flush (no per-request fsync)
- [ ] `cargo check --workspace` passes
- [ ] All tests pass

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| File I/O blocks async runtime | High | BufWriter + background task with mpsc channel |
| Disk full stops audit logging | Medium | Warn log on write error; don't crash. Contract doesn't require guaranteed delivery |
| peer_addr not available on RequestCtx | Medium | Verify in request_ctx_builder.rs; add if missing |
| JSON serialization performance | Low | serde_json is fast; entries are small (<500 bytes) |
| File rotation not handled | Low | Contract doesn't require rotation; append-only is fine for benchmark runs |
