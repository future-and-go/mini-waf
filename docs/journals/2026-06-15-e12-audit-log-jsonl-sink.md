# E12: Audit Log JSONL Sink — VictoriaLogs Decommissioned

**Date:** 2026-06-15
**Severity:** High
**Component:** Audit logging, configuration, API routes
**Status:** Closed

## What Happened

Epic E12 shipped: converted audit-only sink from VictoriaLogs remote service to a configurable append-only JSONL file (`./waf_audit.log`), fully decommissioned the remote logging stack, and wired the contract into response headers.

## The Brutal Truth

This was clean but required surgical deconstruction. VictoriaLogs was pervasive — 13 files deleted, routes nuked, state torn down — and the urge to ship a half-working stub was strong when integration tests started failing. Resisted that. Took time to fix the real bugs (bad action values in error paths, stale route tests, config block migration) before merging. No shortcuts.

## Technical Details

**Architecture:**
- Dedicated append thread + bounded sync_channel (10k cap) + BufWriter off hot path
- Lazy file creation on first record; drop-on-backpressure via `try_send`
- Flush every 500ms; survives reset_state calls
- New `[audit]` config block (AuditFileConfig{enabled, log_path}) replaces `[victoria_logs]`

**Contract (8 required fields, verified):**
- `request_id` (UUIDv4), `ts_ms` (epoch ms int), `ip` (TCP peer_addr, never XFF)
- `method` (uppercase), `path` (with query string), `action` (one of six decision classes)
- `risk_score` (0–100 int), `mode` (enforce / log_only)

**Correlations:**
- `request_id` + `mode` mirror X-WAF-Request-Id / X-WAF-Mode response headers verbatim
- TCP peer_addr governs `ip` field; distinct 127.0.0.x clients logged separately
- `client_ip` preserved as extra key for XFF-resolved source (informational, not required)

**Code footprint:**
- `crates/waf-engine/src/logging/audit_sender.rs` (record build)
- `audit_file_sink.rs` (writer thread)
- Deletions: vlogs_layer.rs, batch_buffer.rs, 13 files total, VictoriaLogsConfig, /api/v1/logs/* routes, victoria_logs_base_url state

## Lessons Learned

**Error-path bugs are easy to miss at review.** Two fail-closed sites hardcoded action:"error" (not a valid class). Grep for all audit record build sites before closing; don't rely on tests alone.

**Config migration must be explicit.** Old `[victoria_logs]` block was still in default.toml when code was deleted. Would have broken user upgrades silently. Always verify config block names match between code and fixture files.

**Test cleanup is verification.** Stale tests asserting 400 on deleted routes made it obvious what needed removal. Trust the gaps.

## Next Steps

- Monitor audit log file growth in production (plan cap/rotation if needed).
- Update upgrade guide to note config block change from `[victoria_logs]` to `[audit]`.

**Proof:** cargo check -p waf-api --tests clean; audit_file_sink_integration 5/5; audit_sender 12 unit + audit_file_sink 3 unit; zero live victoria refs via grep.
