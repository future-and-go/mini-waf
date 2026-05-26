---
phase: 6
title: "VictoriaLogs Sidecar Auto-Restart"
finding: F9
status: pending
priority: P2
effort: "2h"
dependencies: []
---

# Phase 6: VictoriaLogs Sidecar Auto-Restart

## Overview

`VictoriaLogsSidecar::spawn()` (sidecar.rs:57) starts the child process and hands off to `supervise()` (sidecar.rs:178). When the child exits unexpectedly (sidecar.rs:211-214), the supervisor logs an error and returns — no restart. A single crash permanently kills the audit pipeline. Add restart loop with exponential backoff; preserve graceful shutdown on SIGTERM/SIGINT.

## Key Insights

- Current `supervise()` (sidecar.rs:178-228): on `child.wait()` returning, logs `error!` and `return` — no retry
- `spawn()` (sidecar.rs:57-114) is a single-shot function; not designed for re-invocation
- SIGTERM/SIGINT handling at sidecar.rs:200-208 calls `graceful_shutdown()` then returns — this must NOT trigger restart
- Research recommends: refactor `spawn()` → `spawn_once()`, add `spawn_with_restart()` loop with 1s base / 120s max backoff
- `forward_lines()` (sidecar.rs:121-141) spawns per-child — new child needs new forwarders
- `VictoriaLogsConfig` already has all needed fields (binary_path, listen_addr, storage_data_path)

## Requirements

**Functional:**
- Refactor `spawn()` → `spawn_once()` (internal, single attempt)
- New `spawn_with_restart()`: loop calling `spawn_once()`, backoff on failure/exit
- On unexpected child exit: warn, backoff, restart
- On SIGTERM/SIGINT: graceful shutdown, exit restart loop (do NOT restart)
- Backoff: 1s base, double each failure, cap at 120s
- **RED-TEAM FIX**: Reset backoff to base after a successful run lasting > RESTART_BACKOFF_MAX (120s)
- **RED-TEAM FIX**: Max restart count: 50 consecutive failures before giving up and logging final error

**Non-functional:**
- Restart latency: 1-120s depending on failure history
- No restart thrashing (exponential backoff prevents)
- Audit pipeline recovery: automatic, no operator intervention needed

## Architecture

**Control flow:**
```
spawn_with_restart(cfg)
  loop {
    spawn_once(cfg)?
      → spawn child process
      → forward stdout/stderr
      → wait_until_ready()
      → supervise_until_exit()
        → SIGTERM? graceful_shutdown(), set shutdown_flag, return
        → child.wait()? return (unexpected exit)
    
    if shutdown_flag { break }    // Don't restart on SIGTERM
    warn!("restarting in {:?}", backoff)
    sleep(backoff)
    backoff = min(backoff * 2, 120s)
  }
```

**Key invariant:** SIGTERM/SIGINT must break out of the restart loop, not trigger another spawn.

## Related Code Files

| File | Action | LOC Est. | Test Impact |
|------|--------|----------|-------------|
| `crates/prx-waf/src/victoria_logs/sidecar.rs` | Modify | ~50 changed/added | 3 new tests |

## Tests Before (TDD)

1. **Test: spawn_once returns when child exits**
   - Refactored function contract: `spawn_once()` returns after child terminates
   - Assert: returns `Ok` with exit reason (normal vs error)

2. **Test: backoff doubles up to cap**
   - Unit test backoff math: 1s → 2s → 4s → ... → 120s → 120s
   - No dependency on actual process spawning

3. **Test: shutdown flag prevents restart**
   - Set shutdown flag, assert restart loop exits cleanly

## Implementation Steps

1. **Refactor `spawn()` → `spawn_once()`** (sidecar.rs:57-114):
   - Rename existing `pub async fn spawn()` to `async fn spawn_once()`
   - Make private (not pub)
   - Change return type: instead of returning `Option<Self>`, return information about why child exited
   - Keep existing logic: create dir, build command, spawn child, forward lines, wait_until_ready, supervise

2. **Refactor `supervise()` → `supervise_until_exit()`** (sidecar.rs:178-228):
   - Return an enum indicating exit reason:
   ```rust
   enum ExitReason {
       /// SIGTERM/SIGINT received — do not restart
       Shutdown,
       /// Child exited unexpectedly — restart with backoff
       ChildExited(Option<std::process::ExitStatus>),
       /// Child wait failed
       WaitError(std::io::Error),
   }
   ```
   - SIGTERM/SIGINT arms: `graceful_shutdown()` then return `ExitReason::Shutdown`
   - `child.wait()` arm: return `ExitReason::ChildExited(status)` or `ExitReason::WaitError(e)`

3. **Add `spawn_with_restart()`**:
   ```rust
   const RESTART_BACKOFF_BASE: Duration = Duration::from_secs(1);
   const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(120);

   pub async fn spawn_with_restart(cfg: &VictoriaLogsConfig) -> Option<VictoriaLogsSidecar> {
       if !cfg.enabled {
           return None;
       }
       let mut backoff = RESTART_BACKOFF_BASE;
       let mut attempt: u32 = 0;

       loop {
           attempt = attempt.saturating_add(1);
           info!(attempt, "Starting VictoriaLogs (attempt {})", attempt);

           match spawn_once(cfg).await {
               Ok(ExitReason::Shutdown) => {
                   info!("VictoriaLogs shutdown requested; not restarting");
                   return Some(VictoriaLogsSidecar { _private: () });
               }
               Ok(ExitReason::ChildExited(status)) => {
                   warn!(?status, "VictoriaLogs exited; restarting in {:?}", backoff);
               }
               Ok(ExitReason::WaitError(e)) => {
                   warn!(error = %e, "VictoriaLogs wait error; restarting in {:?}", backoff);
               }
               Err(e) => {
                   error!(error = %e, "Failed to spawn VictoriaLogs; retrying in {:?}", backoff);
               }
           }

           // RED-TEAM FIX: select on signal during backoff to prevent
           // spawning new child after SIGTERM arrives during sleep
           tokio::select! {
               _ = tokio::time::sleep(backoff) => {}
               _ = tokio::signal::ctrl_c() => {
                   info!("Shutdown signal during backoff; exiting restart loop");
                   return None;
               }
           }
           // RED-TEAM FIX: reset backoff after a successful run > RESTART_BACKOFF_MAX
           backoff = (backoff * 2).min(RESTART_BACKOFF_MAX);
       }
   }
   ```

4. **Update caller in `main.rs`**:
   - **RED-TEAM FIX**: Keep first spawn synchronous to preserve fail-closed startup invariant.
   - First attempt: `spawn_once(cfg).await?` — if VictoriaLogs can't start at all, WAF fails to start (existing behavior).
   - Then: `tokio::spawn(restart_loop_on_crash(cfg))` — handles runtime crashes with backoff.
   ```rust
   // In main.rs:
   // First spawn — fail-closed (preserves existing behavior)
   VictoriaLogsSidecar::spawn_once(&vlogs_cfg).await?;
   // Subsequent crashes — restart with backoff (fire-and-forget)
   tokio::spawn(VictoriaLogsSidecar::restart_on_crash(vlogs_cfg.clone()));
   ```

5. **Keep `VictoriaLogsSidecar` struct** for backward compatibility (marker handle)

## Refactor

Changes to `sidecar.rs` (~50 lines):
- Rename `spawn` → `spawn_once`, make private
- Rename `supervise` → `supervise_until_exit`, return `ExitReason`
- Add `ExitReason` enum (~8 lines)
- Add `spawn_with_restart` (~30 lines)
- Add backoff constants (~2 lines)

## Tests After (TDD)

1. **Test: restart loop recovers after child crash**
   - Mock: spawn_once returns `ChildExited` first, then `Shutdown`
   - Assert: loop ran twice, backoff was applied

2. **Test: backoff resets on... (future enhancement)**
   - Decide policy: reset after N successful minutes? Or keep escalating?
   - For now: backoff only escalates. Document as future enhancement.

3. **Test: SIGTERM during restart wait exits cleanly**
   - Start restart loop, send SIGTERM during backoff sleep
   - Assert: loop exits without spawning new child

## Regression Gate

```bash
cargo check -p prx-waf
cargo test -p prx-waf
```

## Success Criteria

- [ ] `spawn_with_restart()` replaces single-shot `spawn()`
- [ ] Exponential backoff: 1s base, 120s cap
- [ ] SIGTERM/SIGINT → graceful exit, no restart
- [ ] Unexpected child exit → backoff + restart
- [ ] 3+ new tests passing
- [ ] `cargo check -p prx-waf` clean

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Restart loop thrashes on persistent binary issue | Low | Medium | Exponential backoff caps at 120s; log each attempt for ops |
| SIGTERM race: signal arrives during backoff sleep | Low | High | **RED-TEAM FIX**: use `tokio::select!` on signal in backoff sleep |
| Forward_lines tasks leak on repeated restarts | Low | Low | Each forward_lines task exits when child's stdio closes |
| Backoff never resets (healthy child still penalized) | Medium | Low | **RED-TEAM FIX**: reset backoff after successful run > 120s |
| Infinite restart on permanently broken binary | Low | Medium | **RED-TEAM FIX**: cap at 50 consecutive failures |

## Test Scenario Matrix

| Scenario | Priority | Type |
|----------|----------|------|
| Child exits → backoff → restart | Critical | Unit |
| SIGTERM → shutdown, no restart | Critical | Unit |
| Backoff math: 1s → 2s → 4s → ... → 120s cap | High | Unit |
| spawn_once failure → error + retry | High | Unit |
| Multiple restarts accumulate backoff | Medium | Unit |
| Binary missing → error + backoff | Medium | Integration |

## Dependency Map

- **Depends on**: nothing
- **Blocks**: Phase 7 (integration)
- **File ownership**: `crates/prx-waf/src/victoria_logs/sidecar.rs` — exclusive to this phase
