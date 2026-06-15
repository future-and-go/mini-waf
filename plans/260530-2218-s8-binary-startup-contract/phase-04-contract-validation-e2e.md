---
phase: 4
title: "Contract validation E2E"
status: pending
priority: P1
effort: "0.5d"
dependencies: [3]
---

# Phase 4: Contract validation E2E

## Overview

Prove the §8 startup contract end-to-end by mimicking the benchmarker exactly: from a clean working directory containing `./waf` and `./waf.toml`, run `./waf run`, poll the health endpoint until it returns `200`, measure the time-to-ready, and assert `./waf_audit.log` (parent-plan dependency) appears after a single proxied request. No code changes — pure validation.

## Context Links

- Contract §8: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 504–528 (binary contract + health check)
- Phase 1: binary is `waf`
- Phase 2: config auto-discovery picks up `./waf.toml` from CWD
- Phase 3: `./waf` and `./waf.toml` exist at repo root after running the release script
- Health endpoint: gateway plane at `/health` (proxy.rs:607), admin plane at `/health` (waf-api/server.rs:95)
- Parent-plan dependency for `./waf_audit.log`: `260527-1157-waf-interop-v23-critical-compliance` Phase 3

## Requirements

**Functional (mimic benchmarker exactly):**
1. From a clean shell, `cd` to a directory containing `./waf` and `./waf.toml`.
2. Execute `./waf run` as a background process; capture PID.
3. Poll `GET http://127.0.0.1:<gateway-port>/health` every 250 ms.
4. First `200` response → record the elapsed seconds since spawn.
5. Send one real proxied request → assert `./waf_audit.log` exists with ≥1 JSONL line (only enforced if parent-plan Phase 3 is merged; otherwise skipped with a logged warning).
6. Send `SIGTERM` → assert clean exit within 5 s.

**Non-functional:**
- Test is a single POSIX shell script in `tests/e2e/`.
- No reliance on Docker, sudo, or pre-installed services.
- Hardcoded ports overridable via env vars (`WAF_GATEWAY_PORT`, `WAF_HEALTH_PORT`).
- Reports pass/fail with a one-line summary and a non-zero exit code on any failure.

**Performance budget (provisional):**
- Time-to-ready under a release build on a developer laptop: **≤ 5 s** (informational).
- The contract doesn't specify the exact startup-timeout value; we measure and report. If a number is later disclosed, this script becomes the regression gate.

## Architecture

### Two-step harness

```
tests/e2e/s8-startup-contract.sh        ← orchestrator (this phase)
  ├─ Stage 1: copy ./waf and ./waf.toml into a tempdir
  ├─ Stage 2: spawn ./waf run, poll /health, time the ready transition
  ├─ Stage 3: issue one proxied request through the gateway
  ├─ Stage 4: stat ./waf_audit.log (skip-if-absent + log warning)
  └─ Stage 5: SIGTERM, wait, assert exit code
```

The tempdir-stage isolates the test from the developer's working tree: a CI run can leave artifacts in the tempdir without polluting `./waf_audit.log` at repo root.

### Health-endpoint selection

The contract says "the benchmarker polls the configured health endpoint". The benchmark won't know whether the WAF exposes `/health` on the proxy port (gateway plane) or the admin port. To match what a benchmarker is most likely to probe, **prefer the gateway-plane endpoint** (proxy.rs:607, port from `[proxy] listen_addr`). Admin endpoint at port 9527 is a fallback only.

**Probe sequence:** try gateway-plane `/health` first; if 5 s passes with no 200, also start polling admin-plane in parallel. First 200 wins. Log which plane answered.

### Proxied-request assertion

To trigger the audit log, send a benign request through the proxy. Since `./waf.toml` from Phase 3 inherits the upstream routing of `configs/default.toml`, the test needs to hit a route that resolves. Two options:
- (A) Use the `/health` endpoint on the gateway — but it's served by the proxy itself, no upstream involved, so it may not write an audit line.
- (B) Configure a deterministic test upstream in `./waf.toml` (e.g. a `nginx` running in the script). Too heavy.
- **(C, chosen):** Hit the proxy with `Host: nonexistent.test`. The proxy returns a no-route response, which IS a proxy decision → audit line emitted. No upstream needed.

If (C) doesn't generate an audit line (depends on parent-plan §6 implementation choice), fall back to **skip-with-warning** for the audit-log assertion. Phase 4 is not the gate for §6 work.

## Related Code Files

**Create:**
- `tests/e2e/s8-startup-contract.sh` — orchestrator harness (POSIX sh)

**Modify:**
- `.github/workflows/nightly-e2e.yml` — add a job that runs `scripts/release-waf-bundle.sh` then `tests/e2e/s8-startup-contract.sh`. Verify it runs against the renamed binary from Phase 1.

**Untouched:**
- Production code — pure validation phase. If the harness reveals a contract gap, log it; do NOT patch in this phase. File a follow-up.

## Implementation Steps

1. **Draft `tests/e2e/s8-startup-contract.sh`** with the five stages above. Skeleton:

   ```sh
   #!/bin/sh
   # §8 WAF Startup & Binary Contract — end-to-end validator.
   # Exit 0 only when every contract line is observed.
   set -eu

   ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
   GATEWAY_PORT="${WAF_GATEWAY_PORT:-80}"
   HEALTH_TIMEOUT_SECS="${WAF_HEALTH_TIMEOUT:-30}"

   [ -x "$ROOT/waf" ]      || { echo "FAIL: $ROOT/waf missing — run scripts/release-waf-bundle.sh"; exit 1; }
   [ -f "$ROOT/waf.toml" ] || { echo "FAIL: $ROOT/waf.toml missing"; exit 1; }

   STAGE="$(mktemp -d)"
   trap 'rm -rf "$STAGE"; [ -n "${WAF_PID:-}" ] && kill -TERM "$WAF_PID" 2>/dev/null || true' EXIT

   cp "$ROOT/waf" "$STAGE/waf"
   cp "$ROOT/waf.toml" "$STAGE/waf.toml"

   cd "$STAGE"
   ./waf run >waf.stdout 2>waf.stderr &
   WAF_PID=$!

   echo "Started PID=$WAF_PID; polling http://127.0.0.1:$GATEWAY_PORT/health (timeout ${HEALTH_TIMEOUT_SECS}s)"
   START_NS=$(date +%s%N)
   READY=0
   for _ in $(seq 1 "$((HEALTH_TIMEOUT_SECS * 4))"); do
       if curl -sf -o /dev/null "http://127.0.0.1:$GATEWAY_PORT/health"; then
           READY=1; break
       fi
       sleep 0.25
   done
   END_NS=$(date +%s%N)

   if [ "$READY" = "0" ]; then
       echo "FAIL: health did not return 200 within ${HEALTH_TIMEOUT_SECS}s"
       echo "--- stderr ---"; tail -50 waf.stderr
       exit 1
   fi
   ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
   echo "READY in ${ELAPSED_MS}ms"

   # Trigger an audited request through the proxy.
   curl -s -o /dev/null -H "Host: nonexistent.test" "http://127.0.0.1:$GATEWAY_PORT/" || true

   sleep 0.5
   if [ -f "$STAGE/waf_audit.log" ]; then
       LINES=$(wc -l < "$STAGE/waf_audit.log")
       echo "audit log: $LINES line(s)"
       [ "$LINES" -ge 1 ] || { echo "FAIL: waf_audit.log present but empty"; exit 1; }
   else
       echo "SKIP: waf_audit.log not present (parent-plan §6 likely not merged yet)"
   fi

   kill -TERM "$WAF_PID"
   SHUTDOWN_WAITED=0
   while kill -0 "$WAF_PID" 2>/dev/null; do
       SHUTDOWN_WAITED=$((SHUTDOWN_WAITED + 1))
       [ "$SHUTDOWN_WAITED" -ge 20 ] && { echo "FAIL: WAF did not exit within 5s of SIGTERM"; exit 1; }
       sleep 0.25
   done
   WAF_PID=""

   echo "PASS: §8 startup contract verified (ready in ${ELAPSED_MS}ms)"
   ```

2. **Run locally** from a clean repo:
   ```sh
   scripts/release-waf-bundle.sh
   tests/e2e/s8-startup-contract.sh
   ```
   Expected: `PASS` line; non-zero exit on any contract violation. Measure the typical ready-time; record in PR description.

3. **Handle port collisions.** Port 80 requires root on Linux. Either:
   - Document `WAF_GATEWAY_PORT=8080 tests/e2e/s8-startup-contract.sh` plus a one-line `sed` override of `./waf.toml`.
   - Or override the listen address inside the staged `./waf.toml` (Stage 1) before launch — preferred. Add an awk/sed override line in the script after `cp`.

   Implement the second approach. The override block at the bottom of `./waf.toml` already uses last-write-wins; the harness can append `[proxy] listen_addr = "127.0.0.1:18080"` to force a high port for the test, leaving the production override file alone.

4. **Wire the harness into CI.** Edit `.github/workflows/nightly-e2e.yml` — add a job (or a step in an existing job) that runs the release script then the harness. Use port `18080` to avoid root. Fail the job on non-zero exit.

5. **Document operator-facing instructions** in the existing top-level README (if it covers run-local instructions) — one paragraph showing:
   ```
   scripts/release-waf-bundle.sh
   tests/e2e/s8-startup-contract.sh
   ```
   Skip if README does not cover this surface; do not invent a new doc.

6. **shellcheck** the new script. Resolve warnings or `# shellcheck disable=` with rationale.

## Success Criteria

- [ ] `tests/e2e/s8-startup-contract.sh` exists and is executable
- [ ] Script passes shellcheck
- [ ] Local run after `scripts/release-waf-bundle.sh` exits 0
- [ ] Script reports time-to-ready in ms on success
- [ ] Script exits 1 with a diagnostic if `/health` does not return 200 within timeout
- [ ] Script exits 1 if WAF does not terminate within 5 s of SIGTERM
- [ ] Audit-log check is skip-with-warning when parent-plan §6 is unmerged (does NOT fail the harness)
- [ ] Nightly-e2e workflow runs the harness and gates the job on its exit code
- [ ] Time-to-ready measured and documented in PR description

## Risk Assessment

| Risk | Likelihood | Mitigation |
|---|---|---|
| Port 80 requires root in CI | High | Override listen_addr to `127.0.0.1:18080` inside the staged `./waf.toml` before launch |
| Cold-start time exceeds benchmark startup-timeout | Medium | Phase 4 measures and reports; if too slow, file follow-up — do NOT optimize in this plan |
| `curl` not installed on minimal CI image | Low | Add `curl` to the e2e job's image; standard Ubuntu runner has it |
| Health endpoint chosen does not match what the benchmark probes | Medium | Probe gateway plane first (most likely), fall back to admin plane after 5 s; log which answered |
| Audit-log file path differs from `./waf_audit.log` once parent-plan §6 lands | Medium | Skip-with-warning today; revisit when §6 ships and lock the path then |
| `Host: nonexistent.test` request doesn't generate an audit line (depends on §6 audit semantics) | Medium | Skip-with-warning; switch trigger to a different request shape when §6 lands |
| `kill -0` and `kill -TERM` semantics differ on macOS vs Linux | Low | Standard POSIX behavior; tested on both during development |

## Unresolved Questions

1. **Benchmark startup-timeout numeric value** — contract says "expires" without disclosing the limit. Without a number we measure but cannot fail-fast on slow cold-starts. Ask the harness team.
2. **Which `/health` does the benchmark probe — gateway plane or admin plane?** Ask the harness team. Until known, the harness probes both.
3. **Audit-log path** — locked to `./waf_audit.log` per contract, but parent-plan §6 may make it configurable. Confirm before merging this phase.
