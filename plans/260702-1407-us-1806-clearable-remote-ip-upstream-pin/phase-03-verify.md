---
phase: 3
title: "Verify"
status: pending
effort: "S"
---

# Phase 3: Verify

## Overview

Prove all acceptance criteria across build, API contract, and live routing.

## Implementation Steps

1. **FE build/typecheck** (in `web/admin-panel`):
   ```bash
   npm run build   # or: npm run lint && npx tsc --noEmit
   ```
   Expect no `remote_ip` type errors; dialog renders the new field.

2. **API contract** — assert `GET /api/hosts` already includes `remote_ip`
   (should be true pre-change; confirms AC without code change):
   ```bash
   curl -s <admin-api>/api/hosts | jq '.data[0] | has("remote_ip")'   # → true
   ```

3. **Backend test** (phase 2):
   ```bash
   cargo test -p waf-storage --test repo_hosts
   ```

4. **Live routing (E2E, manual)** on a host with an active pin shadowing the
   hostname:
   - Open Edit Host → confirm the "Upstream IP (pin)" field shows the current pin
     (visibility AC).
   - Clear the field, Save. Send a request through the proxy → traffic reaches
     `remote_host` (no restart, no SQL). AC: clear takes effect.
   - Set the pin to a new IP, Save. Next request dials the new IP. AC: set/change
     takes effect.
   - Network tab: cleared save body contains `"remote_ip": ""` (guards the
     undefined-vs-empty risk from phase 1).

5. **Record proof status** when `harness-cli` is available:
   ```bash
   scripts/bin/harness-cli story update --id US-1806 \
     --unit 1 --integration 1 --e2e 1 --platform 0
   ```
   (Binary absent in this checkout per story — record when built; otherwise note
   proof status in the PR.)

## Success Criteria

- [ ] FE build/typecheck passes.
- [ ] `GET /api/hosts` returns `remote_ip`.
- [ ] `repo_hosts` test passes (or clean-skipped if no Docker, noted honestly).
- [ ] Manual E2E: clearing pin routes to hostname; setting pin dials new IP; pin
  visible on edit; cleared body sends `""`.
- [ ] No migration added; routes unchanged (`git diff` confirms).

## Risk Assessment

- **Config hot-reload:** AC requires "no restart". Confirm the host config
  watcher picks up the DB change on the next request (existing behavior for other
  host fields via `arc-swap`/`notify`); if routing does not update without
  restart, that is a separate reload bug, not this fix — flag it, do not
  widen scope here.
