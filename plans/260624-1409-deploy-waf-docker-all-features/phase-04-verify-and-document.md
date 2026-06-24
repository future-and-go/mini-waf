---
phase: 4
title: "Verify and Document"
status: complete
effort: "S"
---

# Phase 4: Verify and Document

## Overview

End-to-end verification that the one-click path works and that every enabled feature is actually live, plus a short deploy doc. README already references a missing `docs/deployment-guide.md`; this phase adds a focused deploy section rather than reconstructing the full (missing) guide.

## Requirements

- Functional: prove the deployed stack enforces, not just runs.
- Non-functional: documentation matches reality (commands copy-paste runnable).

## Architecture

Verification matrix (run against the live stack):

| Check | Command | Expected |
|---|---|---|
| Health | `curl -ksf https://localhost:16827/health` | `status: healthy`; `database`/`waf_engine`/`cache` healthy |
| Cache backend = valkey | inspect `/health` component or `docker compose logs prx-waf \| grep -i valkey` | standalone Valkey connected, not memory fallback |
| HTTP/3 advertised | `curl -ksI --http3 https://localhost:16843/` (if curl has HTTP/3) or check `alt-svc` header | h3 offered / UDP 443 listening |
| Config loaded | `docker compose logs prx-waf \| grep full-features` | running `full-features.toml` |
| WAF blocks SQLi | `curl -s 'http://localhost:16880/?id=1%27%20OR%201=1--' -H 'Host: juice.local'` | 403 / block response |
| Benign passes | `curl -s http://localhost:16880/ -H 'Host: juice.local'` | proxied 200 |
| Event recorded | `curl -ksf https://localhost:16827/api/security-events` (after login) | SQLi block present |
| Outbound strip | response headers from proxied app | no `X-Powered-By` / server fingerprint leak |
| Audit sink | `docker compose exec prx-waf sh -c 'ls -la waf_audit.log'` | file exists, JSONL lines |

## Related Code Files

- Create: `DEPLOY.md` at repo root **or** add a "Docker one-click deploy (all features)" section to `README.md` (decide during impl; prefer extending README §Deployment since it already exists and references deploy docs). If a standalone file, keep it short and link from README.
- Read-only reference: `README.md`, plan phases 1-3 outputs

## Implementation Steps

1. Run `scripts/deploy.sh` on a clean tree; capture timing + final health output.
2. Walk the verification matrix; record actual vs expected. Any feature not provably live → fix the config (loop back to Phase 1) before claiming done.
3. Write the deploy doc: prerequisites, the single command, the access table, default-creds change warning, how to enable/disable individual features (point at `configs/full-features.toml`), and the excluded-features note (cluster/community/CrowdSec/ACME) with one-line "how to enable later" pointers.
4. Update `README.md` §Deployment with a row/line for the all-features one-click path.
5. Save a verification report under `plans/reports/` per the naming convention.

## Success Criteria

- [ ] Every row in the verification matrix passes (or has a documented, accepted caveat — e.g. GeoIP no-op without a DB file, HTTP/3 check skipped if local curl lacks h3).
- [ ] SQLi probe blocked AND visible in `/api/security-events`.
- [ ] Deploy doc is copy-paste runnable and lists how to toggle features + what's excluded.
- [ ] Verification report written to `plans/reports/`.

## Risk Assessment

- **Feature "enabled" in config but inert at runtime** (e.g. needs a host entry, or a missing rules file). Mitigate: the matrix tests behavior, not config presence.
- **Local `curl` lacks HTTP/3** → can't directly verify h3 client-side. Mitigate: verify UDP 443 listener + `alt-svc`, mark client h3 check as environment-limited.
- **Doc drift** if config keys change. Mitigate: doc points at the config file as source of truth rather than re-listing every key.
