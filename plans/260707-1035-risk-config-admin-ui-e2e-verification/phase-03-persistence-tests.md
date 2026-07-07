---
phase: 3
title: "Persistence suite (all UI settings)"
status: complete
priority: P1
dependencies: [2]
---

# Phase 3: Persistence suite — all UI settings

## Overview
The always-achievable tier: for every UI-exposed setting, PUT a value via
`/api/risk/config`, GET it back, and confirm it landed in `risk.yaml`. Proves
the setting the UI controls actually persists through the real API path.

## Requirements
- Functional: each UI field round-trips (PUT → GET match → file contains value).
- Functional: invalid values rejected (invalid backend → 400; bad type → 400).
- Non-functional: evidence = observed GET body value + file grep logged into
  each assertion detail.

## Architecture
Build `run-risk-config.sh` skeleton here (sourced `lib.sh`, `e2e_init
"risk-config"`, auth against `:16827`, `e2e_finalize`). Add a local helper to
read a header value (`curl -D -` + grep) for later phases. Persistence tests use
`http_get` PUT/GET + a container-file read (via compose exec or the GET
round-trip as the file-of-record, since PUT writes the file it then re-reads).

UI settings covered (from `risk-scoring/index.tsx`):
- General: `enabled`, `ttl_secs`, `gc_interval_secs`
- Store: `backend`, `redis.url`, `redis.key_prefix`
- Decay: `min_clean_streak`, `decay_rate`, `max_decay`
- Canary: `enabled`, `ban_ttl_secs`, `paths`

## Related Code Files
- Create: `tests/e2e/run-risk-config.sh`
- Read: `crates/waf-api/src/risk_api.rs` (PUT merge/validate contract)
- Read: `tests/e2e/run-api.sh` (auth + assert patterns to mirror)

## Implementation Steps
1. Scaffold suite: health, login (reuse run-api.sh pattern), `AUTH` header.
2. For each setting: PUT `{section:{field:value}}`, GET, assert the returned
   value matches; log observed value as evidence.
3. `store.backend`, `redis.url`, `redis.key_prefix`: round-trip only; label
   detail "persistence-only (memory-only stack)".
4. `gc_interval_secs`: round-trip only; label detail "persistence-only (no
   black-box behavioral signal)".
5. Negative: PUT `store.backend:"postgres"` → assert HTTP 400; PUT
   `ttl_secs:"nan"` → assert 400.
6. Confirm PUT preserves unmanaged sections (GET still shows seed/ingest/
   challenge defaults) — guards the deep-merge contract.

## Success Criteria (TDD: round-trip assertions first)
- [ ] All 12 UI fields: PUT→GET match, observed value logged.
- [ ] Invalid backend and bad-type rejected with 400.
- [ ] Unmanaged sections survive a PUT (deep-merge intact).
- [ ] `gc_interval_secs` + store fields explicitly tagged persistence-only.

## Risk Assessment
- **File readback needs container access** — if compose exec is awkward, treat
  the GET response as the file-of-record (PUT writes then serializes the same
  data GET reads). Mitigation: GET round-trip is sufficient proof of persistence.
- **Array replace semantics** — `canary.paths` replaces wholesale (verified in
  risk_api tests). Assert the exact new array, not a merge.
