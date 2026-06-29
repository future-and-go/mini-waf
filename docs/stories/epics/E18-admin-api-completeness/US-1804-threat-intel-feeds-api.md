# US-1804 Threat-Intel feeds API + runtime feed registry

## Status

implemented

## Lane

normal

Plan: `docs/review/admin-panel/plans/D3-threat-intel-feeds-api.md`.
Gap spec §D3 (G.1 row 17). Req IDs: FR-042, FR-008.

## Product Contract

The Settings → Threat-Intel feeds table must show real per-feed metadata
(name/source/entry-count/last-refresh/enabled) from a real backend endpoint,
not a table synthesized from `/api/rules/registry`, and drop the "no live API"
fallback.

## Acceptance Criteria

- `GET /api/threat-intel/feeds` returns a typed list of feed metadata loaded
  from `configs/relay.yaml` at startup; metadata only (never raw IP/ASN lists);
  empty/zero rows when feeds are unconfigured (not 500).
- The FE feeds table consumes the endpoint; no synthesis from `/api/rules/
  registry`; no "no live API available" fallback.

## Design Notes

- **Decision (recorded with the user):** the relay-intel subsystem was not
  instantiated anywhere on `main` (no `ProviderRegistry`, status endpoints were
  stubs, `relay.yaml` ships feeds disabled). Per the user's choice, a **runtime
  feed registry** was stood up — feeds are loaded into the engine at startup with
  real metadata — **without** wiring per-request relay *detection* into the
  gateway hot path (that FR-007 enforcement is a separate, deliberately-deferred
  follow-up to avoid hot-path risk).
- Engine: `relay::FeedMeta { name, source, entry_count, last_refresh_ms,
  enabled }` + `relay::load_feed_metadata(&RelayConfig)` (loads Tor/datacenter
  files, counts entries, mtime = last_refresh). `WafEngine` gains
  `relay_feeds: ArcSwap<Vec<FeedMeta>>`, `relay_feeds()`, and
  `load_relay_feeds(path)`; wired at startup in `main.rs`
  (`configs/relay.yaml`), fail-soft.
- API: `GET /api/threat-intel/feeds` (`stats.rs`) reads `engine.relay_feeds()`;
  `{ success, data: [...], total }`.
- UI: `web/admin-panel/src/pages/settings/index.tsx` feeds table now consumes
  the endpoint (columns name/source/entries/last-refresh/enabled); empty →
  "no feeds configured"; error → warning (no more "no live API").
- ASN mmdb entry count is not cheaply available → reported as 0 with source +
  mtime (documented).

## Validation

| Layer | Expected proof |
| --- | --- |
| Unit | `relay::load_feed_metadata` — empty config → 3 disabled zero-count feeds; signals.enabled flips `enabled`. |
| Integration | (live) endpoint returns the 3 feeds; non-zero count when a feed file is configured. |
| E2E | live Docker: feeds table renders real rows; configuring `tor.list_path` → tor count > 0 after restart. |
| Release | `cargo clippy -D warnings` + FE build clean. |

## Harness Delta

- Out of scope / follow-up: per-request relay **detection** enforcement in the
  gateway (FR-007 runtime); a manual "refresh feeds" endpoint (feeds currently
  load at startup); live periodic feed fetching (Tor/ASN over HTTP).

## Evidence

Verified 2026-06-29 (rebuilt `prx-waf` image).

- Unit: `relay::tests::load_feed_metadata_*` (2) pass; `cargo clippy -D warnings`
  clean.
- Startup log: `relay-intel: feed metadata loaded /app/configs/relay.yaml`.
- Live: `GET /api/threat-intel/feeds` → `{ data: [tor_exit, asn, datacenter],
  total: 3 }`, each `enabled:false, entry_count:0, source:"(not configured)"`
  — the real engine state for the shipped (feeds-disabled) `relay.yaml`. The
  loader's entry-counting is covered by the unit test (the bundled example Tor
  seed contains only comments, so a live non-zero demo wasn't meaningful).
- FE: `settings/index.tsx` feeds table consumes the endpoint; the synthesized
  `/api/rules/registry` table + "no live API available" fallback are removed
  (replaced with proper empty/error states). FE compiled (`tsc` + `vite build`).
