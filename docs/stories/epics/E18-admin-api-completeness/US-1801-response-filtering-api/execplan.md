# Exec Plan

## Goal

Make the admin panel's Response Filtering page work end to end: a working
preview endpoint and a working per-host GET/PUT API whose settings the proxy
actually honors.

## Scope

In scope:

- `POST /api/response-filtering/preview` (global panel-config, body-only).
- `GET`/`PUT /api/hosts/{id}/response-filter` + persistence under
  `defense_json.response_filter`.
- DB → `HostConfig` wiring for the five fields (boot loader + API CRUD).
- Shared `HostResponseFilter` DTO + `apply_response_filter` in `waf-common`.
- Unit + integration tests; live verification in Docker.

Out of scope:

- New redaction algorithms; per-route overrides; `defense_json` migration;
  per-host preview; Global-tab panel-config schema mismatch.

## Risk Classification

Risk flags: Data model (`defense_json`), Audit/security (response filtering is a
security control; PUT audited), Public contracts (3 new routes), Existing
behavior (response hot path via `HostConfig` mapping), Multi-domain
(`waf-common` + `waf-api` + `prx-waf` + `gateway`).

Hard gates: Audit/security, Data model → high-risk (confirmed by human).

## Work Phases

1. **waf-common**: add `HostResponseFilter` + `HostConfig::apply_response_filter`
   + `from_defense_json`. Unit tests (serde round-trip, defaults).
2. **Phase 1 — preview**: `preview_response_filter` in `security.rs` + route.
   Reuse gateway scanner + redactor over global panel-config. Unit tests.
3. **Phase 2 — GET**: `get_host_response_filter` in `handlers.rs` + route.
4. **Phase 3 — PUT**: `put_host_response_filter` — validate, persist, register,
   audit.
5. **Phase 4 — wiring**: map `defense_json.response_filter` onto `HostConfig` in
   `handlers.rs` (create/update) and `main.rs` boot loader. Gateway integration
   test proving the proxy applies a per-host override.
6. **Verify**: `cargo fmt`/`clippy`/`test` in Docker; rebuild `prx-waf`
   container; live-test all three endpoints with the provided admin credentials.

## Stop Conditions

Pause for human confirmation if:

- The preview mapping would change global config semantics.
- The `HostConfig` mapping would change behavior for hosts without a stored
  `response_filter` (must stay default-preserving).
- A migration turns out to be required after all.
