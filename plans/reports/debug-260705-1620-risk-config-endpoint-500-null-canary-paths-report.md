# Debug: GET /api/risk/config "endpoint is not available"

## Executive Summary

Endpoint IS registered and reachable. It returns **500 Internal** because the shipped
`configs/risk.yaml` has `canary.paths:` as an explicit YAML `null` (all list items
commented out), and the API's JSON round-trip rejects `null` for `Vec<String>`.
The admin panel shows the misleading banner "GET /api/risk/config endpoint is not
available." on ANY query error, including this 500.

## Root Cause (empirically verified)

Chain:

1. `configs/risk.yaml:78` — `paths:` key present, every entry commented → YAML parses value as `null`.
2. `crates/waf-api/src/risk_api.rs:53-62` (`get_risk_config`) → `current_risk_node` reads file via
   `read_yaml_opt` into `serde_json::Value` → `canary.paths = null`.
3. `serde_json::from_value::<RiskConfig>(node)` fails: `#[serde(default)]` on
   `CanaryConfig.paths: Vec<String>` (`crates/waf-engine/src/risk/config.rs:271-272`) applies only to
   MISSING keys, not explicit `null`.
4. Handler maps to `ApiError::Internal` → HTTP 500.
5. FE `web/admin-panel/src/pages/risk-scoring/index.tsx:384-390` renders the "endpoint is not
   available" banner for any `configQuery.query.isError`.

Repro evidence (temporary test mirroring the API path, since deleted):

```
canary node = {"ban_ttl_secs":3600,"enabled":false,"paths":null}
panicked: API path: configs/risk.yaml must parse as RiskConfig:
Error("invalid type: null, expected a sequence", line: 0, column: 0)
```

Contrast: engine parser is fine — `cargo test -p waf-engine --test config_yaml_regression`
passes all 7 tests, incl. `risk_yaml_loads_through_engine_parser` (serde_yaml direct
deserialization tolerates the null; serde_json::from_value does not). Existing regression
test only covers the engine path, so the API-path divergence had no coverage.

## Blast Radius

- `GET /api/risk/config` → 500 (this issue).
- `PUT /api/risk/config` → also broken while file has `paths: null` (`current_risk_node` feeds
  the same node into the merge; `from_value` gate rejects it as "invalid risk config").
- Same null-vs-default hazard applies to any hand-edited YAML list left as `key:` with
  commented items, on any endpoint using the `read_yaml_opt` → `from_value` pattern
  (challenge/ddos/relay/device-fp/tx-velocity share `config_files.rs` helpers — not verified individually).

## Recommended Fix (not applied — awaiting go-ahead)

1. **Source fix (robust):** in `waf-api` risk read path, prune/normalize `null` values before
   `serde_json::from_value` (e.g. deep-strip nulls in `current_risk_node`), so API parsing matches
   engine serde_yaml tolerance. Fix at source, not just data.
2. **Data fix (immediate):** `configs/risk.yaml` → `paths: []` (or delete the key).
3. **Regression test:** add API-path round-trip test (YAML → `serde_json::Value` → `RiskConfig`)
   for shipped `configs/*.yaml`, alongside `config_yaml_regression.rs`.
4. **FE polish (optional):** banner conflates 404/401/500 as "not available"; surface actual status.

## Unresolved Questions

- Do the other YAML config endpoints (challenge, ddos, relay, device-fp, tx-velocity) have the
  same null-list hazard in their shipped configs? Not audited.
- Why serde_yaml's direct path accepts `null` for `Vec` while serde_json rejects it — behavior
  confirmed empirically, mechanism not chased.
