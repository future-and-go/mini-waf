---
phase: 3
title: "Risk config PUT/GET serde round-trip"
status: completed
priority: P1
dependencies: []
---

# Phase 3: Risk config PUT/GET serde round-trip

## Overview

Replace the hand-mapped `yaml_to_fe` / `fe_to_yaml` / `default_risk_fe` trio in
`crates/waf-api/src/risk_api.rs:60-132` with serde round-trips through
`waf_engine::risk::config::RiskConfig`, so a UI save can never silently drop
`session_cookie`, `ingest.signal_weights`, `challenge`, or seed file paths.

## Requirements

- Functional: GET returns the full serialized `RiskConfig`; PUT accepts a full
  config, validates it parses as `RiskConfig`, and writes
  `{ risk: <serialized config> }` to `configs/risk.yaml`.
- Contract: FE field names stay identical for the fields the FE already edits
  (`enabled`, `ttl_secs`, `gc_interval_secs`, `header_name`, `emit_header`,
  `store`, `decay`, `seed.*`, `canary`) — RiskConfig serde names already match;
  verify against `webui` usage before deleting the mappers.
- Partial-body safety: fields absent from the PUT body take `RiskConfig` serde
  defaults, NOT silent deletion of operator-set values. To preserve operator
  values the FE never sends, deep-merge the incoming JSON over the current
  file's `risk:` node **before** deserializing to `RiskConfig` for validation.

## Architecture

```text
PUT body (JSON) ──deep-merge over──> current risk.yaml `risk:` node (as Value)
                └──> serde_yaml::from_value::<RiskConfig>()  // validation gate
                └──> write_yaml({ "risk": merged })          // atomic tmp+rename
GET: read risk.yaml → risk node → from_value::<RiskConfig>() → Json(serialize)
     (missing file → RiskConfig::default())
```

## Related Code Files

- Modify: `crates/waf-api/src/risk_api.rs` (delete 3 mapper fns, rewrite GET/PUT)
- Read-only: `crates/waf-engine/src/risk/config.rs` (serde shape is authoritative)
- Check: webui risk settings page for field-name coupling before merge

## Implementation Steps

1. Add deep-merge helper (JSON object merge, arrays replaced not merged) or
   reuse one if any waf-api module already has it.
2. Rewrite `get_risk_config` / `put_risk_config` per architecture; delete
   `yaml_to_fe`, `fe_to_yaml`, `default_risk_fe`.
3. Reject unparseable merged config with 400 + serde error message (no write).
4. Round-trip test: full `RiskConfig` with non-default `challenge`,
   `session_cookie`, `ingest.signal_weights`, seed paths → GET → PUT body from
   GET → file reparsed as `RiskConfig` equals original.

## Success Criteria

- [ ] Acceptance test: load → PUT → reload → same config (issue AC #4).
- [ ] PUT with unknown/invalid values returns 400 and leaves the file untouched.
- [ ] Grep confirms `fe_to_yaml`/`yaml_to_fe`/`default_risk_fe` deleted.

## Risk Assessment

- `RiskConfig` serde must be a faithful round-trip (GH-198 fixed the store-side
  cases). If any field uses `skip_serializing`, round-trip test will catch it.
- FE contract drift: if webui reads a field name that differs from RiskConfig
  serde, fix the FE mapping in the same change (grep webui for `risk` API usage).
- Overlap: GH-207 item 2 asks for exactly this dedupe — this phase implements
  it; GH-207's plan references it as done.
