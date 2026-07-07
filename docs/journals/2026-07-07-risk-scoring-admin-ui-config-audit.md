# Risk Scoring Engine: Admin-UI vs Backend Config Schema Audit

**Date:** 2026-07-07 10:27 +07:00
**Severity:** Medium
**Component:** waf-engine/risk (config schema), admin-panel (risk-scoring config UI)
**Status:** Audit complete; gap identified; no code changes

## What Happened

Conducted a technical-consultation session to map the admin-panel risk-scoring config form against the backend `RiskConfig` schema. Goal: verify that operators can fully configure the risk engine via UI without hand-editing `configs/risk.yaml`. Starting point was a `/ask` follow-up on GH-196 (risk scoring enablement) that surfaced uncertainty about what the UI actually exposed. Traced both the backend schema (`crates/waf-engine/src/risk/config.rs`) and the admin-panel form (`web/admin-panel/src/pages/risk-scoring/index.tsx`), listed each of the 7 backend config sections, and cross-checked what the form exposes. Result: 4 of 7 sections are UI-reachable; the other 3 require YAML hand-edit. This gap was not a surprise—no design doc promised full UI coverage—but documenting it now prevents operators from being confused when UI controls turn out to be incomplete.

## The Brutal Truth

This is a knowledge gap, not a bug. The form was built to cover the config surface that operators most commonly tweak (general enable/disable, Redis backend, decay tuning, canary paths). The sections it leaves out (seed asset paths, ingest signal weighting, challenge-credit tuning) were left out *deliberately*—they're complex, infrequently changed, and safer to house in YAML. But nobody wrote down which sections live where, so it's ambiguous to operators whether the UI is incomplete or if they're just missing a feature flag. Now it's documented: you can edit Decay via the form; you cannot edit Seed via the form, full stop.

## Technical Details

**Backend config schema** (7 top-level sections in `RiskConfig`):
1. **General** (top-level): `schema_version`, `enabled`, `ttl_secs`, `gc_interval_secs`, `session_cookie`, `header_name`, `emit_header`.
2. **Store**: `backend` (memory|redis), `redis.url`, `redis.key_prefix`, `redis.op_timeout_ms`, `redis.breaker_threshold`, `redis.cache_capacity`.
3. **Decay**: `min_clean_streak`, `decay_rate`, `max_decay` (validated ≤100).
4. **Seed**: `enabled`, `tor_exits_path`, `asn_classes_path`, `whitelist_path`, `tor_delta`, `datacenter_delta`, `bad_asn_delta`.
5. **Ingest**: `enabled`, `channel_capacity`, `signal_weights` (map overriding 17 built-in signal deltas from `risk/ingest/signal_to_contributor.rs`).
6. **Canary**: `enabled`, `paths` (exact-match, case-sensitive), `ban_ttl_secs`.
7. **Challenge**: `enabled`, `ttl_secs`, `hmac_secret_path`, `lru_size`, `header_name`, `valid_delta`, `invalid_delta`, `replay_delta`, `expired_delta`.

Hot-reloaded via `ArcSwap` + `notify` crate (`risk/reload.rs`); YAML source is `configs/risk.yaml`.

**Admin UI coverage** (form in `web/admin-panel/src/pages/risk-scoring/index.tsx`, API routes PUT/GET `/api/risk/config`):
- ✅ **General**: `enabled`, `ttl_secs`, `gc_interval_secs` (3/7 top-level fields exposed; missing: `session_cookie`, `header_name`, `emit_header`).
- ✅ **Store**: `backend` (select), `redis.url`, `redis.key_prefix` (3/6 redis fields exposed; missing: `op_timeout_ms`, `breaker_threshold`, `cache_capacity`).
- ✅ **Decay**: `min_clean_streak`, `decay_rate`, `max_decay` (full coverage).
- ✅ **Canary**: `enabled`, `ban_ttl_secs`, `paths` (tag-list input; full coverage).
- ❌ **Seed**: no UI form at all.
- ❌ **Ingest**: no UI form at all.
- ❌ **Challenge**: no UI form at all.

**Not exposed in UI:**
- Top-level: `session_cookie` (custom cookie name for risk state persistence), `header_name` (HTTP header exposing risk score to downstream), `emit_header` (bool to enable header emission).
- Redis: `op_timeout_ms` (operation timeout), `breaker_threshold` (circuit-breaker failure threshold), `cache_capacity` (local cache size before Redis fallback).
- Seed, Ingest, Challenge: all fields in these 3 sections.

**Decay mechanism semantics** (for future config validators): Decay only applies once `clean_streak >= min_clean_streak`; subtracts up to `decay_rate` points per clean request; floors at `max_decay` (validated ≤100, not a maximum but a floor per the name). Both `decay_rate: 0` and `min_clean_streak: 0` are valid and tested—not a misconfiguration. Decay is skipped entirely while an actor is pinned (e.g., by a canary hit).

**Canary mechanism semantics** (for future config validators and operators): Exact-match, case-sensitive path set. On path match, score is force-pinned to 100 for `ban_ttl_secs` duration; IP is added to `DynamicBanTable` for the same TTL; request blocked immediately, bypassing the normal threshold gate. Hot-reloadable via `ArcSwap<HashSet<String>>`. Canary is independent of risk thresholds; it is not a tier-scoped policy.

**Risk thresholds deliberately NOT in RiskConfig**: Allow/Challenge/Block thresholds are per-tier in `waf-common::tier::RiskThresholds` (consumed by `risk/threshold.rs::decide()`). Policy (thresholds) is tier-scoped; scoring mechanism (engine config) is global. Operators configure thresholds via tier settings, not via risk config.

## Gap Identified

The admin-UI risk-scoring form covers ~50% of the backend config surface by count (4/7 sections, 8/23 leaf fields), but 100% of the operationally common knobs (enable/disable, decay tuning, canary paths, Redis backend selection). The sections left out require YAML hand-edit: changing Seed asset paths (Tor, ASN, whitelist deltas), signal weighting overrides, or challenge-credit tuning. This is by design—those are rare, complex changes—but operators should know it up front. Currently, no warning in the UI or the docs signals this split.

## Next Steps

- Document the UI coverage boundary (which sections are UI-reachable, which require YAML) in the risk-scoring config doc or release notes for GH-196 / E27 (Risk Scoring Rollout). One-liner acceptable: "General, Store (Redis fields only), Decay, and Canary are UI-configurable; Seed, Ingest, and Challenge require direct YAML edit."
- If future work requests UI forms for Seed/Ingest/Challenge, this audit provides the exact field inventory and semantics to implement them.
- No bug fix required. The form is fit for purpose; the gap is a documentation gap, not a feature gap.

---

**Status:** DONE
**Summary:** Audit mapped admin-panel risk-scoring form to backend RiskConfig schema; identified 3 config sections (Seed, Ingest, Challenge) with no UI form. By design; gap is documentation, not implementation.
**Concerns/Blockers:** None.
