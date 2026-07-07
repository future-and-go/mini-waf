# Phase 1 Spike Findings — score-raise mechanism + stack wiring

**Date:** 2026-07-07
**Verdict: GO for full behavioral coverage.** No degradation to persistence-only.
Device-fp/ingest is NOT required — the anomaly XFF accumulator + canary cover
every observable setting.

## Critical prerequisite discovered

The prebuilt `target/release/waf` was **stale (2026-06-30)**; the risk engine
changed 2026-07-06 (`87ca279`). The stale binary silently failed to load
`risk.yaml` (no log, canary never fired). **A fresh `cargo build --release -p
prx-waf` is mandatory before the image build.** With the fresh binary the risk
subsystem logs `risk: initial config loaded` and all wiring works.

## Stack wiring (confirmed)

- Main config `risk-e2e.toml` mounted at `/app/risk-e2e.toml`; engine + admin API
  both resolve `configs/risk.yaml` → **`/configs/risk.yaml`** (two levels up).
- `/configs` must be a **directory** bind mount, not a single-file mount: the
  admin API persists via tmp-write-then-rename, which EBUSY-fails over a file
  mount. Mounted `./out/risk-config/cfg:/configs`.
- Tier thresholds via `[tiered_protection] config_path = "/app/tier-risk-e2e.toml"`
  (absolute path; resolved as a literal PathBuf). Low thresholds
  `allow=10 / challenge=30 / block=60` on all tiers.
- Enforcement is **Enforce by default**: `apply_mode` only *downgrades* to
  LogOnly when a mode registry says so or the host is log-only. With neither,
  risk block/challenge is enforced. Confirmed `X-WAF-Mode: enforce`.
- Distinct host ports **26880** (proxy) / **26827** (admin) via `ports: !override`
  so the risk stack coexists with a running dev stack on 16880/16827.
- Container runs as **root** → files it writes into `/configs` are root-owned;
  the run script reset must tolerate a root-owned leftover (busybox fallback).
- glibc: host binary needs ≥2.39; base image overridden to `debian:trixie-slim`
  (mirrors `docker-compose.deploy.yml`).

## Score-raise mechanism (the spike's core question)

**Chosen: crafted `X-Forwarded-For` anomaly (unpinned, accumulates, decays).**

Request header (3 XFF violations: private-after-public + chain>5 + duplicate →
capped **+10** per request, `ContributorKind::Anomaly`):

```
X-Forwarded-For: 8.8.8.8, 10.0.0.1, 1.1.1.1, 2.2.2.2, 3.3.3.3, 8.8.8.8
```

Observed against the live stack (`GET /get`, Host: localhost):

- Accumulation: 6 crafted requests → score `10,20,30,40,50,60` (linear +10).
- Decay (`min_clean_streak=2, decay_rate=5, max_decay=0`): clean requests held
  at 60 for 2 requests, then `55,50,45,40` (−5/clean req toward floor 0).
- Actor id (client IP as seen by WAF) = **`172.19.0.1`** (docker bridge gateway)
  — used for `/api/risk/actors/<ip>/credit|clear`.

Why not the alternatives:
- **Canary** pins score to 100 **and bans the IP** → unusable for ttl/decay/credit
  (kept for the `enabled`/canary behavioral group only). `/canary/trap` → 403,
  score 100, `X-WAF-Action: block`.
- **Seed layer** re-applies every request (no decay/expiry) and needs ASN/tor
  files + a classifiable client IP → unusable.
- **device-fp signals** (ua_blocklist etc.) need the device-fp capture pipeline
  active (not wired in e2e). Not needed given the anomaly path works.

## Verified behavioral hooks for phase 4

| Setting | Mechanism | Evidence |
|---|---|---|
| `enabled` on/off | PUT enabled + crafted XFF | on→score climbs; off→score 0 |
| canary `paths`/`enabled`/`ban_ttl_secs` | hit `/canary/trap` | 403 + score 100 + ban; ttl expiry |
| `ttl_secs` | raise, idle > ttl (gc 2s) | score drops to 0 after purge (boot value; ttl is boot-only, see run-results finding) |
| `decay` (`min_clean_streak`/`decay_rate`/`max_decay`) | raise, clean reqs | step-down sequence; rate 0 → constant |
| `credit`/`clear` | raise, POST credit/clear | 30→credit −25→5; clear→removed:true |

## Hot-reload

PUT `/api/risk/config` (deep-merge) → file rewritten → notify watcher reloads
(~2s debounce) → next request reflects new behavior. Confirmed with an
`enabled` toggle.

## Unresolved questions

None blocking. Note: `store` fields + `gc_interval_secs` stay persistence-only
(memory-only stack, no black-box signal) as planned; metrics/actors endpoints
are stubs and excluded.
