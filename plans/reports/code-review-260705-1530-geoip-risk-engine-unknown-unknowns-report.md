# GeoIP + Risk-Scoring Engine — Cross-Layer Review & Unknown Unknowns

**Date:** 2026-07-05 15:30 · **Branch:** main-harness · **Mode:** codebase (advisory, no files changed)
**Scope:** geoip + risk score engine across `web/admin-panel`, `waf-api`, `waf-engine`, `migrations/`
**Method:** 4 parallel `code-reviewer` subagents (one per layer), every load-bearing claim re-verified by controller against source + live upstream data. Reviewer claims that failed verification are marked REFUTED.

---

## TL;DR

The plumbing landed over the last week (GH-195..208) is mostly solid — auth is correct, YAML writes are atomic, SSRF fetch hardening is real, Redis roundtrip fixed. But the **feature is largely inert or misleading in its default shipped state**, and that gap is invisible because the tests wire things by hand that production never wires.

Three things you almost certainly believe are working but are not:
1. **Seed scoring (Tor/datacenter/bad-ASN) and challenge-credit are dead in the live engine** — configured, tested, documented, never attached to the production scorer.
2. **The "Add credit" button in the risk UI returns HTTP 400 on every click** — sign convention disagrees across 4 layers.
3. **Risk metrics + actor list in the UI are hardcoded zeros/empty** rendered as if real — you're flying blind while the credit/clear buttons mutate live state by IP.

One reviewer CRITICAL was **refuted**: the geoip region-string parser is correct for the actual upstream data (see Refuted section) — don't spend time "fixing" it.

---

## Severity-ranked findings (verified, cross-layer)

### CRITICAL

**C1 — Seed(L0) + challenge-credit layers never wired into the production scorer.** `engine.rs::build_scorer` (`crates/waf-engine/src/engine.rs:379-383`) calls only `set_canary`. `set_seed` / `set_challenge_verifier` exist but are invoked **only in tests** (grep-confirmed). At `scorer.rs:129` the seed branch is `match (&self.seed, cfg.seed.enabled)` — `self.seed` is always `None` in prod, so it yields `SeedVerdict::None` **regardless of `seed.enabled: true` in `configs/risk.yaml`**. Effect: Tor-exit (+30), datacenter (+15), bad-ASN (+25) deltas never fire; the whitelist short-circuit never runs; challenge tokens are never verified. Two configured security features silently do nothing. Tests pass because they call `set_seed` by hand.

**C2 — UI "Add credit" is 100% broken (every click → HTTP 400).** Buttons send `[-50,-25,-10]` (`web/admin-panel/src/pages/risk-scoring/index.tsx:680`); API rejects anything outside `1..=100` (`crates/waf-api/src/risk_api.rs:125`); engine ignores sign anyway with `-amount.abs()` (`engine.rs:451`). Sign convention contradicts itself across UI buttons, the i18n hint ("positive decreases, negative increases", `en.json:922`), the API gate, and the engine. Fix is small but touches all four.

### HIGH

**H1 — Fingerprint axis + rule-match deltas discarded on the enforcement path.** The engine calls `scorer.score(ctx, None, &[], None, now_ms)` (`engine.rs:881`) — `fp_key=None`, `sync_deltas=&[]`. Device-fp risk written by the ingest worker on the fp axis is **never read** at enforcement (IP/session only), and rule-match `RiskDelta`s never contribute to cumulative score. The `score_with_l2` fold machinery is dead in the engine path.

**H2 — Velocity + sequence stores grow unbounded; purge never scheduled.** `VelocityLayer::purge_idle` is called only from tests (grep-confirmed; no loop in engine/main). Keyed on full `RiskKey`, so cookie/IPv6 spray both evades the per-minute window (fresh window per key) and grows the `DashMap` without bound → memory-exhaustion DoS. Same for the session/fp index in `MemoryRiskStore` (keyed on attacker-controlled bytes, GC caps at 1000/axis/tick). The risk store has a purge loop; velocity does not.

**H3 — `store.backend` change via API PUT silently no-ops until restart.** `put_risk_config` returns `success:true` (`risk_api.rs:64`); the reload closure only logs a warning and keeps the active store (`engine.rs:413-419`). Admin switches memory→redis in the panel for durable/clustered risk, gets 200 OK, but scores still vanish on restart and aren't shared across nodes — directly undercutting the GH-198 Redis work. Also: startup falls back memory→redis on a 5s connect timeout with no retry, so a transient Redis blip at boot silently downgrades to per-instance memory.

**H4 — geo rule `action` unvalidated; any non-`"allow"` value becomes a BLOCK.** `create_geo_rule` accepts an arbitrary `action` string (`geo_api.rs:65`); `parse_geo_rules` treats everything except exact `"allow"` as `Block` (`checks/geo_config.rs:77-84`). The UI offers `challenge` and `log` options (`geo-shared.ts:7`, `rules-tab.tsx:86,226`) that the engine has no geo equivalent for — pick "challenge" for a country and it **silently hard-blocks** it, while the API echoes `action:"challenge"` back as if honored.

**H5 — Risk actor list + metrics are permanent stubs while credit/clear mutate real state.** `list_risk_actors` returns `[]`, `get_risk_metrics` returns hardcoded zeros, both `success:true` (`risk_api.rs:78-103`) — the doc comment even warns FE to treat `[]` as "no data, not no risky actors," and the UI does exactly the wrong thing (shows "no risky actors" + zero KPIs as healthy). Meanwhile `credit`/`clear` operate on the live store by IP. Operator can mutate actors they cannot see.

**H6 — Panel-config risk thresholds are orphaned from enforcement.** The dashboard risk-band preview is fed from `WafPanelConfig.risk_allow/challenge/block` (`dashboard/index.tsx:512`, defaults 51/74/75), but **nothing in `gateway/` or `waf-engine/` reads those fields** — enforcement uses `TierPolicy.risk_thresholds` (tier default 30/70/90; registry 10/50). Editing these values in the UI has zero effect on the WAF. Additionally the preview renders a 4-band model and labels the middle band "Block," but `threshold::decide` (`risk/threshold.rs:17-39`) uses only allow+block — scores in that band are *challenged*, not blocked. The UI misrepresents actual enforcement.

**H7 — Redis vs memory backends have genuinely different semantics, not just perf.** `MemoryRiskStore::apply` is check-then-insert (TOCTOU: concurrent first-requests across axes can split-brain the index and drop a delta batch); Redis is atomic Lua. `reset_all` is swap-with-empty on memory but incremental SCAN+DEL on Redis (`store_trait.rs:69-74` mandates atomic; Redis violates it). Redis also assumes a single instance — Lua computes state keys not declared in `KEYS`, so a Redis Cluster returns `CROSSSLOT` on every apply → permanent degraded mode. A green memory test suite does not prove Redis behavior.

### MEDIUM

- **M1 — Decay/TTL config silently non-hot-reloadable.** Store built once; reload swaps only the cfg snapshot + canary. `ttl_secs`, `decay_rate`, `max_decay`, `min_clean_streak` edits to `risk.yaml` are accepted with no error and do nothing (`engine.rs::start_risk_watcher`).
- **M2 — geoip auto-updater writes hardcoded filenames.** `ip2region_v4.xdb`/`ip2region_v6.xdb` under `data_dir` = parent of `ipv4_xdb_path` only (`main.rs:1687`, `geoip_updater.rs:87,145`). Default paths match, so **default config works**; but custom filenames or split v4/v6 dirs → updater writes files the service never loads, and `reload()` re-reads unchanged configured paths = silent no-op forever. (Reviewer rated HIGH; downgraded — default is safe.)
- **M3 — Partial download freezes the other family.** `download()` fetches v4, renames to disk, *then* v6; a persistently-failing v6 URL (`?` propagates) means `reload()` never runs, so fresh v4 bytes on disk are never loaded into memory (`geoip_updater.rs:145-176`). Warn-only.
- **M4 — `get_geo_stats` runs 4 unbounded full-table GROUP BY on `security_events` per call**, no time window (`stats.rs` / repo agg). Grows linearly forever; the 0008 expression indexes won't help a full-table hashaggregate.
- **M5 — geo YAML CRUD is read-modify-write with no lock.** Concurrent POST/PATCH/DELETE race on `next_id = max+1` (`geo_api.rs:33`); atomic rename protects the *reader*, not concurrent *writers* → id collision / last-write clobber.
- **M6 — `risk` i18n namespace missing from `vi.json` + zh.json** (0 `risk.*` keys; geo IS translated) → raw keys shown across the whole Risk page for VN/CN. (`en.json` complete.)
- **M7 — Nonce store evicts by capacity, not TTL** — if >`lru_size` (100k) nonces are consumed within a token TTL, the oldest is evictable and a valid token replays. Moot today (challenge unwired, C1) but a latent trap once wired.

### LOW / cosmetic
- geo `fail_closed` accepted+persisted on Block rows but hardcoded `false` by engine (`geo_config.rs:97`) — contract mismatch, meaningful only on allow rows.
- `lookup_ip` returns `iso_code:"XX"` for both "GeoIP disabled" and "IP genuinely not in DB" (`geo_api.rs:139`); UI "Block this country" then persists a junk `XX` rule.
- geo per-family reload isn't atomic across families (brief new-v4 + old-v6). Benign.
- Canary match is exact/case-sensitive `HashSet` lookup — trivial evasion via trailing slash/case (may be intentional honeypot behavior).
- Default divergence: FE `riskAllow ?? 50` vs backend `default_risk_allow() == 51`.
- `store.backend: "redis"` selectable in UI even without the `redis-store` build feature; PUT validates parse only, not availability.

---

## REFUTED (do not act on)

**GeoIP reviewer's CRITICAL "region-string parser mismatch" — FALSE for the configured data source.** The reviewer assumed the old ip2region 2.0 region format (`国家|区域|省份|城市|ISP`, no ISO, all Chinese). I fetched the actual upstream (`raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ipv4_source.txt`): rows are `start|end|Country|Province|City|ISP|ISO`, e.g. `Australia|Queensland|0|0|AU` and `中国|福建省|福州市|中国电信|CN`. The compiled xdb region string is exactly `Country|Province|City|ISP|ISO` — **precisely what `parse_region` (`geoip.rs:195`, `splitn(5)`) expects.** ISO codes parse correctly, so iso-code block/allow rules **do** match. The only real residue is cosmetic: `country_name` is localized (Chinese for CN rows, English elsewhere) — LOW, since matching keys on `iso_code`, not country name. Upstream URLs (v4 + v6) also both return HTTP 200 with stable `Content-Length` and `accept-ranges` — the "hardcoded path 404" concern (#6) is not currently real.

---

## Unknown unknowns — explained

Ranked by how much the shipped behavior diverges from what the config/docs/UI imply.

1. **Risk scoring ships `enabled: false`; even flipped on, the seed/challenge/fp/rule-delta halves stay dark.** `configs/risk.yaml` top-level `enabled: false`, but `seed.enabled: true` inside it. So you flip the master switch, reasonably expect Tor/ASN/datacenter scoring to be live (the sub-config says enabled), and get only canary + anomaly + velocity — the seed layer is `None` at the object level (C1). *Why it matters:* the config is actively misleading. *Where:* `scorer.rs:119,129`; `engine.rs:379`.

2. **Geo classification, risk keying, rate limits, and bans are all spoofable when `trust_proxy_headers=true` — and the code takes the LEFTMOST XFF token.** `resolve_client_ip` (`gateway/src/ctx_builder/request_ctx_builder.rs:239-249`): empty `trusted_proxies` = trust every peer, and it reads `xff.split(',').next()` — the leftmost value, which is client-controlled even behind a legitimate proxy (proxies *append*). An attacker sets `X-Forwarded-For: <anything>` to pick their geo country, shed accumulated risk by rotating identity, or frame another IP for a ban. Default is off, and issue #74 mentions XFF cleanup — but the leftmost-token choice is a genuine landmine. *Where:* `request_ctx_builder.rs:239-249`.

3. **Geo stats/map is a distribution of *detections*, not visitors, and is silently empty without an xdb.** `geo_info` is written only on attack-log/security-event paths and only when the GeoIP service is loaded (`engine.rs:945-947,1287`). No xdb → `geo_info` NULL → blank map, zero errors anywhere. And even fully loaded, the "country distribution" counts blocked/flagged traffic, not all traffic. *Why it matters:* looks broken/wrong in prod with no diagnostic. 

4. **The 0008 `attack_logs.geo_info` column + `idx_attack_logs_geo_country` index are dead.** The only geo aggregation queries `security_events`, not `attack_logs` (`stats.rs`). All three 0008 expression indexes target `WHERE geo_info->>'country'=?` lookups that don't exist in the codebase. *Where:* `migrations/0008_add_geo_info_to_attack_logs.sql`.

5. **Nothing risk-related persists to Postgres.** Risk config lives in `configs/risk.yaml`; risk actor state lives in memory (lost on restart) or Redis. There is no risk DDL. Memory backend + the credit/clear admin ops = mutations that evaporate on the next deploy. *Why it matters:* operators expect DB-backed durability by analogy with the rest of the system.

6. **Tier classifier ships with `classifier_rules: []`, so every request is `catch_all` (fail_mode: open).** The registry *is* wired now (`main.rs:1445` — issue #169 is stale), but with no classifier rules every request lands in `catch_all`, whose `fail_mode: open`. Net: the GH-201 Redis fail-*closed* work is inert under the default config — a Redis outage always fails open until an operator writes classifier rules. *Where:* `configs/tier-policies.yaml:1`.

7. **Redis `force_max`/`clear` return `Err` (not degraded-fallback) on failure, unlike `apply`.** A canary pin during a Redis blip surfaces only as a `tracing::warn`; the Block still returns for that request, but the pin is **not persisted** — the actor is un-pinned on the next request. Asymmetric failure semantics inside one store. *Where:* `scorer.rs` canary branch, `redis.rs`.

8. **`build_risk_store` swallows a startup Redis outage into a silent memory downgrade with no ongoing retry** (5s connect bound). Combined with H3, an operator can believe redis is authoritative while every score/credit lands in per-instance memory.

9. **Docs drift:** `CLAUDE.md`/README claim "ip2region + MaxMind" but the subsystem is ip2region-only (`maxminddb` unused here). Fail-closed exists only on AllowOnly geo rules by design — a "block CN" rule does *nothing* when geo is unavailable (fail-open), which is a non-obvious security gap even though it's intended.

---

## How to prompt me better for the implementation

You asked how to get better results when you hand me the fix work. Concrete, based on what went wrong in *this* codebase:

1. **Name the wiring seam, not just the feature.** The recurring defect class here is "unit exists + tested, integration absent" (C1, H1, H6). Prompts like *"add seed scoring"* got you tested-but-unwired code. Instead: *"wire SeedLayer into the production scorer via build_scorer, and add an engine-level test that a Tor-exit IP actually accrues +30 through `engine.inspect()` — not through a hand-constructed Scorer."* Force the test to exercise the real entry point.

2. **Demand an end-to-end assertion through the public entry point, and say which fake to ban.** Every one of these shipped green because tests called `set_seed`/`score(...)` directly. Tell me: *"the test must drive `WafEngine::inspect()` (or the HTTP handler), and must fail if I wire it by hand."* The GH-200 journal shows the gold standard — they git-stashed the fix and proved the test fails without it. Ask me to do that.

3. **State the cross-layer contract explicitly when a value crosses a boundary.** C2 (credit sign) and H4 (geo action) and H6 (thresholds) are all "layer A and layer B disagree on the same field." When you ask for a field, give me the contract: *"credit amount: UI sends positive magnitude 1..100, API validates 1..100, engine decreases score. Reconcile the i18n hint too."* Don't let me infer the sign convention.

4. **Tell me the default-config posture you want, separately from the code.** Much of this is inert because of shipped defaults (risk `enabled:false`, empty `classifier_rules`, seed sub-enabled). If you want a fix *active in prod*, say *"and update `configs/*.yaml` so this is actually reachable in the default deployment, and add a smoke test that boots with the default config."* Otherwise I'll fix the code and leave the config dark.

5. **Separate "persist" from "enforce" in the ask.** The façade findings (H3, H5) are API-writes-that-don't-take-effect. When you say "make X configurable via the panel," add: *"a successful PUT must change live behavior; if it can't take effect without restart, the API must say so in the response, not return success."*

6. **For anything touching client IP, specify the trust model.** Give me: *"assume XFF is hostile unless peer ∈ trusted_proxies (non-empty); take the rightmost-untrusted hop, not the leftmost."* (See unknown-unknown #2.)

7. **When you want me to verify a claim, say "prove it against real data / a running instance," not "check."** This review's refuted CRITICAL is the case in point — the format bug was plausible on paper and false against the actual xdb source. A prompt of *"verify the region parser against a real downloaded xdb, not a fabricated string"* would have caught it at authoring time.

Short version: **name the integration point, ban the hand-wired test, spell out the cross-layer contract, and state the default-config + trust posture.** That converts my output from "passes CI" to "works in prod."

---

## Suggested fix ordering (if you want a plan)

1. C1 (wire seed + challenge) + H1 (fp/rule deltas) — one engine change, one honest end-to-end test each. Highest security payoff.
2. C2 (credit sign) — small, unblocks the admin UI.
3. H5 + H3 — replace stubs / signal restart-required. Stops operators flying blind.
4. H2 (velocity purge loop) — memory-DoS; mechanical (copy the risk-store purge loop).
5. H4 (validate geo action) + H6 (band preview vs enforcement) — contract + UI truthfulness.
6. Unknown-unknown #2 (XFF) — coordinate with issue #74.

I can turn any of these into a phased plan under `plans/` on request.

---

## Unresolved questions

1. Is the seed/challenge un-wiring a staged rollout or a regression? If staged, the `seed.enabled: true` default is misleading and should be `false` until wired.
2. Is fp-axis-write-only intentional (pending a future enforcement story) or an oversight (H1)?
3. Is switching risk store backend at runtime supposed to be supported, or restart-only by design? If restart-only, the API should reject/annotate the field, not 200-OK it (H3).
4. Are `list_risk_actors`/`get_risk_metrics` scheduled this cycle, or should the UI show explicit "not implemented" now (H5)?
5. Is panel-config `risk_allow/challenge/block` meant to drive enforcement (missing wiring) or should the band preview read tier thresholds / be removed (H6)?
6. Should `attack_logs.geo_info` + its 0008 indexes be dropped (dead), and should `get_geo_stats` be time-bounded (M4)?
7. Is `trust_proxy_headers=true` with empty `trusted_proxies` a reachable prod config? Determines severity of unknown-unknown #2.
8. Is the exact-match canary intentional honeypot behavior?
