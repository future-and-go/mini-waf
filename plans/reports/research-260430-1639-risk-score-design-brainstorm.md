---
title: "Risk Score Design Brainstorm — mini-waf"
date: 2026-04-30
type: research
slug: risk-score-design-brainstorm
sources:
  - analysis/requirements.md
  - analysis/docs/EN_present_v2.3.md
  - analysis/docs/EN_waf_interop_contract_v2.3.md
  - arxiv:2602.09606 (JA4 bot detection)
  - arxiv:2510.11804 (Tor WF survey)
  - arxiv:2410.03817 (TLS feature expansion + LSH similarity)
  - arxiv:2601.01183 (VAE/GAN/SMOTE Tor detection)
  - arxiv:2411.00368 (Real-time ML risk scoring)
  - usenix:usenixsecurity24-kondracki (Smudged Fingerprints — bot detection)
  - https://www.maxmind.com/en/geolite-commercial-redistribution-license
  - https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/
  - https://packet.guru/blog/TLS-Fingerprinting-JA3-JA4 (JA4+ in 2026)
  - https://www.mdpi.com/2673-8732/5/3/29 (ECH adoption measurement 2025)
  - https://github.com/beowolx/rensa (rensa MinHash Rust crate)
  - https://github.com/ritchie46/lsh-rs (lsh-rs Rust crate)
  - https://github.com/advisories/GHSA-6gvq-jcmp-8959 (CVE-2025-68113 ALTCHA PoW replay)
  - https://developers.cloudflare.com/cloudflare-challenges/concepts/clearance/ (cf_clearance pattern)
---

# Risk Score Design Brainstorm — mini-waf

## 0. Executive Summary

The WAF interop contract treats the risk score as the **primary observability signal** of the engine — it appears on every response (`X-WAF-Risk-Score`), drives Allow/Challenge/Block decisions, and is benchmark-tested for **lifecycle behavior** (accumulation, decay, reset). A naive "sum of rule deltas" score is enough to compile, but will fail the benchmark on three axes: (a) under-discrimination on low-confidence signals, (b) noisy decay producing false positives on legitimate traffic, (c) gameable by IP rotation.

Recommendation: build a **3-layer cumulative score** keyed on `(peer_ip, ja4_hash, session_id)` triple. Each layer feeds a single 0–100 integer:

1. **Reputation layer** (slow-changing): IP/ASN/Tor/blacklist priors → seeds the score.
2. **Per-request signals** (fast): rule hits, OWASP detectors, header anomalies, fingerprint conflicts → bounded delta added per request.
3. **Sequence/velocity layer** (sliding window): cross-endpoint flows, burst detection, transaction velocity → decaying weighted sum.

Final score is `clamp(seed + Σ deltas − decay, 0, 100)` with **per-tier multipliers** (CRITICAL routes scale danger up, static routes down). Threshold thus stays static (30/70) while sensitivity adapts to route value. This matches the contract semantics, survives the dynamic benchmark, and stays explainable for the audit log + dashboard.

---

## 1. Hard Constraints From The Interop Contract

These are non-negotiable — the bench tool fails the run if any are violated.

| # | Constraint | Source | Implication |
|---|-----------|--------|-------------|
| C1 | `X-WAF-Risk-Score` integer 0–100, on **every** response (incl. allow + challenge + block + timeout + circuit_breaker) | §5.1 | Score must be available *before* response is written, even on cached HITs |
| C2 | Score reflects state **after** current request | §5.3 | Compute → emit → persist; can't lazy-update |
| C3 | Cumulative per `{IP + device_fp + session}`; **does not reset per request** | FR-025, FR-026 | Need keyed store w/ TTL eviction, not per-conn state |
| C4 | Increases on rule match / failed challenge / anomaly / suspicious ASN / fingerprint conflict | FR-026 | Each must produce explicit, attributable delta |
| C5 | Decreases on challenge success + sustained normal behavior | FR-026 | Need a decay function and a "challenge-passed" credit |
| C6 | `reset_state` MUST wipe risk state, MUST preserve audit log | §2.4 | Risk store separate from log writer |
| C7 | `log_only` mode evaluates normally, reports intended action via headers, but does not enforce | §2.5, §3 | Score logic identical in both modes; only the *consumer* (action gate) differs |
| C8 | IP = TCP `peer_addr`, NOT `X-Forwarded-For` (XFF spoofable, also bench uses `127.0.0.x` aliases as distinct clients) | §6, §10 | Loopback aliases must be distinct keys |
| C9 | `X-WAF-Rule-Id` must identify the dominant detector behind the action; `none` if no rule | §5.1 | Engine must track *which* signal pushed across threshold, not just total |
| C10 | Deterministic: same input → same output | §1 | No randomness in score; salts must be stable per benchmark run |
| C11 | Bench tests **risk accumulation/decay** lifecycle on allowed responses | §5.3 | Score must visibly move on benign traffic too — pure pass-through = fail |
| C12 | Thresholds (FR-027): <30 Allow, 30–70 Challenge, >70 Block — configurable | FR-027 | Don't hardcode 30/70 — make them config-driven |

**Brutal note:** a score that only fires on attacks fails C11. The benchmark sends benign traffic and verifies the score moves up *and* down. Static `risk=0` for all-good is wrong.

---

## 2. Insights Pulled From Papers

Five papers downloaded to `plans/reports/research-arxiv/`. Only what's transferable to scoring is summarized — not the full content.

### 2.1 arxiv:2602.09606 — TLS JA4 Bot Detection (Feb 2026)
- JA4 fingerprint structure: `JA4_a` (protocol+TLS+SNI+counts+ALPN) `_` `JA4_b` (sorted-ciphe r SHA256-12) `_` `JA4_c` (sorted-extensions+sigalgs SHA256-12).
- **Feature importance for bot vs human (XGBoost):** `JA4_b` >> `cipher_count` > `ext_count` > `JA4_c` > `ALPN_code` > `OS` > `sni_flag` > `tls_version`.
- XGBoost on 227k labeled JA4DB records → precision 0.9668, recall 0.9798, F1 0.9732, AUC 0.998.
- **JA4 strength matrix:**
  - Scripts/scrapers (curl, requests, Scrapy): HIGH detection.
  - User-Agent / IP rotation: HIGH (JA4 stable across rotation).
  - Full-stack emulation (Puppeteer/Selenium driving real Chrome): NONE — JA4 identical to legit browser.
  - Advanced TLS-spoofing libs (intentional bitwise mimicry): MEDIUM.
- **Two cheap heuristics that punch above weight:**
  - UA claim ↔ TLS stack mismatch (e.g. UA="Chrome on iOS" but JA4 = curl) → impersonation. Empirical 30–35% TLS dissimilarity across browser families.
  - Missing `Accept-Language` header on script-flagged JA4H_ab → strong automation signal.

→ **Use for risk:** seed +20 for known-bad JA4_b hashes, +15 for JA4↔UA inconsistency, +10 for missing Accept-Language combined with non-browser JA4 family. JA4 is the device fingerprint in FR-010.

### 2.2 arxiv:2510.11804 — Comprehensive Survey of Tor Website Fingerprinting (Jan 2026)
- Mostly about *attacking* Tor (de-anonymizing users), but the **traffic-feature taxonomy** is directly transferable to defensive Tor *detection* at our WAF:
  - Timing: packet inter-arrival, time gap, transmission/total ratio.
  - Length: total packets, in/out counts, bytes per direction.
  - Cell/packet size: Tor uses fixed 512/514-byte cells (visible at TLS-record level only when WAF is also TLS terminator).
  - Direction: incoming/outgoing sequence (+1/-1).
  - Bursts: short high-rate same-direction sequences.
  - Coarse: total transmission time, per-direction bandwidth, burstiness.
- **Defense-side observation:** at a WAF that is the *origin* (not a Tor relay), the most actionable Tor signals are **IP-set membership** (Tor exit list) and **ASN classification** — content-level WF features are too late and too noisy for a per-request decision.
- Tor circuits rotate every ~10 min → same client may appear from multiple exit IPs in a session. Risk store must be keyed on JA4+session, not only IP, to track this continuity.
- Survey notes **concept drift** as #1 future challenge: any static rule list ages. Implication: refresh threat-intel periodically (FR-042).

→ **Use for risk:** Tor exit IP match = fixed +30 seed. Datacenter/hosting ASN +10. Residential = 0. ASN-anomaly (mobile carrier IP serving 1000 req/s) = anomaly delta +15.

### 2.3 arxiv:2410.03817 — TLS Fingerprint Feature Expansion + LSH Similarity (Oct 2024)
- Pure hash-based fingerprints (JARM, raw JA3) are brittle: tiny config change → totally different hash, while CDN-shared fingerprints have so high cardinality they lose discriminative power.
- Solution: enrich TLS metadata with HTTP-header features, then use **MinHash + Locality-Sensitive Hashing** to compute a *similarity* score against known-bad fingerprints, not exact match.
- 67 previously unknown malicious domains found purely via similarity to known-bad clusters.
- Lesson borrowed from cheminformatics: high-dim similarity > exact hash for adversarial drift.

→ **Use for risk:** when a JA4 hash misses the blacklist exactly, run LSH against a small bad-cluster index → if Jaccard ≥ 0.8, treat as fuzzy match (+10, lower than exact +20). Caveat: MinHash+LSH at 5k req/s in p99 5ms is tight — might be a P1 enhancement, not P0.

### 2.4 arxiv:2601.01183 — VAE/GAN/SMOTE for Tor Detection (Jan 2026)
- Real WAF traffic is **~90/10 normal/abnormal** — extreme class imbalance is the norm, not the exception.
- 26 middle-correlation features from packet length, inter-arrival, TCP flags suffice for a strong Random Forest / XGBoost classifier.
- Trade-offs: SMOTE simple/recall-oriented; GAN higher fidelity but memorizes; VAE best privacy/diversity balance.

→ **Use for risk:** if we ever ship the FR-046 ML bonus, start with XGBoost on 25–30 hand-crafted features (cheap, explainable, fast inference). Class-imbalance handling is required during training data prep — it's not a model choice.

### 2.5 arxiv:2411.00368 — Real-Time ML Risk Scoring + Fraud Detection (Oct 2024)
- Multi-model ensemble pattern is the industry default:
  1. Decision Tree → fast initial classification (cheap features: IP, ASN, basic headers).
  2. Random Forest → reduce variance.
  3. GBM/XGBoost → iterative refinement on misclassified.
  4. SVM → high-dim separation.
  5. Neural Net → hidden patterns.
  6. Autoencoder → reconstruction error = anomaly score.
- **Hierarchical principle:** cheap features evaluated first; expensive features only invoked if score is borderline. Saves CPU for benign majority.
- Continuous update: score evolves as new signals arrive within the same session.
- LightGBM had high precision + recall + AUC for credit fraud — strongest single model.

→ **Use for risk:** fold this into a **tiered evaluator pipeline**:
- L0 (constant time): IP/ASN/Tor list, JA4 exact match.
- L1 (sub-ms): rule engine, header sanity, OWASP regex.
- L2 (ms-scale): velocity counters, anomaly scoring.
- L3 (only if borderline 25–75): expensive checks (LSH similarity, cross-endpoint correlation).
Above 75 OR below 15, skip L3. This is the only way to hit p99 ≤ 5ms at 5k rps.

---

## 3. Proposed Risk Score Architecture

### 3.1 Identity Triple (the score's primary key)

```
RiskKey := (peer_ip: IpAddr, ja4_hash: u64, session_id: Option<SessionId>)
```

- `peer_ip`: TCP `peer_addr` only (C8). For loopback test rig, `127.0.0.X` are distinct.
- `ja4_hash`: 64-bit truncated hash of full JA4 string. Stable across IP rotation (paper 2.1).
- `session_id`: from `Cookie: session=…` or signed challenge cookie issued by WAF. `None` until first cookie issued.

Three lookup keys in a single Dashmap: `by_ip`, `by_ja4`, `by_session`. The score is the **max** across keys. This kills two evasion patterns:
- IP rotation, same JA4 → still flagged by JA4 key.
- JA4 rotation (curl with random ciphers), same IP → still flagged by IP key.

### 3.2 Score Composition (single 0–100 int, computed per request)

```
score(t) = clamp(
    seed                               // 3.3 — IP/ASN/Tor reputation, slow
  + Σ rule_deltas_in_window            // 3.4 — explicit FR-022 risk_score_delta
  + Σ anomaly_deltas_in_window         // 3.5 — JA4 conflict, header sanity, behavior
  + Σ velocity_deltas_in_window        // 3.6 — burst, sequence, transaction velocity
  − decay(elapsed_since_last_bad)      // 3.7 — sustained normal behavior
  − challenge_credit                   // 3.8 — successful PoW/JS proof
  , 0, 100
) * tier_multiplier                    // 3.9 — CRITICAL=1.2, MEDIUM=1.0, STATIC=0.8
```

All deltas additive; no multiplication of unbounded terms (avoids score explosion). `tier_multiplier` applied **last** so the same triple has different effective scores on `/login` vs `/static/*` — this matches FR-002 tiers without duplicating state.

### 3.3 Reputation Seed (one-time per key, refreshed on TTL)

| Signal | Δ |
|--------|---|
| Tor exit list match (FR-008, FR-042) | +30 |
| Bad-ASN list (FR-007) | +15 |
| Datacenter ASN (Hetzner/OVH/DO/AWS direct) when route is human-only (CRITICAL) | +10 |
| Residential ASN | 0 |
| Mobile carrier ASN with > N concurrent sessions | +10 (anomaly, see 3.5) |
| Whitelisted IP/FQDN | force score = 0, skip remaining layers |
| Honeypot canary path hit (FR-028) | +100 (force max) |

ASN classification needs IP→ASN mapping. Options: MaxMind GeoLite2-ASN (free), Team Cymru WHOIS (network call, no), pyasn-style local prefix tree (best). At startup load → ~250MB → in-memory radix trie → O(log n) lookup, <1µs per query.

### 3.4 Rule Deltas (FR-022 explicit)

YAML rule schema — already in FR-022:
```yaml
- id: sqli-union-select
  match: { path_or_body: "(?i)union\\s+select" }
  action: block
  risk_score_delta: 50
  scope: global
  priority: 100
```

Delta is signed integer; rule action (`allow/challenge/block`) is *advisory* — final action comes from threshold. Lets bench-tested `set_profile` toggle to `log_only` work without re-engineering the rules.

### 3.5 Anomaly Deltas (the discriminator)

| Signal | Δ | Source |
|--------|---|--------|
| JA4 ↔ UA family inconsistency (e.g., UA=Chrome but JA4=curl-family) | +15 | paper 2.1 |
| JA4 in known-bad cluster (exact match) | +20 | paper 2.1 |
| JA4 in fuzzy bad cluster (LSH Jaccard ≥ 0.8) | +10 | paper 2.3 |
| Missing `Accept-Language` + non-browser JA4 family | +10 | paper 2.1 |
| `X-Forwarded-For` chain length > 2 | +10 | FR-007 |
| `X-Forwarded-For` IP differs from peer in suspicious way (e.g., RFC1918 in XFF, public peer) | +15 | FR-017 |
| Same `ja4_hash` observed from > 5 different `peer_ip` in 60s (fingerprint conflict / proxy chain) | +20 | FR-010 |
| Same session cookie observed from > 3 different `ja4_hash` in 60s | +25 | session theft |
| Inter-request interval < 50ms (FR-011) for > 5 consecutive requests | +15 | FR-011 |
| Zero-depth session (only one path, no Referer chain) on CRITICAL tier | +10 | FR-011 |
| HTTP/2 SETTINGS frame fingerprint mismatches UA-claimed browser | +10 | FR-010 |
| Decoded payload yields nested encoding > 2 layers | +10 | evasion |
| Response from upstream contains stack trace or internal IP (outbound, FR-033) | +5 to *target* IP | retro-attribute scanning |

These are **deltas applied at request time**, persisted in the keyed store, and decay via 3.7. Each delta carries its rule_id so `X-WAF-Rule-Id` can pick the dominant contributor.

### 3.6 Velocity / Sequence Deltas (FR-012, FR-018, FR-019)

Sliding window: last 60s and last 600s, two counters per key.

| Pattern | Δ |
|---------|---|
| > N requests in 60s on CRITICAL tier (per-tier thresholds) | +10 per overshoot decade |
| > 3 failed logins same key in 5 min | +20 (FR-018) |
| Login → OTP → withdrawal sequence < 30s end-to-end | +25 (FR-012 — too fast for human) |
| > 10 distinct paths in 60s (recon scan, FR-019) | +15 |
| > 5 4xx responses in 60s | +10 |
| OPTIONS method abuse | +5 |

Use **token-bucket** (FR-004) to feed these counters — already needed for rate limiting, so velocity is essentially "rate-limit shadow" feeding into score.

### 3.7 Decay Function (the part most teams will get wrong)

C11 forces decay: bench tests that score declines on sustained normal traffic. Naive `score -= 1 per second` is wrong because it's request-volume independent — an idle attacker waiting 5 minutes resets to clean.

**Better:** decay is **per-request on this key** AND **time-bounded**:

```
decay(elapsed, requests_since_last_bad) =
    min(MAX_DECAY,
        floor(requests_since_last_bad / 5)        // -1 per 5 clean reqs
      + floor(elapsed_seconds / 30))              // -1 per 30s wall-clock
```

with cap `MAX_DECAY = 50` so a 100-score never drops to 0 without an explicit `reset_state` or human/challenge intervention. An attacker can't game this by sleeping — wall-clock decay is bounded; only behavior-based decay can fully erase.

### 3.8 Challenge Credit (FR-006)

- JS challenge passed: −15.
- PoW solved (difficulty ≥ 4): −25.
- Challenge issued but unsolved: 0 (no penalty for refusal — refusal is just "stop", not new evidence).
- Challenge token replay (same nonce, same key, > 1 use): +30.

### 3.9 Tier Multiplier (FR-002 + FR-038)

Apply *after* clamping to keep the score in [0, 100] but tier-aware:

| Tier | Routes | Multiplier | Effective threshold |
|------|--------|-----------|---------------------|
| CRITICAL | /login, /otp, /deposit, /withdrawal | 1.2 | Allow <25, Challenge 25–58, Block >58 |
| HIGH | /api/* | 1.1 | Allow <27, Challenge 27–63, Block >63 |
| MEDIUM | /game/*, /user/* | 1.0 | Allow <30, Challenge 30–70, Block >70 |
| CATCH-ALL | /static/*, /assets/* | 0.8 | Allow <38, Challenge 38–87, Block >87 |

Headers still report the **post-multiplier** integer so the bench tool sees the actual decision-driving value.

---

## 4. Score Lifecycle: Concrete Flow

```
┌──────────────────────────────────────────────────────────────┐
│ Request arrives → extract (peer_ip, ja4, session) = key       │
├──────────────────────────────────────────────────────────────┤
│ L0  load_or_create(key) → existing struct with seed already set
│     • If new: seed = reputation(peer_ip, ja4) + 0
│     • If existing: just hydrate prior_score                   │
├──────────────────────────────────────────────────────────────┤
│ L1  rule engine evaluates → collect Vec<(rule_id, delta)>     │
│     OWASP regex/SQLi/XSS/Path/SSRF/Header                    │
├──────────────────────────────────────────────────────────────┤
│ L2  anomaly scorer → header sanity, JA4↔UA, velocity counters │
├──────────────────────────────────────────────────────────────┤
│ L3  *(only if 25 ≤ post-L2 score ≤ 75)*                       │
│     LSH fuzzy JA4 match, cross-endpoint sequence detector     │
├──────────────────────────────────────────────────────────────┤
│ Apply decay (per 3.7) → new_total = clamp                     │
│ Apply tier_multiplier per route                               │
├──────────────────────────────────────────────────────────────┤
│ Decision:                                                     │
│   score < t_allow  → action = allow                           │
│   t_allow ≤ score < t_block → action = challenge              │
│   score ≥ t_block  → action = block                           │
│   override: rule.action = block (high confidence) → block     │
│   override: WAF unhealthy + tier=CRITICAL → block (fail-close)│
├──────────────────────────────────────────────────────────────┤
│ Persist updated state to RiskKey store (TTL: 30 min idle)     │
├──────────────────────────────────────────────────────────────┤
│ Emit headers: X-WAF-Risk-Score = score,                       │
│   X-WAF-Action = action, X-WAF-Rule-Id = top_contributor_id,  │
│   X-WAF-Mode = mode_for(top_contributor),                     │
│   X-WAF-Cache = cache_state, X-WAF-Request-Id = uuid          │
├──────────────────────────────────────────────────────────────┤
│ Append audit log line (mode=enforce|log_only)                 │
│ If enforce: enforce(action). If log_only: forward upstream    │
└──────────────────────────────────────────────────────────────┘
```

p99 budget per stage (5ms total): L0 100µs, L1 1ms, L2 1ms, L3 (skipped 80% of time) 2ms, persist 200µs, headers 50µs. Realistic on Rust + Pingora.

---

## 5. Storage Sketch (Rust types — illustrative)

```rust
// crates/waf-engine/src/risk/state.rs
pub struct RiskState {
    pub key: RiskKey,
    pub score: u8,                 // 0..=100, post-tier
    pub raw_score: i32,            // pre-clamp, pre-tier (for diagnostics)
    pub last_seen_ms: u64,
    pub last_bad_ms: u64,
    pub clean_streak: u32,         // consecutive non-positive-delta requests
    pub contributors: SmallVec<[Contributor; 8]>, // top-N for X-WAF-Rule-Id
}

pub struct Contributor {
    pub rule_id: CompactString,    // e.g. "rule-sqli-001", "anom-ja4-conflict"
    pub delta: i16,
    pub ts_ms: u64,
}

pub struct RiskKey {
    pub peer_ip: IpAddr,
    pub ja4_hash: u64,
    pub session_id: Option<SessionId>,
}

// Triple-indexed shard:
pub struct RiskStore {
    by_ip: DashMap<IpAddr, Arc<RwLock<RiskState>>>,
    by_ja4: DashMap<u64, Vec<Weak<RwLock<RiskState>>>>,
    by_session: DashMap<SessionId, Arc<RwLock<RiskState>>>,
}
```

Use `parking_lot::RwLock` per state (project rule, no `std::sync::Mutex`). DashMap for sharded concurrent access. Eviction: background task every 60s sweeping `last_seen_ms < now - 1800s`.

`reset_state` (C6): `by_ip.clear(); by_ja4.clear(); by_session.clear();` — synchronous, atomic, audit log file untouched.

---

## 6. Audit-Log Schema (extends §6 of contract)

Minimum required fields plus extras for dashboard / SIEM bonus:

```jsonl
{"request_id":"550e…","ts_ms":1714000000000,"ip":"1.2.3.4","method":"POST",
 "path":"/login","action":"block","risk_score":78,"mode":"enforce",
 "ja4":"t13d1516h2_8daaf6152771_02713d6af862","ja4_hash":"abcd…",
 "asn":13335,"asn_name":"CLOUDFLARENET","is_tor":false,"is_dc":true,
 "session_id":"sess-…","tier":"CRITICAL",
 "score_seed":15,"score_rule_delta":40,"score_anomaly_delta":15,
 "score_velocity_delta":8,"score_decay":0,
 "contributors":[{"rule":"rule-sqli-001","delta":40},{"rule":"anom-ja4-ua-mismatch","delta":15}],
 "user_agent_hash":"…","upstream_status":null,"upstream_latency_ms":null}
```

Append-only, JSONL. Score components broken out → dashboard can show "why this score" (FR-029, FR-030) without re-computing.

---

## 7. Common Failure Modes (and how this design avoids them)

| Failure mode | Likely consequence | Mitigation in this design |
|--------------|-------------------|---------------------------|
| Score never moves on benign traffic | Bench fails C11 lifecycle | Decay is bounded; benign requests still run L0–L2 to register clean_streak |
| Score spikes to 100 on first SQLi attempt then never drops | False positives on shared NAT IPs | Per-key state; whitelisted IP override; decay floor |
| IP rotation completely evades | Easy bypass via rotating residential proxy | JA4 key + session key — score is `max` across triple |
| Same `ja4_hash` from many real Chrome users on shared NAT scored high | Mass false positive | JA4-key state must NOT include score increments from rule matches on *other* IPs — only conflict count is shared. Score = per-IP score; JA4-conflict adds anomaly delta only. |
| Tor exit list goes stale | False negatives | TTL refresh every 1h (FR-042); compare delta against previous list, log adds/removes |
| `set_profile log_only` and team forgets to compute decisions | Bench fails — no `X-WAF-Action` reported | Score+action computed in BOTH modes; only the *enforcement gate* differs |
| Score field-leaks into upstream | Not directly tested but breaks FR-035 | Strip `X-WAF-*` from upstream-bound request; only attach on response |
| Race on simultaneous requests for same key (CRITICAL) | Lost updates → bench non-determinism | Per-state `RwLock`; score read+update under write lock |
| `reset_state` mistakenly truncates audit log | Bench scoring penalty (§2.4) | Risk store and log writer fully decoupled; reset_state only touches in-memory maps |

---

## 8. Adversarial Considerations (from Attack Battle prep)

Red Team's 8 attack vectors map to score components as follows:

| Attack | Primary score driver | Where it shows in score |
|--------|---------------------|-------------------------|
| DDoS L4/L7 | Velocity (3.6) + tier multiplier on CRITICAL | Score saturates fast on bursters |
| Bot login / credential stuffing | Failed-login velocity + JA4 family | Score >70 in <10 attempts |
| Relay & proxy attack | Reputation seed (Tor/DC ASN) + XFF anomaly | Seed +30, anomaly +15 = 45 baseline |
| Device fingerprint evasion | JA4-conflict cross-IP | +20 once N>5 same JA4 |
| Behavioral bypass | Sequence + interval anomaly | +15 per fast sequence, accumulates |
| Transaction fraud | FR-012 sequence detector → +25 | Tipping score over Block easily |
| OWASP injection | Rule deltas (3.4) | +50 typical for SQLi UNION |
| Canary/recon | Honeypot hit = +100 | Instant Block; canary IP also blacklisted |

**Hardest case: full-stack browser emulation** (Puppeteer with real Chrome). JA4 = legit Chrome. Defense must rely on:
1. Behavioral velocity (3.6).
2. Cross-endpoint sequence (3.6).
3. ASN — Puppeteer farms usually run on datacenter IPs.
4. HTTP/2 settings + h2 priority order — easier to fingerprint than TLS for headless browsers.

---

## 9. P0 vs P1 Split

What to ship for Round 1/2 vs reserve for Round 3 bonus.

**P0 (mandatory for Round 2 pass):**
- Identity triple, simple max-score across keys.
- L0 reputation seed (Tor list + ASN classification).
- L1 rule engine with `risk_score_delta`.
- L2 basic anomaly: JA4↔UA mismatch, header sanity, fingerprint conflict count.
- Velocity counters: failed logins, request rate.
- Bounded decay.
- Challenge credit on PoW success.
- Tier multiplier.
- Honeypot.
- Audit log + headers.

**P1 / Round-3 bonus:**
- LSH fuzzy JA4 matching (paper 2.3) — Tier A bonus.
- HTTP/2 SETTINGS fingerprinting — Tier A.
- Lightweight XGBoost ML classifier on top of current signals (FR-046) — Tier A.
- Score explainability dashboard with contributor breakdown — Tier B.
- Rule simulator / dry-run mode — Tier A.
- IP-reputation feed auto-refresh w/ versioning — Tier B.

---

## 10. Bench Compliance Checklist (the literal scoring gates)

- [ ] `X-WAF-Risk-Score` integer 0–100 on every response (allow + block + challenge + rate_limit + timeout + circuit_breaker).
- [ ] `X-WAF-Action` matches actual enforcement when mode=enforce; reports intended action when mode=log_only.
- [ ] `X-WAF-Rule-Id` = top contributor's id, or `none` when score driven entirely by reputation/decay.
- [ ] `X-WAF-Mode` correctly switches via `POST /__waf_control/set_profile`.
- [ ] `X-WAF-Cache` = `BYPASS` for CRITICAL tier always.
- [ ] `X-WAF-Request-Id` = audit-log `request_id` 1:1.
- [ ] `peer_addr` (NOT XFF) used for IP key.
- [ ] `127.0.0.1` and `127.0.0.2` treated as distinct keys.
- [ ] `reset_state` clears risk store atomically; audit log untouched.
- [ ] Score visibly accumulates on attack patterns; visibly decays on clean traffic.
- [ ] Same input → same score (deterministic; no `rand` in hot path).
- [ ] Whitelist override sets score=0 unconditionally.
- [ ] Honeypot path → score=100 immediately.

---

## 11. Question Resolutions

Each question gets: **finding** → **decision** → **citation**. Resolutions sourced from web research + USENIX + 2025–2026 publications. Research notes preserved at `plans/reports/research-260430-1655-risk-score-unresolved-questions.md`.

### Q1 — JA4 plaintext vs hash → **RESOLVED**
**Finding:** JA4 string is not PII. JA4+ is industry-standard 2026; Cloudflare/AWS/IBM/VirusTotal expose full string in headers.
**Decision:** Expose **both**. `X-WAF-JA4: <full 38-char string>` and `X-WAF-JA4-Hash: <u64 hex>` as bonus observability headers (allowed under contract §5.2). Audit log carries both `ja4` and `ja4_hash`.
**Sources:** [packet.guru 2026](https://packet.guru/blog/TLS-Fingerprinting-JA3-JA4), [proxies.sx](https://www.proxies.sx/use-cases/privacy/tls-fingerprint).

### Q2 — MaxMind GeoLite2-ASN license → **RESOLVED**
**Finding:** Free GeoLite2 is OK for use *if user downloads it themselves*. **Cannot bundle .mmdb in our binary** — that requires paid Commercial Redistribution License (per-product).
**Decision:**
- Don't bundle. Config file points to user-provided `geolite2-asn.mmdb`. FR-042 wording ("from file at startup") aligns with this workflow.
- Fallback: ship a public-BGP-derived IP→ASN radix trie (Team Cymru / RIPE bulk WHOIS, public data, ~3MB) — no license issue.
**Sources:** [MaxMind Commercial Redistribution](https://www.maxmind.com/en/geolite-commercial-redistribution-license), [GeoLite2 Free](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/).

### Q3 — Session ID source → **RESOLVED**
**Finding:** Cloudflare's `cf_clearance` is the industry reference: WAF-issued, HMAC-signed, bound to IP+fingerprint, separate from upstream session.
**Decision:** WAF issues its own cookie `__waf_session=<uuid>.<hmac>` only when (a) a challenge is solved or (b) a request triggers risk delta > 0. No cookie on clean traffic. Don't touch upstream's session cookie. Risk-store key = `(peer_ip, ja4_hash, waf_session_id | upstream_session_id | None)` — first match wins.
**Source:** [Cloudflare Clearance docs](https://developers.cloudflare.com/cloudflare-challenges/concepts/clearance/).

### Q4 — Decay parameter tuning → **DEFERRED (engineering)**
No external benchmark fits our decay model. Build a replay harness reading `waf_audit.log`. Seed values from §3.7. Re-tune after first bench dry-run. Target: 1 accidental rule trip (+15) returns under 30 within ~50 clean reqs OR ~15 minutes.

### Q5 — Tier classification source → **RESOLVED**
Single `waf.yaml` with `tiers:` block. Longest-prefix match, first match wins. Tier definitions are static config (not hot-reloadable like rules):
```yaml
tiers:
  CRITICAL: { paths: ["/login","/otp","/deposit","/withdrawal"], fail_mode: fail-close, multiplier: 1.2 }
  HIGH:     { paths: ["/api/*"],                                    fail_mode: fail-close, multiplier: 1.1 }
  MEDIUM:   { paths: ["/game/*","/user/*"],                         fail_mode: fail-open,  multiplier: 1.0 }
  CATCH_ALL:{ paths: ["/*"],                                        fail_mode: fail-open,  multiplier: 0.8 }
```

### Q6 — Successful challenge credit → **RESOLVED**
**Finding:** ALTCHA CVE-2025-68113 (Sep 2025) — HMAC over nonce-only let attackers re-interpret signatures with modified expiry → replay. Fix: HMAC must bind **all** challenge params, not just nonce.
**Decision:** Challenge token = `b64(nonce) || ts || difficulty || hmac(secret, nonce||ts||difficulty||peer_ip||ja4_hash)`. Credit when ALL of:
1. HMAC verifies.
2. `now - ts < 300s`.
3. PoW nonce hash meets difficulty.
4. Nonce not in **consumed-nonce LRU** (100k entries, 5min TTL, ~1MB).
5. Submitting client's `(peer_ip, ja4_hash)` matches the binding in HMAC. (Stops cookie theft.)

Credit values: JS challenge −15; PoW d=4 −20, d=5 −25, d=6 −30. Replay attempt (consumed nonce) → +30 penalty. Require 5 clean reqs between credits (anti-grinding).
**Source:** [GHSA-6gvq-jcmp-8959 / CVE-2025-68113](https://github.com/advisories/GHSA-6gvq-jcmp-8959).

### Q7 — Penalize on upstream errors → **RESOLVED**
**Finding:** Cloudflare/AWS WAF score on 4xx ratio + path diversity per source, never on 5xx (upstream's fault).
**Decision:** Boost only on **client-attributable 4xx** (`400`, `404`, `405`) — NOT `401/403/429` (we issued those, no double-count) and NEVER `5xx`. Threshold: `4xx_count > 10 in 60s AND distinct_paths > 5` → +15 (recon, FR-019). Single 404 from typo: no boost.

### Q8 — JA4 stability under ECH → **RESOLVED (not a concern)**
**Finding:** John Althouse (JA4 creator, 2026): *"ECH does not impact JA4 TLS Client Fingerprinting"* if you terminate TLS. Our WAF terminates → reads inner ClientHello → JA4 unaffected. ECH server adoption still <1% in 2026; 59% of QUIC ECH extensions are GREASE placeholder values.
**Decision:** Document in submission: "ECH-terminating mode supported; JA4 computed post-ECH-decryption." Not on the worry list.
**Sources:** [packet.guru 2026](https://packet.guru/blog/TLS-Fingerprinting-JA3-JA4), [MDPI 2025 ECH measurement](https://www.mdpi.com/2673-8732/5/3/29), [JA4 in the Wild](https://deveshshetty.com/blog/ja4-client-fingerprinting/).

### Q9 — LSH performance budget at 5k rps → **RESOLVED (estimated)**
**Finding:** Three production Rust crates: **rensa** (FxHash/Murmur3, batch-vectorized, fastest), **lsh-rs** (full LSH framework), **datasketch-minhash-lsh** (Python port). MinHash filtering = ~4000× speedup vs naive Jaccard.
**Decision:** Use **rensa**. Estimated cost per request: 64-hash MinHash sig (~5µs) + LSH bucket lookup (~1µs) + Jaccard verify on ≤10 candidates (~5µs) = **~10–15µs total**. Comfortably inside the 2ms L3 budget. Microbenchmark on day 1 of integration; if >100µs at 5k rps, demote to async-warm-cache mode.
**Sources:** [rensa](https://github.com/beowolx/rensa), [lsh-rs](https://github.com/ritchie46/lsh-rs), [datasketch-minhash-lsh](https://crates.io/crates/datasketch-minhash-lsh).

### Q10 — Bonus / Tier-A scope → **RESOLVED**
Round 3 favors fewer-bigger over many-small (diminishing returns within tier). Top-3 Tier-A picks:
1. **HTTP/2 SETTINGS + h2 priority fingerprinting** — complements JA4, catches Puppeteer/headless-Chrome (the hardest case from §8). ~2 days.
2. **Risk-score-aware adaptive rate limiting** — bucket size shrinks as score rises. Merges FR-004 + FR-027.
3. **Score explainability dashboard** — contributor breakdown per request_id. UI work, low cost, high judge-impression value (FR-029/030/031).

**Skip ML (FR-046)** — high effort, fragile under bench mutations, hard to debug. Defer post-hackathon.

---

## 11.1 New Questions That Emerged During Resolution

1. **Public-BGP IP→ASN refresh cadence.** If we use the Team-Cymru-derived prefix file (Q2 fallback), how often to refresh? Hackathon: load once at startup, no refresh. Production: weekly. Document the gap.
2. **HMAC secret persistence.** Q6 challenge HMAC secret must survive WAF restart. If regenerated on each boot, outstanding challenges become invalid → bench may interpret as duplicate-challenge bug. Solution: persist secret to disk on first generation, reload on restart. Same risk-key on `reset_state` — keep secret across resets, only nuke consumed-nonce set + risk store.
3. **JA4 collision FP rate.** JA4 is `13_a + 12_hash_b + 12_hash_c`. Some legit user collision with bad cluster expected. Need empirical FP measurement before trusting `+20` exact-match delta. Mitigate: lower to `+15` if dry-run FP rate >0.5%.
4. **rensa crate maintenance status.** Check last-commit date before adding to Cargo.toml. Fall back to `lsh-rs` if abandoned.

---

## 12. Suggested Next Step

Build a **risk-score harness** in `crates/waf-engine/src/risk/` with:
1. `RiskStore` + `RiskState` types (above).
2. `score()` function that takes `(Request, RouteCtx, &mut RiskStore)` → `(u8, Action, RuleId)`.
3. Unit tests covering: accumulation, decay, reset, JA4 conflict, Tor seed, tier multiplier, log_only invariance.
4. A replay tool that reads `waf_audit.log` and re-computes scores for regression.

Once that's stable in isolation, wire into the Pingora handler. Don't try to integrate score logic with rule engine and Pingora simultaneously — too many failure axes.
