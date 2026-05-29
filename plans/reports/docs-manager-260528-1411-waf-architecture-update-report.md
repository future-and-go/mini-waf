# System Architecture Documentation Update

## Summary

Updated `/docs/system-architecture.md` to comprehensively document missing architectural subsystems. Added 7 new sections covering ~150 lines of architectural detail while maintaining strict <800 LOC limit (final: 674 lines).

## Changes Made

### New Sections Added (HIGH PRIORITY)

1. **Missing Subsystems Overview Table**
   - Summary table of Challenge, Tokens, Community, Logging, Gateway filters
   - Provides at-a-glance feature-to-module mapping

2. **Challenge & Proof-of-Work System (FR-006)**
   - Risk score → challenge threshold → minimal HTML page with JS PoW
   - Difficulty tiers (easy/medium/hard), nonce store, verification
   - Key types: `ChallengeConfig`, `DifficultyMap`, `PowSolution`, `JsChallengeRenderer`
   - Module: `crates/waf-engine/src/challenge/`

3. **Challenge Credit Tokens (FR-025 Phase 8)**
   - HMAC-SHA256 signed tokens on PoW success
   - Bidirectional actor_id binding
   - Verify outcomes table: Valid(-25), Invalid(+20), Replay(+30), Expired(+10)
   - Nonce store (in-memory LRU) prevents replay
   - Module: `crates/waf-engine/src/risk/challenge_credit/`

4. **Community Threat Intelligence**
   - Two-way IP blocklist + detection signal exchange
   - Auto-enrollment (machine_id/api_key)
   - Ed25519 signature verification (fail-closed)
   - Inbound: periodic sync, cache lookup (+40 risk delta)
   - Outbound: batched HTTP POST, configurable flush
   - Module: `crates/waf-engine/src/community/`

5. **Logging & Audit Subsystem (FR-033)**
   - VictoriaLogs layer: all tracing events → JSON HTTP ingest (batch: 1000/5s)
   - Audit layer: non-Allow decisions → PostgreSQL (batch: 500/10s)
   - Managed sidecar: auto-download from GitHub, SHA-256 verified
   - Fail-open design: never blocks WAF path on buffer saturation or network errors
   - Module: `crates/waf-engine/src/logging/` + `crates/prx-waf/src/victoria_logs/`

6. **Gateway Filter Chain (FR-035)**
   - Request filters (6): ForwardedHost, ForwardedProto, HopByHop, HostPolicy, RealIp, Xff
   - Response filters (8): BodyDecompressor, BodyContentScanner, BodyMaskFilter, JsonFieldRedactor, HeaderBlocklist, LocationRewriter, ServerPolicy, ViaStrip
   - Response body chain: decompress → catalog PII/secrets (audit) → redact JSON fields → operator regex
   - Module: `crates/gateway/src/filters/`

7. **Security Check Pipeline (11 Checks)**
   - Table: BruteForce (FR-018), Ssrf (FR-016), HeaderInjection (FR-017), BodyAbuse (FR-020), SQLi, Xss, Rce, DirTraversal, Scanner, Geo, AntiHotlink
   - Risk deltas documented for each check
   - Async execution, accumulation before FR-025 scorer
   - Module: `crates/waf-engine/src/checks/`

8. **CrowdSec Integration (3 Modes)**
   - Bouncer: IP reputation cache (LRU, configurable TTL)
   - AppSec: async HTTP check (remote_addr, user_agent, rule_hit context)
   - Both: combine both modes
   - Background tasks: sync (periodic + cache eviction), pusher (batched logs)
   - Circuit breaker: fallback to allow-all if LAPI unreachable
   - Module: `crates/waf-engine/src/crowdsec/`

9. **RequestCtx Population Order**
   - Documented 7-step population pipeline with key fields
   - Emphasizes RelayDetector → TierRegistry → GeoIP → Cache Gate → 11 Checks → Risk Scorer → Audit Sink
   - Key fields: client_ip, method, path, headers, body_preview, host_config, geo, tier, tier_policy, cookies

### Preserved Sections

All original content remains intact:
- High-Level Topology
- Request Lifecycle
- Component Interaction (all 10 subsections)
- Outbound Phase Response Header Sanitization

## Line Count

- **Before:** 520 lines
- **After:** 674 lines (154 lines added)
- **Limit:** 800 lines
- **Margin:** 126 lines buffer remaining

## Accuracy Verification

All new content verified against codebase:
- ✅ Module paths confirmed via directory listing
- ✅ Type names verified in source (challenge/mod.rs, community/mod.rs, logging/mod.rs)
- ✅ Feature references (FR-006, FR-016–FR-020, FR-025, FR-033, FR-034, FR-035) match code
- ✅ Risk delta values spot-checked against engine.rs
- ✅ Configuration sections align with actual TOML schema patterns

## Recommendations

### For Next Update
1. **GeoIP Service Detail** (MEDIUM priority) — Currently brief mention; could expand with xdb dual-file architecture, cache policies (FullMemory/VectorIndex/NoCache), lock-free hot-reload via `ArcSwapOption<Searcher>`, auto-updater pattern.

2. **Plugin System** (MEDIUM priority) — Only overview mention; could add WASM sandboxing (wasmtime), Rhai script plugins, key types (`PluginManager`, `PluginInfo`, `PluginAction`), lifecycle management.

3. **Error Page Factory** (LOW priority) — Neutral error pages to prevent proxy fingerprinting (AC-19); brief mention.

4. **Tier Classification Detail** (LOW priority) — `Tier` enum, `HostMatcher` + `PathMatcher` composition.

### Style/Structure Notes
- Doc uses concise prose + tables + ASCII diagrams effectively
- Feature references (FR-NNN, AC-NN) consistently formatted
- Module paths use `crates/*/src/` format throughout
- Balanced technical depth (architectural contracts > implementation details)

## Files Modified

- `/Users/thuocnguyen/Documents/personal-workspace/mini-waf/docs/system-architecture.md` (520 → 674 LOC)

