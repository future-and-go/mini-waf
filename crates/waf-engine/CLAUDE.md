# waf-engine

Core detection engine. Evaluates inbound HTTP requests against rule sets and security checks, returning allow/block/challenge decisions.

## Features
- **Rule engine**: YAML / JSON / ModSecurity rule loading, hot-reload, builtin rule sets (OWASP, bot, scanner), custom-file loader.
- **Security checks**: SQL injection (libinjection + custom), XSS, RCE, directory traversal, anti-hotlink, sensitive-data, scanner detection, bot detection, geo, CC.
- **Access control (FR-008)**: hot-reloadable IP/CIDR allow/block tables + host-gate evaluator.
- **Relay / proxy intel (FR-009)**: ASN classifier, Tor-exit, datacenter, proxy-chain, XFF validator providers fed by HTTP feeds (iptoasn, Tor exit list) with atomic swap reload.
- **Device fingerprinting (FR-010)**: TLS ClientHello + HTTP/2 frame capture, JA3 / JA4 / Akamai H2 fingerprint hashers, identity store (in-memory or Redis), risk-signal providers (UA blocklist/entropy, fingerprint conflict, IP hopping, H2 anomaly), risk aggregator.
- **Transaction velocity (FR-012)**: signal-only; dispatched from gateway `logging()` hook (not `response_filter`) so streaming, WAF-blocked, and origin-down paths are handled correctly. Events carry tristate `Outcome::{Pending, Ok, Failed}`; classifiers ignore Pending. Velocity signals carry both `count` (settled attempts in window) and `ok_count` (subset that succeeded). Cookie-less requests fall back to `RequestCtx.device_fp` scoped by `peer_ip` for session identity.
- **CrowdSec integration**: AppSec component, decision sync, cache, pusher, models.
- **Community blocklist**: enrollment, fetch, reporter, checker.
- **Plugins**: WASM (`wasmtime`) and Rhai script execution for custom logic.
- **GeoIP**: ip2region + MaxMind lookups with background updater.
- **Block page**: rendered response for denied requests.

## Folder Structure
```
src/
├── lib.rs
├── engine.rs                # Top-level evaluator
├── checker.rs               # Check orchestration
├── rules.rs                 # Public rules API (legacy facade)
├── block_page.rs            # Block response renderer
├── geoip.rs / geoip_updater.rs
├── checks/                  # Individual security checks
│   ├── sql_injection{,_patterns,_scanners}, xss, rce, dir_traversal,
│   ├── geo, cc, bot, scanner, sensitive, anti_hotlink, owasp
│   ├── ddos/                # FR-005 DDoS protection (config + detector strategy)
│   │   ├── detector/        # Detector trait + implementations (per-IP, per-fingerprint, per-tier)
│   │   └── store/           # Counter backends (memory, redis)
├── rules/
│   ├── engine.rs, manager.rs, registry.rs, hot_reload.rs, sources.rs,
│   ├── custom_file_loader.rs
│   ├── builtin/             # owasp, bot, scanner builtin rules
│   └── formats/             # yaml, json, modsec, custom_rule_yaml parsers
├── access/                  # FR-008 access control
│   ├── config.rs, evaluator.rs, host_gate.rs, ip_table.rs, reload.rs
├── relay/                   # FR-009 proxy/relay intel
│   ├── config.rs, registry.rs, reload.rs, signal.rs
│   ├── intel/               # asn_feed, tor_feed, datacenter_set, http, atomic_swap
│   └── providers/           # asn_classifier, tor_exit, proxy_chain, xff_validator
├── device_fp/               # FR-010 device fingerprinting
│   ├── config.rs, types.rs, signal.rs, registry.rs, reload.rs, aggregator.rs
│   ├── capture/             # tls, h2, client_hello_inspector, h2_frame_inspector, conn_ctx
│   ├── fingerprint/         # ja3, ja4, h2_akamai (+ trait)
│   ├── identity/            # memory + redis stores (redis gated by feature)
│   ├── behavior/            # FR-011 behavioral anomaly detection (per-actor cadence/path classifiers)
│   └── providers/           # ua_blocklist, ua_entropy, fp_conflict, ip_hopping, h2_anomaly
├── risk/                    # FR-025 cumulative risk scoring (in-memory + config hot-reload)
│   ├── config.rs, scorer.rs, score.rs, decay.rs, threshold.rs
│   ├── key.rs               # RiskKey (triple-index: IP/fingerprint/session)
│   ├── state.rs             # RiskState, Contributor, ContributorKind
│   ├── reload.rs            # notify-based hot-reload with ArcSwap
│   └── store/               # RiskStore trait + MemoryRiskStore backend
├── crowdsec/                # appsec, cache, client, sync, pusher, models
├── community/               # blocklist, client, enroll, reporter, checker
└── plugins/                 # WASM + Rhai plugin manager

benches/                     # sql_injection, rule_eval, access_lookup,
                             # relay_eval, device_fp_capture, device_fp_pipeline
tests/                       # acceptance + integration suites
```

## Features (cargo)
- `redis-store` — enables Redis-backed device-fp identity store (`device_fp::identity::redis`).

## Dependencies
Depends on `waf-common`, `waf-storage`. Heavy hitters: `pingora-core` (vendored fork — TLS/H2 inspector traits for FR-010), `wasmtime`, `rhai`, `regex`, `aho-corasick`, `libinjectionrs`, `ip2region`, `maxminddb`, `notify`, `arc-swap`, `ed25519-dalek`, `zstd`, `md-5` / `sha2` (fingerprint hashers), `redis` (optional).
