# waf-engine

Core detection engine. Evaluates inbound HTTP requests against rule sets and security checks, returning allow/block/challenge decisions.

## Features
- **Rule engine**: YAML / JSON / ModSecurity rule loading, hot-reload, builtin rule sets (OWASP, bot, scanner).
- **Security checks**: SQL injection (libinjection + custom), XSS, RCE, directory traversal, anti-hotlink, sensitive-data, scanner detection, bot detection, geo, CC.
- **CrowdSec integration**: AppSec component, decision sync, cache, pusher, models.
- **Community blocklist**: enrollment, fetch, reporter, checker.
- **Plugins**: WASM (`wasmtime`) and Rhai script execution for custom logic.
- **GeoIP**: ip2region-based lookups with background updater.
- **Block page**: rendered response for denied requests.

## Folder Structure
```
src/
├── lib.rs
├── engine.rs                # Top-level evaluator
├── checker.rs               # Check orchestration
├── rules.rs                 # Public rules API
├── block_page.rs            # Block response renderer
├── geoip.rs / geoip_updater.rs
├── checks/                  # Individual security checks
│   ├── sql_injection*, xss, rce, dir_traversal, geo, cc,
│   ├── bot, scanner, sensitive, anti_hotlink, owasp
├── rules/
│   ├── engine.rs, manager.rs, registry.rs, hot_reload.rs, sources.rs
│   ├── builtin/             # owasp, bot, scanner builtin rules
│   └── formats/             # yaml, json, modsec parsers
├── crowdsec/                # appsec, cache, client, sync, pusher, models
├── community/               # blocklist client, enroll, reporter
└── plugins/                 # WASM + Rhai plugin manager

benches/sql_injection.rs     # Criterion bench
tests/sql_injection_acceptance.rs
```

## Dependencies
Depends on `waf-common`, `waf-storage`. Heavy hitters: `wasmtime`, `rhai`, `regex`, `aho-corasick`, `libinjectionrs`, `ip2region`, `notify`.
