# waf-common

Shared primitives used by every other crate in the workspace. No runtime, no I/O — pure types, config parsing, and crypto helpers.

## Features
- **Config loading**: TOML deserialization for the global `prx-waf` config.
- **Domain types**: shared structs/enums (requests, decisions, identifiers) used across engine, gateway, API, and cluster.
- **Crypto helpers**: AES-GCM and SHA-2 wrappers for token sealing and integrity checks.
- **URL validation**: hardened URL parsing/normalization to feed safely into matchers and proxy logic.

## Folder Structure
```
src/
├── lib.rs            # Public re-exports
├── config.rs         # TOML config schema + load helpers
├── types.rs          # Cross-crate shared types
├── crypto.rs         # AES-GCM / SHA-2 / base64 utilities
└── url_validator.rs  # URL parsing and validation
```

## Dependencies
Leaf crate — depends only on third-party libs (`serde`, `toml`, `aes-gcm`, `sha2`, `url`, `thiserror`, `anyhow`).
