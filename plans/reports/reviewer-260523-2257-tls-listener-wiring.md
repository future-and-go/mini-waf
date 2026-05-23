# Code Review — FR-040b TLS Listener Wiring

**Files reviewed:** `crates/waf-common/src/config.rs`, `crates/prx-waf/src/main.rs`, `configs/default.toml`, `crates/waf-common/tests/config_defaults.rs`, `crates/waf-common/tests/config_tls_validation.rs`
**cargo check:** clean (0 warnings, 0 errors)
**Tests:** 23/23 pass (config_tls_validation: 6, config_defaults: 17)

---

## Findings

### [IMPORTANT] Self-signed key written world-readable with no file permission restriction

`ensure_self_signed_cert()` at `main.rs:1468-1469` calls `std::fs::write(&key_path, &key_pem)` without setting restrictive permissions. On Linux this creates the key with the process umask, typically `0644` (world-readable). A private key file should be `0600` (owner-only).

**Evidence:** `main.rs:1468` — no `set_permissions` call follows the write. Compare with `run_cert_init()` at `main.rs:874-875` which has the same pattern.

**Recommendation:** After writing the key, call:
```rust
#[cfg(unix)]
{
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to restrict key permissions: {}", key_path.display()))?;
}
```

---

### [IMPORTANT] Config load failure silently falls back to defaults, masking a broken TLS config

`main.rs:320-323` — `load_config()` is wrapped in `unwrap_or_else(|e| AppConfig::default())`. If the operator sets `tls_cert_pem` / `tls_key_pem` in the TOML but the file is malformed (TOML parse error, or the new TLS fields cause a conflict), the process starts with `AppConfig::default()` — meaning `tls_cert_pem = None`, triggering the self-signed fallback path silently. The warning log is there but the operator gets no startup failure, only a subtly wrong certificate.

**Evidence:** `main.rs:320-322`; `load_config` validation only runs on success path.

**Recommendation:** For `Commands::Run`, fail-fast on config errors rather than silently defaulting. The fallback is reasonable for CLI sub-commands (migrate, seed-admin) but not for the serving path. Consider checking `if matches!(cli.command, Commands::Run)` before falling back.

---

### [MODERATE] Self-signed cert directory coupled to GeoIP xdb path — silent mismatch on config change

`main.rs:1404-1408` — the fallback `data_dir` for `ensure_self_signed_cert` is derived from `config.geoip.ipv4_xdb_path`. If the operator changes `geoip.ipv4_xdb_path` to a new directory, the self-signed cert moves to `<new_dir>/tls/`, while the binary previously searched `<old_dir>/tls/`. The cert is always regenerated (no reuse), but the coupling is non-obvious and the old cert is left as an orphan.

**Evidence:** `main.rs:1404-1407` — `PathBuf::from(&config.geoip.ipv4_xdb_path).parent()`.

**Recommendation:** Use a fixed fallback path (e.g. `data/tls/`) independent of GeoIP configuration, or document the coupling explicitly.

---

### [MODERATE] File-existence check is redundant and TOCTOU-prone

`main.rs:1412-1417` checks `Path::exists()` for cert and key before calling `TlsSettings::intermediate()` at `main.rs:1419-1420`. `TlsSettings::intermediate` already returns an error if the files are missing or unreadable. The explicit existence check adds a TOCTOU window (file could be deleted between check and open) and duplicates the error handling. The `context()` on the `TlsSettings` call provides a better error message.

**Evidence:** `main.rs:1412-1420` — two consecutive failure paths for the same condition.

**Recommendation:** Remove the `exists()` guard and let `TlsSettings::intermediate` report the error. The `.context()` message already covers this case.

---

### [MODERATE] TLS address used for `add_tcp` and `add_tls_with_settings` is correct but easy to misread

`main.rs:1398` adds TCP on `listen_addr` (port 80); `main.rs:1423` adds TLS on `listen_addr_tls` (port 443). This is correct. But `add_tls_with_settings` takes `listen_addr_tls` while the second arg (SNI) is `None` — which means all SNI names are accepted. For a WAF, accepting any SNI may silently serve the self-signed cert to domains the operator did not intend to terminate TLS for.

**Evidence:** `main.rs:1423` — `proxy_service.add_tls_with_settings(&config.proxy.listen_addr_tls, None, tls_settings)`.

**Recommendation:** Informational only at this stage; SNI wildcard is an acceptable WAF default. Worth a comment explaining the intent.

---

## Positive Observations

- `resolve_tls_paths()` correctly enforces the cert+key pair invariant with a clean `anyhow::bail!` — no partial TLS state possible from config alone.
- `TlsSettings::enable_h2()` called before `add_tls_with_settings` — ALPN ordering is correct.
- `server.add_service(proxy_service)` is called after both `add_tcp` and `add_tls_with_settings` — wiring order is correct.
- Error propagation throughout: no `.unwrap()` in the new TLS paths, all use `?` with `.context()`.
- Self-signed cert reuse check (`cert_path.exists() && key_path.exists()`) prevents unnecessary regeneration on restart.
- Test coverage is solid for the config layer; all 6 TLS validation tests cover the meaningful branches.

---

## Missing Test Coverage

- No test for `ensure_self_signed_cert()` itself (cert regeneration, reuse path, directory creation failure). This is an I/O-heavy function that would benefit from at least an integration-style test with a temp dir.
- No test asserting that `Commands::Run` with a broken config file fails fast (rather than falling back silently).
