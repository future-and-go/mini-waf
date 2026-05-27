# Tester Verification — pm_from_file matcher fix

**Date:** 2026-05-24 22:51
**Branch:** `feat/pm-from-file-matcher-fix`
**Commits verified:**
- `59fb6c1` test: pin pm_from_file/contains_any bug + snapshot detect_sqli/detect_xss
- `a08e2ea` feat(waf-engine): unify pm_from_file/contains_any dispatch through Condition pipeline

## Verdict: **PASS** (with one pre-existing failure scoped out — see Anomalies)

All scope-relevant verifications green. waf-engine 2032/0 matches dev-1's count exactly. The one workspace failure is in `waf-storage` (postgres testcontainer test, unchanged by this PR — confirmed pre-existing).

## Test Counts

| Command | Passed | Failed | Ignored |
|---|---|---|---|
| `cargo test -p waf-engine` | **2032** | **0** | 3 |
| `cargo test --workspace` | 3181 | **1** (unrelated, see below) | 1 |
| `cargo check --workspace` | — | 0 errors, 0 warnings (only known pingora-patch info msg) | — |
| `cargo fmt --all -- --check` | — | clean | — |

## Pinning test enumeration (`pm_from_file_pinning`, 9/9 green)

- `pin_dotenv_path_must_block` — ok
- `pin_dotenvrc_path_must_block` — ok
- `pin_dotenv_uppercase_must_block_case_insensitive` — ok (case-insensitive)
- `pin_dotenv_url_encoded_must_block` — ok (URL-decode `%2Eenv`)
- `pin_htpasswd_in_subpath_must_block` — ok
- `pin_lfi_os_file_in_body_must_block` — ok (/etc/passwd)
- `pin_contains_any_xss_payload_must_block` — ok
- `pin_contains_any_php_close_tag_must_block` — ok
- `pin_innocuous_path_must_pass` — ok

## Snapshot test enumeration (`sqli_xss_behavior_snapshot`, 16/16 green)

SQLi: `snap_sqli_single_field_query_skips_path`, `snap_sqli_single_field_query_match`, `snap_sqli_blocks_or_tautology`, `snap_sqli_blocks_union_select`, `snap_sqli_non_utf8_body_safe`, `snap_sqli_url_encoded_evasion`, `snap_sqli_checks_body`, `snap_sqli_checks_headers`, `snap_sqli_allows_clean_input`, `snap_sqli_empty_input_safe` — all ok.

XSS: `snap_xss_allows_clean_input`, `snap_xss_blocks_event_handler`, `snap_xss_empty_input_safe`, `snap_xss_blocks_script_tag`, `snap_xss_checks_body`, `snap_xss_url_encoded_evasion` — all ok. No DetectSqli/DetectXss drift.

## Grep guard (legacy dispatch removed)

`grep -rn "specialised_op\|eval_specialised\|is_specialised_operator" crates/waf-engine/src/` → **0 matches** (exit 1). Dual path fully deleted.

## Unwrap/expect audit

Per-line review of `git diff main..HEAD -- 'crates/waf-engine/src/**/*.rs'`: every new `.unwrap()` occurs inside a `#[cfg(test)]` module (test scaffolding in `data_file_registry.rs` and `data_file_resolver.rs`). **Zero new unwrap/expect in production code.** Seven Iron Rules compliant.

## Anomalies / Scope-Out

**`waf-storage::repo_hosts::invalid_remote_ip_errors` FAILS** (panic at `crates/waf-storage/tests/repo_hosts.rs:153` — assertion `invalid INET cast must error`).

- Pre-existing: `git diff main..HEAD -- crates/waf-storage/` is empty. This branch does not touch `waf-storage`.
- Root cause is in `waf-storage::create_host` accepting `"not-an-ip"` without erroring — unrelated to pm_from_file.
- Recommend filing a separate bug; **does not block this PR**.

`cargo check` emits one info line: `patch \`pingora v0.8.0 … was not used in the crate graph\`` — pre-existing vendored-pingora plumbing, not from this branch.

## Recommendation

Approve PR. Phase 1+2 cleanly: legacy dispatch removed, pinning tests cover the original bug (case-insensitive .env, URL-encoded .env, LFI /etc/passwd, contains_any XSS/PHP), snapshot tests freeze detect_sqli/detect_xss behavior, zero new unwraps in production paths, full waf-engine green.

## Unresolved Questions

- The `waf-storage::invalid_remote_ip_errors` failure should be triaged separately — is `remote_ip` actually cast through INET on insert, or is the test asserting a behavior that the repo code never implemented? Out of scope for this PR.
