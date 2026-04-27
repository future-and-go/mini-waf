# SQLi Modularization: Phase 01 Complete

**Date**: 2026-04-23
**Severity**: Medium
**Component**: waf-engine, SQL injection detection
**Status**: Resolved

## What Happened

Split monolithic `sql_injection.rs` (170 lines) into three focused modules and added 7 new blind/error-based injection patterns. All tests pass.

## Technical Details

- **sql_injection_patterns.rs** (149 lines): 19 total patterns with descriptions
- **sql_injection.rs** (114 lines): Check logic, now readable
- **sql_injection_scanners.rs** (8 lines): Skeleton for Phase 02+ extensions
- **New patterns**: SQLI-013..019 cover numeric tautology, blind data-extraction (SUBSTRING/ASCII/LENGTH), conditional IF(), database fingerprinting (@@version), error-based CAST/CONVERT, DOUBLE overflow
- **ReDoS mitigations**: Bounded `\s{0,10}`, `{1,128}?` limits
- **Regex errors**: Changed from silent fallback to `expect()` — forces compile-time visibility of malformed patterns
- **Tests**: All 142 waf-engine tests pass

## Root Cause of Original Issue

Single file combined pattern data, scanner logic, and integration. Hard to extend safely — pattern changes risked breaking the scanner.

## Lessons Learned

Modularization at 170 lines was premature; waited until we had a real reason (pattern explosion). Bounded quantifiers caught during implementation — easy miss without automated ReDoS linting.

## Next Steps

Phase 02: Add `SqlInjectionScanner` trait, implement specialized scanners (timing, inference). Coordinate with pattern owners before adding more patterns.

Commit: d7acbc7
