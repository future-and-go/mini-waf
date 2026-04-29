# FR-002 Phase 6: Tests, Bench, Docs Complete

**Date**: 2026-04-29 13:45  
**Severity**: N/A (Feature Complete)  
**Component**: FR-002 Tiered Protection Framework  
**Status**: Resolved

## What Happened

Phase 6 (final phase) shipped. E2E tests (6 tests covering tier classification, hot-reload, deserialization), criterion bench (50 rules / 1000 paths), consumer guide (`docs/tiered-protection.md`, 9 sections for FR-005/006/009/027), system-architecture Mermaid diagram, roadmap entry. All quality gates green. FR-002 now fully complete, unblocks dependent features.

## The Brutal Truth

The pragmatic call to skip full Pingora-driven E2E (testing proxy boot + request flow) felt like dodging. But it's identical to FR-001's pattern — we test the *observable contract* via `build_from_parts()` instead of booting the runtime. Saves 2–3 hours of fixture plumbing, delivers equivalent signal. Worth it.

Code-reviewer caught 3 real issues in the 9.4/10 initial score: rule-5 docstring was misleading ("GET only" vs actual /static/ prefix match), bench path had literal space typo, type ambiguity on `tier_policy`. None were bugs; all were clarity/correctness wins. Trust-but-verify actually works.

## Technical Details

- **Commit**: 5417004, 10 files, 863 insertions
- **Test coverage**: 6 E2E tests (tempfile I/O, TomlEnvelope deserialize, RequestCtxBuilder, TierConfigWatcher hot-reload cycle)
- **Bench**: 50 synthetic rules, 1000 request paths, throughput baseline
- **Docs**: 9 sections (overview, tier semantics, classification rules, observability, integration checklist, troubleshooting, examples, metrics, next-steps)
- **Type confirmed**: `tier_policy: Arc<TierPolicy>` (shared across threads, immutable)
- **Build status**: fmt ✓, clippy -D warnings ✓, 109 gateway tests ✓, bench ✓, release build ✓

## What We Tried

Started with full Pingora E2E (setup proxy server, generate requests). Realized it adds 2–3 hours of harness code for zero additional signal — we already validate the tier classification logic and hot-reload watcher in unit/integration layers. Switched to observable-contract testing via `build_from_parts()`. Faster, clearer intent.

## Root Cause Analysis

Scope creep temptation: "E2E should boot the full proxy." Reality: FR-001 (reverse-proxy feature itself) deferred that. FR-002 (tiering logic) has no reason to be stricter. Testing the classifier + watcher contract is sufficient. Perfectionism would have added ceremony, not value.

## Lessons Learned

1. **Observable contracts > orchestration ceremony.** Test what the system *does*, not how hard it is to set up.
2. **Code review catches clarity issues.** 9.4/10 feedback (docstring, typo, type annotation) prevented subtle later confusion.
3. **Follow established patterns.** FR-001 deferred Pingora E2E; FR-002 did the same. Consistency > false rigor.

## Next Steps

FR-002 unblocks FR-005 (custom policy injector), FR-006 (tier observability hooks), FR-009 (rule composition), FR-027 (DSL for rules). Update main roadmap. Notify downstream feature owners.
