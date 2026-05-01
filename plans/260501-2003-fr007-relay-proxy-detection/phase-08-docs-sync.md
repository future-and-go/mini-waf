# Phase 08 — Documentation Sync

## Context Links
- Design: brainstorm §8 (docs-impact list)
- Pipeline change: phase-06 (request flow + FR-008 handover)
- Rule predicate additions: phase-06

## Overview
**Priority:** P1 · **Status:** pending · **Effort:** 0.5 d

Update `docs/` after FR-007 lands. Document new module, request-pipeline insertion, custom-rule predicates, intel-feed deployment, and any new patterns introduced (mainly `IntelProvider` async-refresh).

## Key Insights
- Touch surgical — only sections affected by FR-007.
- Add a dedicated `docs/relay-detection.md` (new) cross-linked from the four existing docs.
- Update FR-008 caveat in `docs/access-lists.md` — XFF caveat now resolved.
- Sample YAML lives in `rules/relay-detection.yaml` (operator-editable starter).

## Requirements

### Functional
- `docs/system-architecture.md` — add Relay subsystem block in architecture diagram + 1-paragraph description.
- `docs/request-pipeline.md` — insert `RelayDetector` between header-parse and Phase-0 access (FR-008).
- `docs/custom-rules-syntax.md` — document `signal:`, `asn_class:`, `chain_depth:` predicate kinds w/ examples.
- `docs/deployment-guide.md` — section: intel feed setup (IPinfo Lite mmdb URL + ETag, Tor list URL, X4BNet optional, operator override YAML, air-gap mode).
- `docs/code-standards.md` — IF `IntelProvider` async-refresh is a new pattern, document under "Async refresh tasks" section. Skip if not novel.
- `docs/relay-detection.md` (new) — module-level guide, signals catalog, fail-close semantics, hot-reload behavior.
- `docs/development-roadmap.md` — mark FR-007 status `In Progress` → `Complete` after merge.
- `docs/project-changelog.md` — entry under current release.
- `rules/relay-detection.yaml` — sample operator config matching brainstorm §4.6.

### Non-functional
- No drive-by edits to unrelated doc sections.
- Cross-references valid (no broken links).

## Related Code Files

### Create
- `docs/relay-detection.md`
- `rules/relay-detection.yaml`
- `rules/threat-intel/hyperscaler-asn-seed.yaml` (created in phase-03; verify presence)
- `rules/threat-intel/operator-overrides.yaml.example` (template)

### Modify
- `docs/system-architecture.md`
- `docs/request-pipeline.md`
- `docs/custom-rules-syntax.md`
- `docs/deployment-guide.md`
- `docs/access-lists.md` — remove FR-007 caveat
- `docs/development-roadmap.md`
- `docs/project-changelog.md`
- `docs/code-standards.md` (only if new pattern)

## Implementation Steps

1. Draft `docs/relay-detection.md` covering: overview, signals catalog (with risk_score_delta defaults), config reference, intel feeds, hot-reload, fail-close, troubleshooting, performance budget.
2. Insert Relay block in `system-architecture.md` diagram + paragraph.
3. Update `request-pipeline.md` step list with detector position.
4. Add predicate examples to `custom-rules-syntax.md`:
   ```yaml
   - id: block-tor-on-critical
     when:
       all:
         - tier: critical
         - signal: tor_exit
     action: block
   - id: extra-rate-limit-datacenter
     when: { asn_class: datacenter }
     action: rate_limit
   - id: deep-chain-warn
     when: { chain_depth: ">3" }
     action: log
   ```
5. Add deployment-guide section: feed file paths, refresh URLs, ETag, air-gap mode, operator override format.
6. Update `access-lists.md` — replace FR-007 TODO caveat with "now resolved by FR-007".
7. Verify `rules/relay-detection.yaml` matches brainstorm §4.6 exactly + comments.
8. Update changelog + roadmap status.
9. Run docs link-check (manual or via existing tool).

## Todo List
- [ ] `docs/relay-detection.md` written
- [ ] `system-architecture.md` updated
- [ ] `request-pipeline.md` updated
- [ ] `custom-rules-syntax.md` updated
- [ ] `deployment-guide.md` updated
- [ ] `access-lists.md` caveat removed
- [ ] `code-standards.md` updated (if novel pattern)
- [ ] `development-roadmap.md` status flipped
- [ ] `project-changelog.md` entry
- [ ] `rules/relay-detection.yaml` sample
- [ ] `rules/threat-intel/operator-overrides.yaml.example`
- [ ] Link-check pass

## Success Criteria
- All listed docs updated with FR-007 references.
- Sample YAML loads cleanly via `RelayConfig::from_yaml_path` in a smoke test.
- No broken links in modified docs.
- Roadmap reflects FR-007 complete; changelog has dated entry.

## Common Pitfalls
- Forgetting `access-lists.md` caveat removal — FR-008 doc still says "XFF deferred to FR-007".
- Sample YAML drifts from brainstorm §4.6 — copy verbatim then add comments.

## Risk Assessment
Low.

## Security Considerations
- Don't include real license keys in samples.
- Operator override examples use placeholder ASNs only.

## Next Steps
None — FR-007 complete. Future: RFC 7239 `Forwarded` header provider as additive ticket (per brainstorm §10 Q3).
