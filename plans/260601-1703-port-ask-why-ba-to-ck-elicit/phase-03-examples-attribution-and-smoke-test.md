# Phase 03 — Examples, Attribution, and Smoke Test

## Context Links
- Plan overview: [plan.md](plan.md)
- Previous phase: [phase-02-content-port-workflow-and-references.md](phase-02-content-port-workflow-and-references.md)

## Overview
- **Priority:** P2 (validation + completeness)
- **Status:** Complete
- Port the 3 source examples into mini-waf-shaped scenarios, confirm MIT attribution, and run a smoke test by invoking `/ck:elicit` on a deliberately under-specified WAF feature ask.

## Key Insights
- Source examples (AI feature for Digital School / certificate workflow / mentor booking) demonstrate the workflow on **realistic vague asks** — same demonstrative role needed locally with engineering scenarios.
- Smoke test is the only way to catch frontmatter / trigger mistakes before merge — `cargo check` and the Rust test suite are irrelevant here.

## Requirements

### Functional
1. 3 example transcripts under `examples/`, each demonstrating a different intent type (one must be Solution Bias).
2. README-style attribution paragraph in `SKILL.md` body footer crediting source author.
3. Smoke test: invoke `/ck:elicit` on a sample vague ask and confirm the skill fires, classifies intent, and asks ≤5 Why questions.

### Non-functional
- Examples short (~80–120 lines each), realistic, easy to skim.
- License compatibility documented.

## Architecture

```
.claude/skills/ck-elicit/examples/
├── rate-limit-vague-ask.md                ← demonstrates Feature Request intent
├── solution-bias-redis-rate-limit.md      ← demonstrates Solution Bias intent
└── tls-policy-compliance-driven.md        ← demonstrates Compliance Concern intent
```

## Related Code Files

### Create
- `.claude/skills/ck-elicit/examples/rate-limit-vague-ask.md`
- `.claude/skills/ck-elicit/examples/solution-bias-redis-rate-limit.md`
- `.claude/skills/ck-elicit/examples/tls-policy-compliance-driven.md`

### Modify
- `.claude/skills/ck-elicit/SKILL.md` (append attribution footer)

### Read for context
- Source examples (already fetched into compare-phase memory): test-ai-feature-digital-school, test-certificate-digital-school, test-mentor-booking-bazone

### Delete
- None.

## Example Mappings (source → port)

| Source example | Port example | Demonstrates |
|---|---|---|
| test-ai-feature-digital-school | `rate-limit-vague-ask.md` — "we need rate limiting" | Feature Request, gap detection across all 5 layers |
| test-certificate-digital-school | `tls-policy-compliance-driven.md` — "audit flagged unencrypted upstream" | Compliance Concern, working backwards from constraint |
| test-mentor-booking-bazone | `solution-bias-redis-rate-limit.md` — "let's use Redis for rate limiting" | Solution Bias (the most-valuable callout), redirect to underlying problem |

## Implementation Steps

1. Write each example transcript as a multi-turn dialogue between user and `ck:elicit`. Each example must include:
   - Initial vague user ask
   - Intent classification output
   - Requirement-layer status table
   - Known/Unknown gap table
   - 3–5 Why questions in the first turn
   - User response + paraphrase-back + classification
   - Stop point: not all turns to completion (mirrors source's brevity)
2. Append attribution footer to `SKILL.md`:
   ```markdown
   ---

   ## Attribution

   Adapted from **Ask Why — BA Elicitation Skill** by Phúc NT, BA Zone (bazone.org).
   Original under MIT, available at https://github.com/phucnt-bazone-vietnam/product-discovery.
   This port keeps the workflow shape and discipline; the vocabulary, layer labels,
   question library, and examples have been rewritten for engineering / infrastructure
   discovery (mini-waf domain).
   ```
3. Add an `MIT-source-LICENSE-NOTICE.md` (or note inline in attribution footer) — confirm MIT requires only credit, no separate file mandated, but a one-paragraph notice is best-practice. (Decide: inline footer alone is sufficient under MIT; skip a separate notice file.)
4. **Smoke test:**
   - Invoke `/ck:elicit "we need bot protection"` (or simulate equivalent prompt loading).
   - Verify the skill loads (no YAML parse error), classifies the intent, displays a layer-status table, and asks ≤5 questions.
   - Verify the skill does NOT one-shot a complete BRD-style document.

## Todo
- [ ] 3 examples written under `examples/`
- [ ] Each example demonstrates a distinct intent type
- [ ] Solution Bias example explicit
- [ ] Attribution footer present in SKILL.md
- [ ] Smoke test passes: skill loads, classifies intent, asks ≤5 questions, does not one-shot
- [ ] No regression — other skills still load (grep for `ck:elicit` collisions, none expected)

## Success Criteria
- `find .claude/skills/ck-elicit -type f | wc -l` ≥ 8 (SKILL.md + 4 refs + 1 template + 3 examples).
- All JSON files in `references/` parse cleanly.
- Manual smoke test produces expected multi-turn output for at least one vague-ask example.
- `git status` shows only files under `.claude/skills/ck-elicit/` + the plan dir; no incidental edits.

## Risk Assessment
- **R1:** Examples too long → reader fatigue. Mitigation: cap each at ~120 lines.
- **R2:** Smoke test passes but skill silently shadows `ck:brainstorm` in real use. Mitigation: revisit `when_to_use` wording in Phase 1 if observed during smoke test.
- **R3:** Attribution wording understates source author's contribution. Mitigation: name + project + URL + MIT, exactly as in source's README.

## Security Considerations
- Confirm no source content includes secrets, API keys, or credentials before vendoring. (Skill content reviewed in Phase 0 / compare — clean.)

## Next Steps
- Optional: open a follow-up to add a `ck:elicit --output-json` flag if the smoke test reveals demand for machine-readable findings. Not in scope here (YAGNI).
- Run `/ck:cook plans/260601-1703-port-ask-why-ba-to-ck-elicit/plan.md` to execute the 3 phases.
