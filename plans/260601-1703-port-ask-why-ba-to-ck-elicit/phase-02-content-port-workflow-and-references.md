# Phase 02 — Content Port: Workflow + References

## Context Links
- Plan overview: [plan.md](plan.md)
- Previous phase: [phase-01-skill-scaffold-and-frontmatter.md](phase-01-skill-scaffold-and-frontmatter.md)
- Source content already fetched (see compare report): `plans/reports/xia-compare-260601-1654-ask-why-ba-vs-local-skills-report.md`

## Overview
- **Priority:** P1 (the substance of the port)
- **Status:** Complete
- Port the 7-step workflow body into `SKILL.md` and populate the `references/` directory. **Audience pivot** applies here: rewrite BABOK labels to engineering-discovery labels, swap the question library, drop VI triggers.

## Key Insights
- Source preserves the *shape* (intent classifier → layer detection → gaps → Why → insight → edge cases → summary) — port that verbatim structurally.
- Source preserves the *discipline* (multi-turn enforcement, paraphrase-and-classify, never one-shot, max 3–5 questions/turn) — port that verbatim too.
- The substantive rewrite is the *vocabulary*: BABOK → engineering, EdTech → WAF/infra.
- "Solution Bias" intent flag is the source's most valuable callout — port verbatim, swap examples ("we need AI" → "we need Redis").

## Requirements

### Functional
1. `SKILL.md` body has all 7 steps with engineering-flavoured examples.
2. `references/detection-logic.md` — 10 intent types with engineering signal phrases.
3. `references/requirement-layers.md` — 5 engineering layers (Goal-Metric / Stakeholders / Functional / Non-functional-SLO / Rollout).
4. `references/question-library.json` — WAF/infra domains: rate-limit, bot-protection, tls-policy, observability, admin-panel-feature, config-migration, abuse-response.
5. `references/output-schema.json` — 10-field engineering findings JSON schema.
6. `templates/findings-summary.md` — Handlebars-style template for the findings deliverable.

### Non-functional
- Surgical port — preserve source's tone and rigour. Do not add features not in the source.
- All references readable standalone; no dangling links.

## Architecture

```
.claude/skills/ck-elicit/
├── SKILL.md                              ← 7-step workflow body (replaces Phase 1 placeholder)
└── references/
    ├── detection-logic.md                ← 10 intent types, engineering signals
    ├── requirement-layers.md             ← 5 engineering layers
    ├── question-library.json             ← WAF/infra starter questions
    └── output-schema.json                ← findings JSON schema
└── templates/
    └── findings-summary.md               ← findings markdown template
```

## Related Code Files

### Create
- `.claude/skills/ck-elicit/references/detection-logic.md`
- `.claude/skills/ck-elicit/references/requirement-layers.md`
- `.claude/skills/ck-elicit/references/question-library.json`
- `.claude/skills/ck-elicit/references/output-schema.json`
- `.claude/skills/ck-elicit/templates/findings-summary.md`

### Modify
- `.claude/skills/ck-elicit/SKILL.md` (add workflow body below frontmatter from Phase 1)

### Delete
- None.

## Layer Mapping (source → port)

| BABOK source layer | Engineering port layer | Owner |
|---|---|---|
| Business Requirement (why) | Goal & Metric (what KPI/SLO does this move?) | EM / Tech Lead / PM |
| Stakeholder Requirement (who) | Stakeholders & Operators (users / oncall / ops / SREs) | PM / SRE |
| Functional Requirement (what) | Functional behaviour (what the system must do) | Engineer |
| Non-functional Requirement (how well) | Non-functional / SLO (p99, RPS, blast radius, security posture) | SRE / Security |
| Transition Requirement (how to migrate) | Rollout & Rollback (feature flag, canary, fallback, migration) | Engineer / SRE |

## Intent Type Mapping (source → port)

| Source intent | Engineering analog | Example signal phrase |
|---|---|---|
| Feature Request | Feature Request | "add rate limiting", "we need bot detection" |
| Complaint | Incident / Pain Report | "p99 spiked", "false positives flooding" |
| Operational Pain | Operational Pain | "oncall manually clears IPs every shift" |
| Workaround | Workaround | "we currently maintain a hand-edited deny list" |
| KPI Goal | SLO/KPI Goal | "reduce malicious-request rate from X to Y" |
| **Solution Bias** ⚠️ | **Solution Bias** ⚠️ (verbatim — swap examples) | "we need Redis", "use Cloudflare Turnstile", "switch to eBPF" |
| Business Objective | Roadmap Objective | "Q3 OKR is to add zero-trust admin auth" |
| Process Issue | Workflow Issue | "rule deployment takes a full day" |
| Reporting Need | Observability Need | "need a dashboard for blocked-request reasons" |
| Compliance Concern | Compliance / Security Concern | "audit flagged unencrypted upstream", "PCI requires X" |

## Question Library Domains (port replaces source)

| Source domain | Port domain |
|---|---|
| EdTech / Digital School | Rate Limiting |
| Loyalty | Bot Protection |
| Reporting | Observability |
| Payment | TLS Policy (per-host ALPN, skip-verify, certs) |
| Approval | Admin Panel Feature |
| Notification | Config Migration (YAML / DB schema) |
| Integration | Abuse Response (deny-list, captcha, throttle) |

Each domain gets 4–6 starter questions targeting: business problem, affected segment, current behaviour, KPI/SLO target, edge cases, rollback path. **Adapt wording per context — library is a seed, not a script.** (Source's instruction preserved.)

## Implementation Steps

1. Append the 7-step workflow body to `SKILL.md`. Steps preserve source structure (Intent Detection → Layer Check → Gap Detection → Ask Why → Insight Extract → Edge Case Scan → Structured Summary). Examples rewritten to engineering domain.
2. Write `references/requirement-layers.md` with the 5 engineering layers (use the table above). Empty-layer signal text + "ask:" prompt per layer, same shape as source.
3. Write `references/detection-logic.md` — one section per intent type with engineering signal phrases and recommended first-response moves. Solution Bias gets the longest section with explicit warning callout (verbatim source warning, examples rewritten).
4. Write `references/question-library.json` — JSON object keyed by domain (rate-limit, bot-protection, observability, tls-policy, admin-panel-feature, config-migration, abuse-response). Each domain → array of {priority, question, targets-layer}.
5. Write `references/output-schema.json` — JSON Schema (draft-07) for findings: business_problem, goal_metric, stakeholders, current_behaviour, root_causes, edge_cases, constraints, success_metrics, non_functional, rollout_plan.
6. Write `templates/findings-summary.md` — Handlebars-style template matching the schema (mirror source's findings-summary.md shape).

## Todo
- [ ] SKILL.md workflow body appended, all 7 steps present
- [ ] Multi-turn enforcement language preserved ("Do NOT complete the whole loop in one response. Progress 1–2 stages per turn.")
- [ ] "Solution Bias" callout retained, examples rewritten
- [ ] 5 engineering layers documented
- [ ] 10 intent types documented
- [ ] Question library JSON valid + covers 7 domains
- [ ] Output schema JSON valid (draft-07) + 10 fields
- [ ] Findings template variables align with schema field names
- [ ] All references readable standalone (no broken links)

## Success Criteria
- `python3 -c "import json; json.load(open('.claude/skills/ck-elicit/references/question-library.json'))"` exits 0.
- `python3 -c "import json; json.load(open('.claude/skills/ck-elicit/references/output-schema.json'))"` exits 0.
- Manual read of SKILL.md confirms all 7 steps + multi-turn enforcement + Solution Bias warning.

## Risk Assessment
- **R1:** Engineering layer labels drift too far from BABOK → loses the rigour the source brought. Mitigation: keep the *shape* (5 layers, why/who/what/how-well/transition) and only rename.
- **R2:** Question library becomes outdated as mini-waf evolves. Mitigation: explicitly mark library as "seed, adapt per context" (source's own framing).
- **R3:** Schema and template drift apart. Mitigation: template field names must match schema keys verbatim.

## Security Considerations
- None — markdown + JSON only, no executable behaviour.

## Next Steps
- Phase 3 ports the 3 examples (rewritten to mini-waf domain), confirms attribution, and runs a smoke test.
