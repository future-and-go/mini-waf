# Port: `ask-why-ba` → `ck:elicit` (engineering-discovery skill)

> Source: `phucnt-bazone-vietnam/product-discovery` (MIT, by Phúc NT / BA Zone)
> Mode: `--port` — idiomatic rewrite for the local Claude skills catalog
> Plan dir: `plans/260601-1703-port-ask-why-ba-to-ck-elicit/`

## Goal

Port the source's BABOK-grounded discovery loop into a ClaudeKit-conventional skill (`ck:elicit`) tuned for **mini-waf's domain**: WAF/infra/security feature requests that arrive as vague engineering asks ("we need rate limiting", "add bot protection", "improve TLS handshake"). Preserve the source's discipline (intent classification → layer detection → Why questions → structured findings) and rewrite content for the engineering audience.

## Audience pivot (the load-bearing decision)

| Source | Port target |
|---|---|
| Business Analysts / POs | mini-waf engineers, ops, security |
| BABOK v3 5-layer requirement taxonomy | Engineering 5-layer adaptation (see Challenge section) |
| EdTech / loyalty / payment domain question library | WAF / infra / security domain question library |
| EN + VI triggers | EN only (matches existing ck:* skills) |
| 13-field BRD findings summary | 10-field engineering requirements summary |
| Targets "Solution Bias" (tech named as requirement) | Targets same anti-pattern in engineering form ("we need Redis", "use Cloudflare Turnstile") |

## Challenge (hard gate — must clear before implementation)

| # | Question | Source's answer | Local answer | Risk if wrong |
|---|---|---|---|---|
| C1 | Does mini-waf actually generate vague feature asks that need elicitation? | n/a | Yes — admin-panel features, anti-abuse modules, observability work routinely arrive under-specified. WAF rule changes carry real ops risk if scope is unclear. | Skill never fires → catalog clutter. |
| C2 | Should the BABOK 5-layer taxonomy be preserved or rewritten? | Preserved | **Rewritten.** Engineering analog: Goal/Metric → Stakeholders → Functional → Non-functional (perf/security/SLO) → Transition (rollout/migration/rollback). Same shape, different labels. | Faithful port = looks like a BA tool engineers will skip. |
| C3 | Keep "Solution Bias" intent flag? | Yes — most dangerous BA failure mode | **Yes — direct engineering analog** ("we need Redis" = solution-as-requirement). High-value pattern, port verbatim with engineering examples. | Losing this drops the source's most valuable callout. |
| C4 | Keep VI bilingual triggers? | Yes | **No.** Existing `.claude/skills/` are EN-only; mixing triggers risks misfires. Note the source's VI heritage in attribution. | Skill activates on Vietnamese text in unrelated contexts. |
| C5 | Replace or keep the domain question library? | EdTech / loyalty / payment / approval / reporting / notification / integration | **Replace.** New domains: rate-limit / bot-protection / TLS-policy / observability / admin-panel-feature / config-migration / abuse-response. | Keeping EdTech examples confuses engineers; skill feels foreign. |
| C6 | Does this overlap dangerously with `ck:brainstorm` and `ck:ck-predict`? | n/a | Partial overlap, distinct timing: `ck:elicit` runs *before* a problem is well-defined; `ck:brainstorm` runs *after* problem is known to explore solutions; `ck:ck-predict` runs *after* a change is proposed to red-team it. Document the sequence in `when_to_use`. | Three skills compete for the same trigger → none fire reliably. |
| C7 | Attribution and license? | MIT, by Phúc NT / BA Zone | Keep MIT, credit source in `metadata.attribution` (same pattern as `ck:scenario` which credits autoresearch). | Stripping credit violates MIT. |

**Approved decisions:** rewrite layer labels (C2), keep Solution Bias verbatim (C3), drop VI (C4), replace question library (C5), document timing vs `ck:brainstorm`/`ck:ck-predict` (C6), attribute MIT source (C7).

## Decision matrix

| Decision | Source's way | Local idiom | Recommendation |
|---|---|---|---|
| Skill name | `ask-why-ba` | `ck:` prefix, short verb | `ck:elicit` |
| Frontmatter | `name/description/author/website/license/version` | `name/description/user-invocable/when_to_use/category/keywords/argument-hint/license/metadata` | Use ClaudeKit shape |
| File layout | `SKILL.md` + `references/` + `templates/` + `examples/` | Identical | Keep |
| Workflow steps | 7 steps, multi-turn enforced | Keep 7 steps, keep multi-turn enforcement | Preserve |
| Output schema | JSON schema + Handlebars MD template | Keep both | Preserve |
| Trigger language | EN + VI | EN only | Drop VI |
| Question library | EdTech / loyalty / payment / approval / reporting / notification / integration | WAF / bot / TLS / observability / admin / config / abuse | Replace |
| Layer labels | Business / Stakeholder / Functional / Non-functional / Transition | Goal-Metric / Stakeholders / Functional / Non-functional-SLO / Rollout | Rewrite |

## Risk score

**Adoption risk:** Low — data-only markdown, no Rust touched, no runtime cost, no migration.
**Value risk:** Medium — depends on whether engineers actually invoke `/ck:elicit` for under-specified WAF features. Mitigation: `when_to_use` clearly carves the slot before `ck:brainstorm`.
**Net:** acceptable. Proceed.

## Phases

| # | File | Status |
|---|---|---|
| 1 | [phase-01-skill-scaffold-and-frontmatter.md](phase-01-skill-scaffold-and-frontmatter.md) | Complete |
| 2 | [phase-02-content-port-workflow-and-references.md](phase-02-content-port-workflow-and-references.md) | Complete |
| 3 | [phase-03-examples-attribution-and-smoke-test.md](phase-03-examples-attribution-and-smoke-test.md) | Complete |

## Key dependencies

- ClaudeKit skill spec: `.claude/skills/agent_skills_spec.md`
- Reference frontmatter shape: `.claude/skills/ck-plan/SKILL.md`, `.claude/skills/ck-scenario/SKILL.md` (especially attribution metadata)
- Existing overlap to disambiguate from: `ck:brainstorm`, `ck:ask`, `ck:ck-predict`, `ck:ck-scenario`
- Source content (already fetched, no re-fetch needed): see compare report `plans/reports/xia-compare-260601-1654-ask-why-ba-vs-local-skills-report.md`

## Source manifest

- Repo: `phucnt-bazone-vietnam/product-discovery`
- Branch: default (HEAD at 2026-06-01)
- License: MIT
- Author: Phúc NT, BA Zone (bazone.org)
- Scope: entire skill (SKILL.md + 4 references + 1 template + 3 examples)

## Handoff

When phases complete, run `/ck:cook plans/260601-1703-port-ask-why-ba-to-ck-elicit/plan.md`.
