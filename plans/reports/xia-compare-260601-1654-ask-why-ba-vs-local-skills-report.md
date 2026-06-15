# Feature Comparison: `ask-why-ba` (BABOK BA Elicitation Skill)

- **Source:** `phucnt-bazone-vietnam/product-discovery` (default branch HEAD; resolved at 2026-06-01)
- **Source artifact type:** Claude *skill* — markdown + JSON references, no executable code
- **Local project:** `mini-waf` — Rust WAF runtime (Pingora-based); `.claude/skills/` catalog hosts 89 skills
- **Mode:** `--compare` (no implementation plan)

---

## TL;DR

The source is a **discovery-first BA elicitation skill** that enforces BABOK 5-layer requirement classification before any solutioning. It targets Business Analysts / Product Owners working on vague stakeholder requests (EdTech, loyalty, payments, etc.), with bilingual EN/VI triggers.

The local project is a **Rust WAF runtime**. Its Claude skills catalog already has three conceptually adjacent skills — `ck:brainstorm`, `ck:ask`, `ck:ck-predict` — all oriented at **engineering** decisions, not **business** discovery.

There is **no feature overlap with mini-waf code**. The only honest comparison axis is "would this skill add value next to the existing utility skills?" — and the answer for a WAF infrastructure project is **no** (no BA workflow exists here to feed it). The skill is well-engineered for its target audience; that audience is not this repo.

---

## Source Anatomy

```
product-discovery/
├── SKILL.md                              (10.8 KB) — entry point, 7-step workflow
├── README.md                             (11.7 KB) — EN/VI marketing + usage
├── CHANGELOG.md
├── references/
│   ├── detection-logic.md                — intent classifier (10 types, signal phrases)
│   ├── requirement-layers.md             — BABOK v3 5-layer taxonomy
│   ├── question-library.json             — domain starter questions (EdTech / loyalty / payment / approval / reporting / notification / integration)
│   └── output-schema.json                — structured findings JSON schema
├── templates/
│   └── findings-summary.md               — handlebars-style BRD-ready output template
└── examples/
    ├── test-ai-feature-digital-school.md
    ├── test-certificate-digital-school.md
    └── test-mentor-booking-bazone.md
```

**Format:** standard Claude skill spec (YAML frontmatter + `references/` + `templates/` + `examples/`) — identical layout to skills already in `.claude/skills/`. License MIT.

**Core workflow (enforced multi-turn):**

```
Intent Detection → Requirement-Layer Check (BABOK) → Gap Detection (Known/Unknown table)
  → Ask 3–5 Why Questions → Insight Extraction (paraphrase + classify) → Edge Case Scan
  → Structured Findings Summary
```

**Operating principles:**
- Never accept feature requests at face value — treat named solutions as hypotheses.
- Never skip BABOK layers; visible layer-status table per turn.
- Max 3–5 questions per turn; never one-shot the whole workflow.
- "Solution Bias" intent is flagged as the **most dangerous and most common** failure mode.

---

## Local Project Surface

`mini-waf` is a Rust 2024 production WAF (CLAUDE.md "Seven Iron Rules", Pingora vendored, admin panel on `:16827`). The skills catalog is a generic ClaudeKit Engineer install — it has no project-specific BA tooling.

Already-installed skills with conceptual proximity:

| Local skill | Role | Overlap with `ask-why-ba` |
|---|---|---|
| `ck:brainstorm` | Engineering ideation, 2–3 alternatives, YAGNI/KISS/DRY trade-offs, HARD-GATE before implementation | Partial: covers "explore alternatives". **Does NOT** enforce BABOK layers, intent classification, or "discovery before solutioning". Engineering-flavoured. |
| `ck:ask` | Senior Systems Architect Q&A — boundaries, scalability, risk | None on requirements side. Answers technical questions, doesn't elicit business needs. |
| `ck:ck-predict` | 5-persona debate before risky changes (architecture/security/perf/UX) | None. Validates *a proposed change*, doesn't surface *whether the right problem is being solved*. |
| `ck:ck-scenario` | Edge-case generation across 12 dimensions | Partial: covers `ask-why-ba` Step 6 (edge case scan) more rigorously, but only after a feature exists. |
| `ck:plan`, `ck:cook` | Plan → implement pipeline | None on the BA side. Assumes requirements already exist. |

**Integration surface:** dropping the skill in would mean `cp -r product-discovery/ .claude/skills/ask-why-ba/` and trusting the existing skill-loader; no code changes, no migrations, no Rust impact.

---

## Head-to-Head

| Aspect | Source (`ask-why-ba`) | Local (existing skills) | Note |
|---|---|---|---|
| **Domain** | Business Analysis / Product Discovery | Software engineering | Disjoint |
| **Discipline backbone** | BABOK v3 (formal IIBA framework) | YAGNI / KISS / DRY (ad-hoc software trinity) | Different rigour traditions |
| **Audience** | BAs, POs, founders, Vietnam/SEA Digital School community | Software engineers | Disjoint |
| **Trigger surface** | Vague business statements, EN + VI ("tôi muốn làm", "cần xây dựng", "stakeholder muốn") | Technical/architectural prompts | No VI triggers locally |
| **Anti-pattern targeted** | Solution Bias — user names a tool as the "requirement" | Premature implementation without trade-off review | Both fight premature-solutioning but at different layers |
| **Output** | 13-field findings summary handlebars template, BRD/PRD-ready | Design recommendations, decision matrices | Source produces a deliverable artifact |
| **Conversation cadence** | Forced multi-turn (3–5 questions / turn, paraphrase-and-classify after each answer) | `brainstorm` HARD-GATE before implementation; `ask` is one-shot | Source is structurally stricter |
| **Domain starter library** | EdTech / loyalty / payment / approval / reporting / notification / integration | None | Source ships a question bank |
| **Output schema** | JSON schema in `references/output-schema.json` | Free-form markdown | Source is machine-consumable |
| **License** | MIT | Mixed (most ClaudeKit) | Compatible |
| **Code touched in mini-waf** | Zero | N/A | Skill is data-only |

---

## Trade-offs & Risks

**If installed locally:**
- ✅ Zero blast radius — markdown skill, no Rust touched, no runtime cost.
- ✅ Adds a missing capability *in principle* (no other local skill does BABOK layer detection or Vietnamese-language BA elicitation).
- ⚠️ **No fit with mini-waf's actual work.** WAF features are driven by RFC/CVE/perf concerns, not BA stakeholder elicitation. The skill's triggers ("we need an AI feature", "khách hàng yêu cầu") would essentially never fire here.
- ⚠️ Vocabulary collision: source's `name: ask-why-ba` would sit alongside `ck:ask`, `ck:brainstorm`, `ck:ck-predict` — three already-overloaded "thinking before doing" skills. Discoverability cost > value.
- ⚠️ Source frames itself as a Senior BA Copilot; loading it in a security/infra context risks the skill's prompt patterns (BABOK tables, layer-status displays) leaking into unrelated engineering conversations.

**If ported (rewritten for engineering):**
- 🟡 The *idea* — enforce a multi-turn discovery loop with a layered checklist before solutioning — is sound and could improve `ck:brainstorm`'s HARD-GATE. But that's a `ck:brainstorm` enhancement, not a fresh skill, and it doesn't need this source as a dependency. YAGNI says don't.

**If used as inspiration only (recommended for this repo):**
- ✅ The two reusable patterns worth noting in `ck:brainstorm`:
  1. **Visible layer-status table per turn** — a forcing function that keeps unfilled gaps visible.
  2. **Intent classifier with "Solution Bias" callout** — flagging when the user names a tool as the requirement.
- These are pattern-level borrows, not file-level ports.

---

## Recommendation

**Do not install, do not port.** mini-waf has no BA workflow to feed it; the existing `ck:brainstorm` / `ck:ask` / `ck:ck-predict` trio already covers the engineering side of "think before coding" (which is exactly the Karpathy guardrail in CLAUDE.md).

**If** the user has a separate project (not mini-waf) where they do product discovery / BRD work — especially in Vietnamese or EdTech contexts — `ask-why-ba` is well-built and worth installing **there**. It is a clean, BABOK-grounded skill from a credible BA community author (Phúc NT, BA Zone) with MIT license, examples, and a JSON output schema.

For mini-waf specifically: **note the two patterns above** if `ck:brainstorm` ever gets revised; otherwise, no action.

---

## Decision Matrix

| Decision | Source's way | mini-waf's way | Recommendation |
|---|---|---|---|
| Pre-solution discipline | BABOK 5-layer + intent classifier + Why-questions | `brainstorm` HARD-GATE + `ask` Q&A + Karpathy guardrails | Keep local — already adequate for engineering work |
| Multi-turn discovery | Enforced (3–5 q / turn, paraphrase + classify) | Optional (`brainstorm` asks questions but doesn't enforce cadence) | Local is fine for engineering; source's rigour is BA-shaped |
| Domain question library | EdTech / loyalty / payment / etc. JSON | None | Not needed for WAF work |
| Output artifact | Findings summary template (BRD-ready) | Free-form recommendations | Local is fine; no BRD audience here |
| Install the skill? | — | — | **No** |
| Port the skill? | — | — | **No** |

---

## Risk Score

**Adoption risk if installed:** Low (data-only, no runtime impact).
**Value risk if installed:** High (zero fit with mini-waf's actual workload → catalog clutter, dilutes "skill space" for skills that actually fire).
**Net:** decline.

---

## Unresolved Questions

- Was the user expecting comparison against the **mini-waf Rust runtime** (no overlap exists) or against the **local skills catalog** (this report's framing)? If the former, the answer is "completely unrelated domains; no comparison possible".
- Is there a separate project where `ask-why-ba` would actually be used? If yes, the install verdict flips to **yes — clean install, MIT, no migration needed**.
