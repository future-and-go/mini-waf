# Phase 01 — Skill Scaffold and Frontmatter

## Context Links
- Plan overview: [plan.md](plan.md)
- ClaudeKit skill spec: `.claude/skills/agent_skills_spec.md`
- Reference frontmatter: `.claude/skills/ck-scenario/SKILL.md` (attribution pattern), `.claude/skills/ck-plan/SKILL.md` (argument-hint pattern)
- Source: `https://github.com/phucnt-bazone-vietnam/product-discovery`

## Overview
- **Priority:** P1 (foundation for phases 2–3)
- **Status:** Complete
- Create the directory skeleton for `ck:elicit` under `.claude/skills/` and the SKILL.md with ClaudeKit-conventional frontmatter. No content yet — that lands in Phase 2.

## Key Insights
- Source uses `name: ask-why-ba` and a bespoke frontmatter shape; local convention is `name: ck:elicit` plus `user-invocable / when_to_use / category / keywords / argument-hint / metadata.{author,version,attribution}`.
- `name` must equal the directory name (per Agent Skills Spec) — but the local convention prefixes `ck:` in the `name` field while the directory itself uses `ck-elicit` (e.g., `.claude/skills/ck-scenario/` has `name: ck:scenario`). Mirror that.
- Source frontmatter description is multi-paragraph; ClaudeKit description is a single quoted line. Compress aggressively.

## Requirements

### Functional
1. Directory `.claude/skills/ck-elicit/` exists with subdirs `references/`, `templates/`, `examples/`.
2. `SKILL.md` exists with valid YAML frontmatter that passes the loader (same fields as `ck:scenario`).
3. `when_to_use` makes it clear when to pick `ck:elicit` vs `ck:brainstorm` vs `ck:ck-predict`.
4. MIT license attribution to Phúc NT / BA Zone in `metadata.attribution`.

### Non-functional
- Single source of truth — no duplicate skill names across catalog.
- Triggers must not collide with existing skills (grep current `when_to_use` lines for conflicts before finalising).

## Architecture

```
.claude/skills/ck-elicit/
├── SKILL.md                ← frontmatter + 7-step workflow (workflow body lands Phase 2)
├── references/
├── templates/
└── examples/
```

## Related Code Files

### Create
- `.claude/skills/ck-elicit/SKILL.md`
- `.claude/skills/ck-elicit/references/` (empty dir for Phase 2)
- `.claude/skills/ck-elicit/templates/` (empty dir for Phase 2)
- `.claude/skills/ck-elicit/examples/` (empty dir for Phase 2)

### Read for context
- `.claude/skills/ck-scenario/SKILL.md` (attribution pattern in `metadata`)
- `.claude/skills/ck-plan/SKILL.md` (argument-hint pattern)
- `.claude/skills/brainstorm/SKILL.md` (to differentiate `when_to_use`)
- `.claude/skills/ck-predict/SKILL.md` (to differentiate `when_to_use`)

### Modify
- None.

### Delete
- None.

## Implementation Steps

1. Verify no existing `ck-elicit` or `elicit` directory under `.claude/skills/` (collision check):
   ```bash
   ls .claude/skills/ | grep -i elicit
   ```
2. Create the directory skeleton:
   ```bash
   mkdir -p .claude/skills/ck-elicit/{references,templates,examples}
   ```
3. Write `.claude/skills/ck-elicit/SKILL.md` with frontmatter:
   ```yaml
   ---
   name: ck:elicit
   description: "Discovery-first elicitation skill for vague engineering feature asks. Detects intent, classifies requirement layers (goal/stakeholders/functional/non-functional/rollout), surfaces gaps, asks 3–5 targeted Why questions per turn, produces a structured findings summary."
   user-invocable: true
   when_to_use: "Invoke BEFORE ck:brainstorm when a feature ask is vague, names a tool as the requirement, or skips business/goal/SLO context. Sequence: ck:elicit (uncover problem) → ck:brainstorm (explore solutions) → ck:ck-predict (red-team chosen approach) → ck:plan."
   category: utilities
   keywords: [discovery, elicitation, requirements, why-questions, intent, gaps]
   argument-hint: "[feature-ask-or-blank] [--fast]"
   license: MIT
   metadata:
     author: claudekit-ported
     attribution: "Adapted from ask-why-ba by Phúc NT, BA Zone (bazone.org). MIT. Original: github.com/phucnt-bazone-vietnam/product-discovery."
     version: "1.0.0"
   ---
   ```
4. Below the frontmatter, write a placeholder `# ck:elicit` heading and a one-line "see Phase 2" marker (the full workflow body lands in Phase 2 to keep this phase atomic).

## Todo
- [ ] Collision check passes (`grep -i elicit` returns no skill dir)
- [ ] Skill dir + 3 subdirs created
- [ ] `SKILL.md` frontmatter valid (YAML parses, all required fields present)
- [ ] `when_to_use` clearly disambiguates from `ck:brainstorm` and `ck:ck-predict`
- [ ] Attribution to source author present in `metadata.attribution`

## Success Criteria
- `ls -R .claude/skills/ck-elicit/` shows skeleton.
- `python3 -c "import yaml; yaml.safe_load(open('.claude/skills/ck-elicit/SKILL.md').read().split('---')[1])"` exits 0.
- A grep across other skills' `when_to_use` confirms no conflicting trigger phrasing.

## Risk Assessment
- **R1:** Name collision with a future ClaudeKit-published skill. Mitigation: `ck:` prefix already used by all local-port additions, low collision risk.
- **R2:** `description` too generic → skill never auto-fires. Mitigation: include strong signal phrases ("vague feature ask", "names a tool as the requirement").

## Security Considerations
- None — markdown-only skill, no tools invoked by the scaffold.

## Next Steps
- Phase 2 fills the workflow body, references, and templates.
