# Skill Architecture & Structure Analysis
## mattpocock/skills Repository Research

**Date:** 2026-05-20  
**Focus:** Understanding skill organization, configuration patterns, and the setup-matt-pocock-skills skill

---

## Executive Summary

The mattpocock/skills repository is a **composable engineering practices framework** for AI-assisted development. Skills are prompt-driven, discoverable, and configurable—each skill directory contains a `SKILL.md` manifest plus domain-specific configuration files. The `setup-matt-pocock-skills` skill bootstraps per-repository configuration (issue tracker, triage labels, domain docs) that other skills depend on.

**Key Finding:** Skills are NOT deterministic scripts. They're **guided workflows** (human + agent interaction) that establish shared conventions. The setup skill exemplifies this: it prompts the user for three decisions (issue tracker, triage labels, domain layout), writes configuration, and enables downstream skills to operate uniformly.

---

## Repository Structure

```
mattpocock/skills/
├── .claude-plugin/          # Claude plugin integration
├── docs/                    # Shared documentation
├── scripts/                 # Utility scripts
├── skills/
│   ├── engineering/         # Core development practices
│   │   ├── README.md
│   │   ├── diagnose/        # Debugging & root-cause analysis
│   │   ├── grill-with-docs/ # Doc-driven alignment
│   │   ├── improve-codebase-architecture/
│   │   ├── prototype/
│   │   ├── setup-matt-pocock-skills/  ← FOCUS
│   │   ├── tdd/             # Test-driven development
│   │   ├── to-issues/       # Convert specs → GitHub issues
│   │   ├── to-prd/          # Convert context → PRD
│   │   ├── triage/          # Issue state machine
│   │   └── zoom-out/        # Gain perspective on unfamiliar code
│   ├── productivity/        # Workflow tools
│   └── miscellaneous/       # Specialized utilities
├── README.md                # Main documentation
├── CLAUDE.md                # Claude-specific guidance
├── CONTEXT.md               # Domain language & shared vocabulary
└── LICENSE
```

**11 engineering skills** organized by workflow role:
- **Problem-solving**: diagnose, prototype, zoom-out
- **Processes**: tdd, triage, grill-with-docs
- **Planning & Coordination**: to-issues, to-prd, setup-matt-pocock-skills
- **Architecture**: improve-codebase-architecture

---

## Setup-Matt-Pocock-Skills: Complete Anatomy

### File Listing

| File | Purpose |
|------|---------|
| `SKILL.md` | Manifest & process flow description |
| `domain.md` | Meta-guide for finding domain context in repos |
| `triage-labels.md` | Reference: five canonical triage label mappings |
| `issue-tracker-github.md` | GitHub CLI configuration & commands |
| `issue-tracker-gitlab.md` | GitLab CLI configuration & commands |
| `issue-tracker-local.md` | Markdown-based (`.scratch/`) issue tracking |

### Purpose

Bootstrap per-repository setup so dependent skills (`to-issues`, `triage`, `diagnose`) can:
- Create/fetch issues consistently (know where they live)
- Apply/read triage labels uniformly (know label mapping)
- Find domain context reliably (know doc structure)

### Process Flow (5 Steps)

**1. Explore**
- Read git remotes, `AGENTS.md`/`CLAUDE.md`, existing domain docs, `.scratch/` directory
- Infer current state (is a tracker already configured?)

**2. Present & Confirm** (User interaction points)
- Propose issue tracker (default: GitHub; options: GitLab, local markdown, custom)
- Propose triage label mappings (five canonical roles → repo-specific label names)
- Propose domain doc location (single-context root vs. multi-context monorepo)
- Get user confirmation

**3. Confirm & Edit**
- Show draft configuration
- Allow user modifications before writing

**4. Write**
- Create/update `CLAUDE.md` or `AGENTS.md` (prefers whichever exists)
- Create three files under `docs/agents/`:
  - `issue-tracker.md` (which tracker is in use + commands)
  - `triage-labels.md` (canonical → actual label mapping)
  - `domain.md` (where to find CONTEXT.md, ADRs, glossaries)

**5. Done**
- Confirm completion
- Note that docs are user-editable afterward

---

## Configuration Patterns

### 1. Issue Tracker Options

#### GitHub (Default)
- **Location:** `issue-tracker-github.md`
- **CLI Tool:** `gh` (GitHub CLI)
- **Core Commands:**
  ```bash
  gh issue create --title "..." --body "..."
  gh issue view <number> --comments
  gh issue list --json number,title,body,labels,comments
  gh issue comment <number> --body "..."
  ```
- **Label Ops:** Native GitHub labels
- **Detection:** Automatic from `git remote -v`

#### GitLab
- **Location:** `issue-tracker-gitlab.md`
- **CLI Tool:** `glab` (GitLab CLI)
- **Terminology Shift:**
  - "merge requests" instead of pull requests
  - "notes" instead of comments
- **Core Commands:**
  ```bash
  glab issue create --title "..." --description "..."
  glab issue view <number>
  glab issue note <number> --message "..."
  ```
- **Label Ops:** Supports multiple comma-separated labels
- **Note:** `glab issue close` does NOT accept closing comment (must post separately)

#### Local Markdown (`.scratch/`)
- **Location:** `issue-tracker-local.md`
- **Structure:**
  ```
  .scratch/
  ├── <feature-slug>/
  │   ├── PRD.md
  │   └── issues/
  │       ├── 01-first-issue.md
  │       ├── 02-second-issue.md
  │       └── ...
  ```
- **Issue Format:**
  - `Status:` field near top (references triage-labels.md)
  - `## Comments` section for discussion thread
  - Plain markdown, version-control friendly
- **Use Case:** Offline workflows, tight VCS integration, simple repos

#### Custom
- Freeform text placeholder for non-standard trackers
- Documented by user; skills adapt based on documented interface

### 2. Triage Label Mapping

**Five Canonical Roles** (ecosystem-wide convention):

| Canonical | Meaning | Typical GitHub Label |
|-----------|---------|---------------------|
| `needs-triage` | Maintainer must evaluate | `needs-triage` |
| `needs-info` | Waiting on reporter | `needs-info` or `waiting-info` |
| `ready-for-agent` | Fully specified, LLM-ready | `ready-for-agent` or `rfa` |
| `ready-for-human` | Needs human implementation | `ready-for-human` or `rfh` |
| `wontfix` | Will not be actioned | `wontfix` or `won't-fix` |

**Pattern:** Teams map canonical → actual labels; skills read canonical names and translate via mapping.

### 3. Domain Documentation Discovery

**Three Search Patterns:**

| Pattern | Purpose | Location |
|---------|---------|----------|
| **Domain Context** | Shared vocabulary, glossary | `CONTEXT.md` (root) or `CONTEXT-MAP.md` (monorepo) |
| **Architectural Decisions** | Design rationale, constraints | `docs/adr/` (ADR format) or custom |
| **Domain Docs** | Single-context vs. multi-context layout | Documented in `domain.md` (the meta-guide) |

**Example monorepo layout (implied):**
```
CONTEXT-MAP.md          # Entry point listing all contexts
docs/
  └── adr/              # Shared ADRs
contexts/
  ├── billing/
  │   ├── CONTEXT.md    # Billing-specific vocabulary
  │   └── README.md
  └── orders/
      ├── CONTEXT.md    # Orders-specific vocabulary
      └── README.md
```

---

## Skill Manifesto Files

### SKILL.md Structure (from setup-matt-pocock-skills example)

Components:
1. **Overview** — What does this skill do?
2. **Purpose** — Why does the team need it?
3. **Process Flow** — Step-by-step interaction model (labeled with step numbers and user interaction points)
4. **Key Configuration Options** — Table of user choices
5. **Outputs** — What gets written/changed

**Tone:** Prompt-written, not algorithm-written. SKILL.md describes the workflow, not code logic.

---

## Engineering Skills Ecosystem

### Interconnection Model

```
setup-matt-pocock-skills
  ↓ (bootstraps config)
  ├─→ to-issues       (uses issue-tracker config + triage-labels)
  ├─→ triage          (uses triage-labels config)
  ├─→ diagnose        (uses domain.md to find context)
  └─→ improve-codebase-architecture (uses domain.md + ADRs)

Additional skills (peer-level):
  - grill-with-docs   (uses CONTEXT.md vocabulary)
  - tdd               (independent process)
  - prototype         (independent process)
  - zoom-out          (independent process)
```

**Key Insight:** Skills form a **dependency graph**. Setup-matt-pocock-skills is the **root** skill; others depend on it for discovered configuration.

---

## Writing & Configuration Patterns

### CLAUDE.md Integration

Setup writes to (or creates) `CLAUDE.md` with an `## Agent skills` block:

```markdown
## Agent skills

- **Issue Tracker:** GitHub (gh CLI)
- **Triage Labels:** [mapping of 5 canonical → actual labels]
- **Domain Docs:** Single-context (CONTEXT.md at root)

### Configuration Files
- `docs/agents/issue-tracker.md`
- `docs/agents/triage-labels.md`
- `docs/agents/domain.md`
```

This block serves as a **discovery mechanism**—other skills/agents read it to understand repo setup.

### Frontmatter & Metadata

**No YAML frontmatter observed.** Files are:
- **Markdown-only** (no YAML/TOML config)
- **Prompt-friendly** (structured as narrative, not data)
- **Human-editable** (not auto-generated; users can modify after creation)

---

## Dependencies & References

### Within Repository
- **CONTEXT.md** — Shared domain language (referenced by domain.md, consumed by grill-with-docs)
- **docs/adr/** — Architectural Decision Records (referenced by improve-codebase-architecture)
- **CLAUDE.md** — Agent configuration hub (the "manifest" of the manifests)

### External
- **gh CLI** (GitHub)
- **glab CLI** (GitLab)
- **Git** (for `git remote -v` detection)

### Ecosystem-Wide Conventions
- **Five canonical triage labels** — agreed across all skills in the ecosystem
- **Kebab-case naming** — skills use hyphens (e.g., `grill-with-docs`, `setup-matt-pocock-skills`)

---

## File Layout Conventions

### Naming
- Skill directories: kebab-case, descriptive (e.g., `setup-matt-pocock-skills`)
- Manifest: Always `SKILL.md` (discoverable)
- Config docs: Snake-case + descriptive (e.g., `issue-tracker-github.md`)
- Feature subdirectories in `.scratch/`: kebab-case slugs

### Organization
```
skill-name/
├── SKILL.md                      # Manifest (required)
├── [config-pattern]-variant.md   # Config alternatives (issue-tracker-*.md)
└── scripts/                      # Optional: Python/bash scripts
    └── (empty in setup skill; present in diagnose)
```

**Modularization:** Configuration options split into separate files (one per tracker type) rather than conditionals within SKILL.md. Makes it easy for users to read only relevant variant.

---

## Core Philosophy (Inferred)

1. **Skills are not deterministic algorithms.** They're guided workflows that blend AI agents and human decision-making.

2. **Configuration is user-confirmed.** Skills propose defaults; users decide what applies to their repo.

3. **Conventions scale.** The five triage labels, GitHub CLI commands, and CONTEXT.md pattern are **ecosystem-wide** so skills interoperate without hardcoding.

4. **Documentation is configuration.** Setup writes markdown files that other skills read; no JSON/YAML intermediate layer.

5. **Discoverability via CLAUDE.md.** A single `CLAUDE.md` block tells downstream agents where to find everything: tracker, labels, domain context.

6. **Offline-first option.** Local markdown (`.scratch/`) is a first-class alternative to hosted trackers, supporting teams that prefer Git over SaaS APIs.

---

## Unresolved Questions

1. **How do skills validate config after setup completes?** Do downstream skills error gracefully if `docs/agents/` files are missing or malformed?

2. **Monorepo scaling:** The domain.md guide references CONTEXT-MAP.md but doesn't show examples. What does a monorepo's `CONTEXT-MAP.md` actually contain?

3. **Custom tracker format:** The GitHub/GitLab variants are specific; custom trackers are "freeform text." How much structure does the downstream skill (to-issues) actually need?

4. **ADR discovery:** The domain.md meta-guide mentions `docs/adr/` but doesn't specify naming convention (MADR? RFC 2119 style?). Is there an existing team standard?

5. **Skill versioning:** If setup-matt-pocock-skills updates its config format, how are existing repos' `docs/agents/` files migrated?

6. **Permission model:** The setup skill writes to CLAUDE.md and creates docs/agents/. What happens if the user lacks write permissions to these paths?

---

## Recommendations for Mini-WAF Integration

If mini-waf adopts this pattern:

1. **Run setup-matt-pocock-skills as the first skill** to bootstrap issue tracker, triage labels, and domain context discovery.

2. **Document mini-waf's five triage labels** (map canonical → actual GitHub labels used in the project).

3. **Create CONTEXT.md** at root with WAF-specific terminology (rules, phases, detections, actions).

4. **Add `docs/agents/` block to CLAUDE.md** after setup completes, so downstream skills (to-issues, diagnose, etc.) know where config lives.

5. **Use markdown-based issue tracking (`.scratch/`)** as an alternative to GitHub issues if offline workflows are important.

6. **Adopt kebab-case naming** for feature directories and skill references, consistent with mattpocock/skills ecosystem.

---

**Status:** DONE  
**Summary:** The setup-matt-pocock-skills skill is a configuration bootstrapper that guides users through three decisions (issue tracker, triage labels, domain context) and writes configuration files that dependent skills consume. The broader ecosystem uses five canonical triage labels, markdown-based configuration (no YAML), and CLAUDE.md as a discovery hub. Skills are interactive, human-confirmed workflows, not deterministic scripts.
