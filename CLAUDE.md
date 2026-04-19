# CLAUDE.md — prx-waf Rust Production Code Standards

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Coding Principles

```
## Coding Principles

Four guardrails against the most common LLM coding failures (source: Andrej Karpathy).

### 1. Think Before Coding
- State assumptions explicitly before writing code
- When multiple interpretations exist, present them — never pick silently
- Push back if a simpler approach exists
- If something is unclear, stop and ask before proceeding

### 2. Simplicity First
- No features beyond what was explicitly asked
- No abstractions for single-use code
- No "flexibility" or "configurability" not requested
- No error handling for impossible scenarios
- Self-test: "Would a senior engineer say this is overcomplicated?" → If yes, rewrite
- If 200 lines could be 50, rewrite it

### 3. Surgical Changes
- Do not improve adjacent code, comments, or formatting
- Do not refactor things that aren't broken
- Match existing style even if you'd do it differently
- If you notice unrelated dead code: **mention it, don't delete it**
- When YOUR changes create orphans (unused imports/vars/funcs): clean those up
- Litmus test: every changed line must trace directly to the user's request

### 4. Goal-Driven Execution
- Transform tasks into verifiable goals with success criteria
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"
- Multi-step plans must have explicit verify conditions per step
```

## Role & Responsibilities

Your role is to analyze user requirements, delegate tasks to appropriate sub-agents, and ensure cohesive delivery of features that meet specifications and architectural standards.

## Workflows

- Primary workflow: `./.claude/rules/primary-workflow.md`
- Development rules: `./.claude/rules/development-rules.md`
- Orchestration protocols: `./.claude/rules/orchestration-protocol.md`
- Documentation management: `./.claude/rules/documentation-management.md`
- And other workflows: `./.claude/rules/*`

**IMPORTANT:** Analyze the skills catalog and activate the skills that are needed for the task during the process.
**IMPORTANT:** DO NOT modify skills in `~/.claude/skills` directory directly. **MUST** modify skills in this current working directory. Unless you are asked to do so.
**IMPORTANT:** You must follow strictly the development rules in `./.claude/rules/development-rules.md` file.
**IMPORTANT:** Before you plan or proceed any implementation, always read the `./README.md` file first to get context.
**IMPORTANT:** Sacrifice grammar for the sake of concision when writing reports.
**IMPORTANT:** In reports, list any unresolved questions at the end, if any.

## Git

**DO NOT** use `chore` and `docs` in commit messages of file changes in `.claude` directory.

## Hook Response Protocol

### Privacy Block Hook (`@@PRIVACY_PROMPT@@`)

When a tool call is blocked by the privacy-block hook, the output contains a JSON marker between `@@PRIVACY_PROMPT_START@@` and `@@PRIVACY_PROMPT_END@@`. **You MUST use the `AskUserQuestion` tool** to get proper user approval.

**Required Flow:**

1. Parse the JSON from the hook output
2. Use `AskUserQuestion` with the question data from the JSON
3. Based on user's selection:
   - **"Yes, approve access"** → Use `bash cat "filepath"` to read the file (bash is auto-approved)
   - **"No, skip this file"** → Continue without accessing the file

**Example AskUserQuestion call:**

```json
{
  "questions": [
    {
      "question": "I need to read \".env\" which may contain sensitive data. Do you approve?",
      "header": "File Access",
      "options": [
        {
          "label": "Yes, approve access",
          "description": "Allow reading .env this time"
        },
        {
          "label": "No, skip this file",
          "description": "Continue without accessing this file"
        }
      ],
      "multiSelect": false
    }
  ]
}
```

**IMPORTANT:** Always ask the user via `AskUserQuestion` first. Never try to work around the privacy block without explicit user approval.

## Python Scripts (Skills)

When running Python scripts from `.claude/skills/`, use the venv Python interpreter:

- **Linux/macOS:** `.claude/skills/.venv/bin/python3 scripts/xxx.py`
- **Windows:** `.claude\skills\.venv\Scripts\python.exe scripts\xxx.py`

This ensures packages installed by `install.sh` (google-genai, pypdf, etc.) are available.

**IMPORTANT:** When scripts of skills failed, don't stop, try to fix them directly.

## [IMPORTANT] Consider Modularization

- If a code file exceeds 200 lines of code, consider modularizing it
- Check existing modules before creating new
- Analyze logical separation boundaries (functions, classes, concerns)
- Use kebab-case naming with long descriptive names, it's fine if the file name is long because this ensures file names are self-documenting for LLM tools (Grep, Glob, Search)
- Write descriptive code comments
- After modularization, continue with main task
- When not to modularize: Markdown files, plain text files, bash scripts, configuration files, environment variables files, etc.

## Documentation Management

We keep all important docs in `./docs` folder and keep updating them, structure like below:

```
./docs
├── project-overview-pdr.md
├── code-standards.md
├── codebase-summary.md
├── design-guidelines.md
├── deployment-guide.md
├── system-architecture.md
└── project-roadmap.md
```

**IMPORTANT:** _MUST READ_ and _MUST COMPLY_ all _INSTRUCTIONS_ in project `./CLAUDE.md`, especially _WORKFLOWS_ section is _CRITICALLY IMPORTANT_, this rule is _MANDATORY. NON-NEGOTIABLE. NO EXCEPTIONS. MUST REMEMBER AT ALL TIMES!!!_

## Rust Edition: 2024

## Seven Iron Rules (Strictly Enforced)

1. NO panic-capable unwrapping — .unwrap(), .expect(), any panic shorthand BANNED in production code
2. NO dead code — zero unused variables, parameters, imports. Zero warnings.
3. NO incomplete implementations — todo!(), unimplemented!(), placeholder returns, empty arms BANNED
4. Business logic must be verifiable — must pass cargo check, no speculative interfaces
5. Validate with cargo check and cargo fix — not cargo run/build
6. Explicit error handling — validate external inputs, never panic instead of error branch
7. Minimize allocations — prefer &str over String, Cow over clone, Arc over deep copy

## Build & Test

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test
cargo build --release
```

## Docker

```bash
podman-compose down && podman-compose up -d --build
# Uses Dockerfile.prebuilt (local binary, fast)
# Ports: 16880 (HTTP), 16843 (HTTPS), 16827 (API/Admin UI)
# Admin UI: http://localhost:16827/ui/  (admin / admin123)
```

## Rust Safety Rules (Non-Negotiable)

### NO .unwrap() in Production Code

- BANNED: `.unwrap()` outside `#[cfg(test)]`
- Use: `?`, `.unwrap_or_default()`, `.unwrap_or(val)`, `if let`, `.expect("BUG: reason")`
- `.expect()` only for compile-time constants

### Error Handling

- `?` with `.context("msg")` for anyhow propagation
- Never silently swallow errors — log before `.ok()`
- `tracing::warn!()` when intentionally discarding errors

### Mutex

- Sync: `parking_lot::Mutex` (no poison, no unwrap)
- Async: `tokio::sync::Mutex` (.lock().await)
- BANNED: `std::sync::Mutex` in production

### SQL Safety

- Parameterized queries only: `sqlx::query("...WHERE id = $1").bind(id)`
- Validate dynamic identifiers: `^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`

### No Secret Logging

- Never log tokens, keys, passwords
- Sanitize URLs before logging

### Unsafe

- Requires `// SAFETY:` comment
- Validate inputs before unsafe block

## Architecture

- Workspace: 7 crates (prx-waf, gateway, waf-engine, waf-storage, waf-api, waf-common, waf-cluster)
- WAF engine: Pingora-based reverse proxy
- Rules: YAML files in rules/ directory
- Admin UI: Vue 3 + Tailwind in web/admin-ui/
- Config: TOML in configs/
- English in code/commits
