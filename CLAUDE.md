# CLAUDE.md — prx-waf Rust Production Code Standards

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

<!-- HARNESS:BEGIN -->
## Harness

Claude Code loads this file into every session, but it does not auto-load
`AGENTS.md`. The bare `@` lines below import the always-required harness
context (the "Must in all lanes" set from `docs/CONTEXT_RULES.md`) at
context-load time. Never wrap them in backticks; that disables the import.

@AGENTS.md

@docs/FEATURE_INTAKE.md

Also run `scripts/bin/harness-cli query matrix` before starting work.

Lane-dependent context (`README.md`, `docs/HARNESS.md`, `docs/ARCHITECTURE.md`,
`docs/CONTEXT_RULES.md`, product docs, stories, decisions) is intentionally not
imported — read it per lane, as `docs/CONTEXT_RULES.md` prescribes.
<!-- HARNESS:END -->
