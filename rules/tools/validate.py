#!/usr/bin/env python3
"""
validate.py - Validate prx-waf YAML rule files.

Checks:
- Required fields (id, name, severity, field, operator, value, action)
- Duplicate ID detection across files
- Regex compilation test (for operator=regex)
- Severity/paranoia value validation
- Prints a summary report

Usage:
    python3 tools/validate.py rules/
    python3 tools/validate.py rules/owasp-crs/
    python3 tools/validate.py rules/owasp-crs/sqli.yaml
"""

import re
import sys
import os
import glob
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml not installed. Run: pip3 install pyyaml", file=sys.stderr)
    sys.exit(1)


REQUIRED_FIELDS = ["id", "name", "severity", "field", "operator", "value", "action"]

VALID_SEVERITIES = {"critical", "error", "warning", "notice", "info", "low",
                    "medium", "high", "unknown"}

VALID_ACTIONS = {"block", "log", "allow", "deny", "redirect", "drop"}

VALID_PARANOIA = {1, 2, 3, 4}


def validate_file(path: str, all_ids: dict) -> tuple[list[str], list[str], int]:
    """
    Validate a single YAML rule file.
    Returns (errors, warnings, rule_count).
    all_ids is a shared dict of {rule_id: filename} for cross-file dedup.
    """
    errors = []
    warnings = []

    # Parse YAML
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"], [], 0
    except Exception as e:
        return [f"File read error: {e}"], [], 0

    if doc is None:
        return ["Empty or null YAML document"], [], 0

    if not isinstance(doc, dict):
        return ["Top-level must be a dict"], [], 0

    # Check top-level fields
    for field in ["version", "description", "rules"]:
        if field not in doc:
            warnings.append(f"Missing top-level field: {field}")

    rules = doc.get("rules", [])
    if not isinstance(rules, list):
        return ["'rules' must be a list"], [], 0

    rule_count = len(rules)

    for i, rule in enumerate(rules):
        prefix = f"Rule[{i}]"
        if not isinstance(rule, dict):
            errors.append(f"{prefix}: must be a dict, got {type(rule).__name__}")
            continue

        rule_id = rule.get("id", f"<index:{i}>")
        prefix = f"Rule {rule_id}"

        # Required fields
        for field in REQUIRED_FIELDS:
            if field not in rule:
                errors.append(f"{prefix}: missing required field '{field}'")

        # Duplicate ID check
        if "id" in rule:
            rid = rule["id"]
            if rid in all_ids:
                errors.append(
                    f"{prefix}: duplicate id '{rid}' "
                    f"(first seen in {all_ids[rid]})"
                )
            else:
                all_ids[rid] = os.path.basename(path)

        # Severity validation
        if "severity" in rule:
            sev = str(rule["severity"]).lower()
            if sev not in VALID_SEVERITIES:
                warnings.append(
                    f"{prefix}: unexpected severity '{sev}' "
                    f"(valid: {', '.join(sorted(VALID_SEVERITIES))})"
                )

        # Paranoia validation
        if "paranoia" in rule:
            pl = rule["paranoia"]
            if pl not in VALID_PARANOIA:
                warnings.append(
                    f"{prefix}: paranoia={pl} outside expected range 1-4"
                )

        # Action validation
        if "action" in rule:
            action = str(rule["action"]).lower()
            if action not in VALID_ACTIONS:
                warnings.append(
                    f"{prefix}: unexpected action '{action}' "
                    f"(valid: {', '.join(sorted(VALID_ACTIONS))})"
                )

        # Regex compilation (warn about PCRE-specific syntax, error on truly broken)
        if rule.get("operator") == "regex" and "value" in rule:
            pattern = str(rule["value"])
            if pattern:
                try:
                    re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    # Check if this is PCRE-specific syntax (valid for the WAF engine)
                    pcre_indicators = [
                        r'\x{',        # PCRE hex escape \x{ff}
                        r'\z',         # PCRE end-of-string anchor
                        r'\Z',         # end-of-string (actually ok in python but check)
                        r'(?i)',        # inline flag not at start
                        r'(*',         # PCRE verb
                        r'\p{',        # PCRE unicode property
                        r'\P{',
                        r'(?<',        # lookbehind / named group variants
                    ]
                    is_pcre = any(ind in pattern for ind in pcre_indicators)
                    # Also check for inline flag issues
                    if re.search(r'\(\?[imsx]+\)', pattern[1:]):
                        is_pcre = True
                    if is_pcre:
                        warnings.append(
                            f"{prefix}: PCRE-specific regex (WAF engine handles this): "
                            f"'{pattern[:50]}...': {e}"
                        )
                    else:
                        errors.append(
                            f"{prefix}: invalid regex '{pattern[:60]}...': {e}"
                        )

        # Value type for non-regex operators
        if rule.get("operator") in ("gt", "lt", "ge", "le", "equals") and "value" in rule:
            val = rule["value"]
            if isinstance(val, str) and val and not val.replace(".", "").isdigit():
                # It's a string value for a numeric operator - just warn if obviously numeric op
                if rule["operator"] in ("gt", "lt", "ge", "le"):
                    warnings.append(
                        f"{prefix}: operator '{rule['operator']}' with non-numeric value '{val}'"
                    )

        # Tags should be a list
        if "tags" in rule and not isinstance(rule["tags"], list):
            errors.append(f"{prefix}: 'tags' must be a list")

    return errors, warnings, rule_count


def collect_yaml_files(directory: str) -> list[str]:
    """
    Recursively collect all .yaml / .yml files under a directory,
    searching the root and known rule subdirectories.

    Skips files whose name starts with '_' (private/template marker).
    Also skips the tools/ subdirectory to avoid picking up sync-config.yaml
    or other tool-configuration files that are not rule files.
    """
    root = Path(directory)
    found = []

    # Subdirectories that contain rule files
    RULE_SUBDIRS = {"owasp-crs", "modsecurity", "cve-patches", "custom"}
    # Subdirectories to skip entirely
    SKIP_SUBDIRS = {"tools", "data", ".git", "__pycache__"}
    # Root-level files to skip (config/meta, not rule files)
    SKIP_FILENAMES = {"sync-config.yaml", "sync-config.yml"}

    for path in sorted(root.rglob("*.yaml")) + sorted(root.rglob("*.yml")):
        rel = path.relative_to(root)
        parts = rel.parts  # e.g. ('owasp-crs', 'sqli.yaml') or ('sync-config.yaml',)

        # Skip root-level non-rule config files
        if len(parts) == 1 and path.name in SKIP_FILENAMES:
            continue
        # Skip tool/data directories
        parent_parts = set(parts[:-1])
        if parent_parts & SKIP_SUBDIRS:
            continue
        # Skip private/template files
        if path.name.startswith("_"):
            continue
        found.append(str(path))

    return sorted(set(found))


def validate_path(target: str) -> int:
    """
    Validate a file or directory. Returns exit code (0=ok, 1=errors).
    When given a directory, recursively searches owasp-crs/, modsecurity/,
    cve-patches/, and custom/ for .yaml rule files.
    """
    if os.path.isfile(target):
        yaml_files = [target]
    elif os.path.isdir(target):
        yaml_files = collect_yaml_files(target)
    else:
        print(f"ERROR: Not a file or directory: {target}", file=sys.stderr)
        return 1

    if not yaml_files:
        print(f"No YAML files found in: {target}")
        return 0

    all_ids: dict[str, str] = {}
    total_rules = 0
    total_errors = 0
    total_warnings = 0
    file_results = []

    for path in yaml_files:
        errs, warns, count = validate_file(path, all_ids)
        total_rules += count
        total_errors += len(errs)
        total_warnings += len(warns)
        file_results.append((path, errs, warns, count))

    # Print report
    print("=" * 70)
    print("  prx-waf YAML Rule Validator")
    print("=" * 70)
    print()

    for path, errs, warns, count in file_results:
        rel = os.path.relpath(path, target) if os.path.isdir(target) else os.path.basename(path)
        status = "✓" if not errs else "✗"
        warn_str = f"  {len(warns)} warn" if warns else ""
        print(f"  {status} {rel:<40} {count:>4} rules{warn_str}")

        for e in errs:
            print(f"      ERROR:   {e}")
        for w in warns:
            print(f"      WARNING: {w}")

    print()
    print("─" * 70)
    print(f"  Files:    {len(yaml_files)}")
    print(f"  Rules:    {total_rules}")
    print(f"  Errors:   {total_errors}")
    print(f"  Warnings: {total_warnings}")
    print("─" * 70)

    if total_errors == 0:
        print("  ✓ All files valid!")
    else:
        print(f"  ✗ {total_errors} error(s) found.")

    print()

    return 0 if total_errors == 0 else 1


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <rules_dir_or_file>")
        sys.exit(1)

    target = sys.argv[1]
    exit_code = validate_path(target)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
