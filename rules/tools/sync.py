#!/usr/bin/env python3
"""
sync.py - Sync prx-waf rules from upstream sources (OWASP CRS, etc.)

Clones or updates the upstream repository, runs the converter (modsec2yaml.py),
copies auxiliary data files, and reports a diff summary of changes.

Usage:
    python sync.py --source owasp-crs --output ../owasp-crs/ [--tag v4.10.0] [--dry-run]
    python sync.py --source owasp-crs --output ../owasp-crs/ --branch main
    python sync.py --check                        # Check if updates are available
    python sync.py --config sync-config.yaml --source owasp-crs --output ../owasp-crs/

Config file (sync-config.yaml) is optional. CLI flags override config values.
Temp directory for cloning: /tmp/prx-waf-sync/
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml not installed. Run: pip3 install pyyaml", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TEMP_BASE = Path("/tmp/prx-waf-sync")

DEFAULT_SOURCES = {
    "owasp-crs": {
        "repo": "https://github.com/coreruleset/coreruleset.git",
        "branch": "main",
        "rules_path": "rules/",
        "data_path": "rules/",          # .data files live alongside .conf files
        "output": "../owasp-crs/",
        "converter": "modsec2yaml.py",
        "description": "OWASP ModSecurity Core Rule Set v4",
        "license": "Apache-2.0",
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd: list[str], cwd: str | None = None, capture: bool = False) -> subprocess.CompletedProcess:
    """Run a shell command, streaming output unless capture=True."""
    if capture:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    else:
        return subprocess.run(cmd, cwd=cwd, check=True)


def file_hash(path: Path) -> str:
    """SHA-256 of a file (used to detect content changes)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot_yaml_dir(directory: Path) -> dict[str, str]:
    """
    Return a dict of {relative_path: sha256} for all .yaml files in a directory.
    Used to compute before/after diff.
    """
    if not directory.exists():
        return {}
    snap = {}
    for p in sorted(directory.rglob("*.yaml")):
        rel = str(p.relative_to(directory))
        snap[rel] = file_hash(p)
    return snap


def diff_snapshots(before: dict[str, str], after: dict[str, str]) -> dict:
    """
    Compare two snapshots and return a diff summary dict with keys:
      added, updated, removed, unchanged
    Each value is a list of relative path strings.
    """
    all_keys = set(before) | set(after)
    added, updated, removed, unchanged = [], [], [], []
    for k in sorted(all_keys):
        if k not in before:
            added.append(k)
        elif k not in after:
            removed.append(k)
        elif before[k] != after[k]:
            updated.append(k)
        else:
            unchanged.append(k)
    return {"added": added, "updated": updated, "removed": removed, "unchanged": unchanged}


def print_diff(diff: dict, verbose: bool = False) -> None:
    """Print a human-readable diff summary."""
    total_changed = len(diff["added"]) + len(diff["updated"]) + len(diff["removed"])
    print()
    print("  Diff Summary")
    print("  " + "-" * 40)
    print(f"  Added:     {len(diff['added'])}")
    print(f"  Updated:   {len(diff['updated'])}")
    print(f"  Removed:   {len(diff['removed'])}")
    print(f"  Unchanged: {len(diff['unchanged'])}")

    if total_changed == 0:
        print()
        print("  No changes detected.")
        return

    if diff["added"]:
        print()
        print("  Added files:")
        for f in diff["added"]:
            print(f"    + {f}")

    if diff["updated"]:
        print()
        print("  Updated files:")
        for f in diff["updated"]:
            print(f"    ~ {f}")

    if diff["removed"]:
        print()
        print("  Removed files:")
        for f in diff["removed"]:
            print(f"    - {f}")

    if verbose and diff["unchanged"]:
        print()
        print("  Unchanged files:")
        for f in diff["unchanged"]:
            print(f"    = {f}")


# ---------------------------------------------------------------------------
# Git operations
# ---------------------------------------------------------------------------

def git_available() -> bool:
    result = subprocess.run(["git", "--version"], capture_output=True)
    return result.returncode == 0


def clone_or_pull(repo: str, clone_dir: Path, branch: str | None, tag: str | None) -> str:
    """
    Clone the repo if it doesn't exist, otherwise fetch and reset to latest.
    Returns the resolved commit SHA.
    """
    if not git_available():
        print("ERROR: git is not installed or not in PATH.", file=sys.stderr)
        sys.exit(1)

    if clone_dir.exists() and (clone_dir / ".git").exists():
        print(f"  Fetching updates for existing clone: {clone_dir}")
        run(["git", "fetch", "--tags", "--prune"], cwd=str(clone_dir))
    else:
        print(f"  Cloning {repo} → {clone_dir}")
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "--filter=blob:none", repo, str(clone_dir)])

    # Checkout the requested ref
    if tag:
        print(f"  Checking out tag: {tag}")
        run(["git", "checkout", tag], cwd=str(clone_dir))
    elif branch:
        print(f"  Checking out branch: {branch}")
        run(["git", "checkout", branch], cwd=str(clone_dir))
        run(["git", "pull", "--ff-only"], cwd=str(clone_dir))
    else:
        run(["git", "checkout", "main"], cwd=str(clone_dir))
        run(["git", "pull", "--ff-only"], cwd=str(clone_dir))

    # Get current commit
    result = run(["git", "rev-parse", "--short", "HEAD"], cwd=str(clone_dir), capture=True)
    return result.stdout.strip()


def get_remote_head(repo: str, ref: str) -> str:
    """
    Query the remote HEAD SHA for a given ref without cloning.
    Returns an empty string on failure.
    """
    result = subprocess.run(
        ["git", "ls-remote", repo, ref],
        capture_output=True, text=True
    )
    if result.returncode != 0 or not result.stdout.strip():
        return ""
    first_line = result.stdout.strip().splitlines()[0]
    return first_line.split("\t")[0][:12]


def get_local_head(clone_dir: Path) -> str:
    """Return the local HEAD SHA or empty string."""
    if not clone_dir.exists():
        return ""
    result = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=str(clone_dir), capture_output=True, text=True
    )
    return result.stdout.strip() if result.returncode == 0 else ""


# ---------------------------------------------------------------------------
# Sync logic
# ---------------------------------------------------------------------------

def run_converter(converter_script: Path, src_conf_dir: Path, output_dir: Path) -> bool:
    """
    Run modsec2yaml.py to convert .conf files to .yaml.
    Returns True on success.
    """
    if not converter_script.exists():
        print(f"ERROR: Converter not found: {converter_script}", file=sys.stderr)
        return False

    print(f"  Running converter: {converter_script.name}")
    result = subprocess.run(
        [sys.executable, str(converter_script), str(src_conf_dir), str(output_dir)],
        capture_output=False,
    )
    return result.returncode == 0


def copy_data_files(src_conf_dir: Path, output_data_dir: Path) -> int:
    """
    Copy .data files from the upstream rules directory to owasp-crs/data/.
    Returns the number of files copied.
    """
    output_data_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for src in sorted(src_conf_dir.glob("*.data")):
        dst = output_data_dir / src.name
        shutil.copy2(src, dst)
        count += 1
    return count


def load_config(config_path: str | None) -> dict:
    """Load optional sync-config.yaml. Returns empty dict if not found."""
    if config_path is None:
        # Look for sync-config.yaml next to tools/ (i.e., in rules/)
        tools_dir = Path(__file__).parent
        default_cfg = tools_dir.parent / "sync-config.yaml"
        if default_cfg.exists():
            config_path = str(default_cfg)
        else:
            return {}

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        return cfg.get("sources", {})
    except Exception as e:
        print(f"WARNING: Could not load config {config_path}: {e}", file=sys.stderr)
        return {}


def build_source_config(
    sources_cfg: dict,
    source_name: str,
    output: str | None,
    branch: str | None,
    tag: str | None,
) -> dict:
    """
    Merge config-file source settings with DEFAULT_SOURCES and CLI overrides.
    Returns the final source config dict.
    """
    # Start from built-in defaults
    cfg = dict(DEFAULT_SOURCES.get(source_name, {}))
    # Overlay config-file values
    if source_name in sources_cfg:
        cfg.update(sources_cfg[source_name])

    if not cfg:
        print(f"ERROR: Unknown source '{source_name}'. "
              f"Available built-in sources: {list(DEFAULT_SOURCES)}", file=sys.stderr)
        sys.exit(1)

    # CLI overrides
    if output:
        cfg["output"] = output
    if branch:
        cfg["branch"] = branch
    if tag:
        cfg["tag"] = tag

    return cfg


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_check(args, sources_cfg: dict) -> int:
    """Check if updates are available for all (or specified) sources."""
    names = [args.source] if args.source else list(DEFAULT_SOURCES.keys())

    print("=" * 60)
    print("  prx-waf Sync — Update Check")
    print("=" * 60)

    any_updates = False
    for name in names:
        cfg = build_source_config(sources_cfg, name, None, None, None)
        repo = cfg["repo"]
        tag = cfg.get("tag")
        branch = cfg.get("branch", "main")
        clone_dir = TEMP_BASE / name

        local_sha = get_local_head(clone_dir)
        ref = f"refs/tags/{tag}" if tag else f"refs/heads/{branch}"
        remote_sha = get_remote_head(repo, ref)

        print(f"\n  Source: {name}")
        print(f"  Repo:   {repo}")
        print(f"  Ref:    {tag or branch}")

        if not local_sha:
            print("  Local:  not cloned yet")
            print("  Status: update available (no local clone)")
            any_updates = True
        elif not remote_sha:
            print(f"  Local:  {local_sha}")
            print("  Remote: (could not query)")
        elif local_sha == remote_sha:
            print(f"  Local:  {local_sha}  (up to date)")
            print("  Status: up to date")
        else:
            print(f"  Local:  {local_sha}")
            print(f"  Remote: {remote_sha}")
            print("  Status: update available")
            any_updates = True

    print()
    if any_updates:
        print("  Updates available. Run sync.py without --check to apply.")
    else:
        print("  All sources are up to date.")
    print()
    return 0


def cmd_sync(args, sources_cfg: dict) -> int:
    """Perform the sync: clone/pull, convert, copy data files."""
    if not args.source:
        print("ERROR: --source is required. Example: --source owasp-crs", file=sys.stderr)
        return 1

    cfg = build_source_config(
        sources_cfg,
        args.source,
        args.output,
        getattr(args, "branch", None),
        args.tag,
    )

    repo = cfg["repo"]
    branch = cfg.get("branch", "main")
    tag = cfg.get("tag")
    rules_path = cfg.get("rules_path", "rules/")
    output = cfg.get("output", f"../rules/{args.source}/")
    converter_name = cfg.get("converter", "modsec2yaml.py")

    # Resolve paths
    tools_dir = Path(__file__).parent
    output_dir = (tools_dir / output).resolve()
    clone_dir = TEMP_BASE / args.source
    converter_script = tools_dir / converter_name

    print("=" * 60)
    print("  prx-waf Sync")
    print("=" * 60)
    print(f"  Source:    {args.source}")
    print(f"  Repo:      {repo}")
    print(f"  Ref:       {tag or branch}")
    print(f"  Output:    {output_dir}")
    print(f"  Dry run:   {args.dry_run}")
    print()

    # Step 1: Clone or pull
    print("Step 1/4: Fetch upstream repository")
    commit = clone_or_pull(repo, clone_dir, branch if not tag else None, tag)
    print(f"  Commit: {commit}")

    src_conf_dir = clone_dir / rules_path
    if not src_conf_dir.exists():
        print(f"ERROR: rules_path not found in repo: {src_conf_dir}", file=sys.stderr)
        return 1

    # Step 2: Snapshot output before conversion
    print()
    print("Step 2/4: Snapshot current output directory")
    snapshot_before = snapshot_yaml_dir(output_dir)
    print(f"  Found {len(snapshot_before)} existing YAML files")

    if args.dry_run:
        print()
        print("  [DRY RUN] Skipping conversion and file copy.")
        print("  The following .conf files would be converted:")
        conf_files = sorted(src_conf_dir.glob("*.conf"))
        for f in conf_files:
            print(f"    {f.name}")
        print()
        print("  The following .data files would be copied:")
        data_files = sorted(src_conf_dir.glob("*.data"))
        for f in data_files:
            print(f"    {f.name}")
        return 0

    # Step 3: Run converter
    print()
    print("Step 3/4: Convert .conf → .yaml")
    ok = run_converter(converter_script, src_conf_dir, output_dir)
    if not ok:
        print("ERROR: Converter failed.", file=sys.stderr)
        return 1

    # Step 4: Copy .data files
    print()
    print("Step 4/4: Copy .data files")
    output_data_dir = output_dir / "data"
    n_data = copy_data_files(src_conf_dir, output_data_dir)
    print(f"  Copied {n_data} .data file(s) → {output_data_dir}")

    # Diff summary
    snapshot_after = snapshot_yaml_dir(output_dir)
    diff = diff_snapshots(snapshot_before, snapshot_after)
    print()
    print_diff(diff)

    print()
    print("  Sync complete.")
    print()
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    global TEMP_BASE  # may be overridden by --temp-dir
    parser = argparse.ArgumentParser(
        description="Sync prx-waf rules from upstream sources.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sync.py --source owasp-crs --output ../owasp-crs/
  python sync.py --source owasp-crs --output ../owasp-crs/ --tag v4.10.0
  python sync.py --source owasp-crs --output ../owasp-crs/ --branch main --dry-run
  python sync.py --check
  python sync.py --check --source owasp-crs
        """,
    )
    parser.add_argument(
        "--source",
        metavar="NAME",
        help="Source name to sync (e.g. owasp-crs). Required unless --check.",
    )
    parser.add_argument(
        "--output",
        metavar="DIR",
        help="Output directory for converted YAML files (overrides config).",
    )
    parser.add_argument(
        "--tag",
        metavar="TAG",
        help="Checkout a specific Git tag (e.g. v4.10.0). Overrides --branch.",
    )
    parser.add_argument(
        "--branch",
        metavar="BRANCH",
        default=None,
        help="Checkout a specific branch (default: main).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only check if updates are available; do not sync.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without writing any files.",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        default=None,
        help="Path to sync-config.yaml (default: auto-detect ../sync-config.yaml).",
    )
    parser.add_argument(
        "--temp-dir",
        metavar="DIR",
        default=str(TEMP_BASE),
        help=f"Temp directory for cloning (default: {TEMP_BASE}).",
    )

    args = parser.parse_args()

    # Allow overriding temp dir via CLI flag
    TEMP_BASE = Path(args.temp_dir)

    # Load config
    sources_cfg = load_config(args.config)

    if args.check:
        return cmd_check(args, sources_cfg)
    else:
        return cmd_sync(args, sources_cfg)


if __name__ == "__main__":
    sys.exit(main())
