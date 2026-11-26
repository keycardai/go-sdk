#!/usr/bin/env python3
"""
Bump version using commitizen for the Go SDK.

Handles version bumping including retry logic for pushing changes
to avoid race conditions in CI.
"""

import re
import subprocess
import sys
import time
from pathlib import Path


def run_command(cmd: list[str], cwd: str | None = None) -> tuple[int, str, str]:
    """Run a command and return exit code, stdout, and stderr."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=cwd, check=False
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def configure_git() -> None:
    """Configure git for automated commits."""
    print("Configuring git...")
    run_command(["git", "config", "--local", "user.email", "action@github.com"])
    run_command(["git", "config", "--local", "user.name", "GitHub Action"])


def pull_latest_changes() -> bool:
    """Pull latest changes from origin/main, handling local modifications."""
    print("Checking for local changes before pulling...")

    exit_code, stdout, stderr = run_command(["git", "status", "--porcelain"])
    if exit_code != 0:
        print(f"Failed to check git status: {stderr}")
        return False

    has_local_changes = bool(stdout.strip())

    if has_local_changes:
        print(f"Found local changes:\n{stdout}")
        print("Stashing local changes before pulling...")
        exit_code, _, stderr = run_command(
            ["git", "stash", "push", "-m", "Auto-stash before version bump"]
        )
        if exit_code != 0:
            print(f"Failed to stash local changes: {stderr}")
            return False

    print("Pulling latest changes from origin/main...")
    exit_code, _, stderr = run_command(["git", "pull", "origin", "main"])
    if exit_code != 0:
        print(f"Failed to pull latest changes: {stderr}")
        if has_local_changes:
            run_command(["git", "stash", "pop"])
        return False

    if has_local_changes:
        print("Restoring stashed changes...")
        exit_code, _, stderr = run_command(["git", "stash", "pop"])
        if exit_code != 0:
            print(f"Warning: Failed to restore stashed changes: {stderr}")
            # Handle go.sum conflicts
            if "go.sum" in stderr:
                print("Detected go.sum conflict. Resolving...")
                run_command(["git", "checkout", "--theirs", "go.sum"])
                run_command(["git", "add", "go.sum"])
                run_command(["git", "stash", "drop"])

    return True


def has_unreleased_changes() -> bool:
    """Check if there are unreleased changes via cz changelog --dry-run."""
    exit_code, stdout, _ = run_command(["cz", "changelog", "--dry-run"])
    if exit_code != 0 or not stdout.strip():
        return False
    lines = stdout.split("\n")
    if not lines[0].strip().startswith("## Unreleased"):
        return False
    for line in lines[1:]:
        line = line.strip()
        if line.startswith("##"):
            break
        if line:
            return True
    return False


def run_bump() -> bool:
    """Run commitizen bump."""
    print("Running version bump...")
    exit_code, stdout, stderr = run_command(["cz", "bump", "--changelog", "--yes"])
    if exit_code != 0:
        print(f"Failed to bump version: {stderr}")
        return False
    print("Version bump completed successfully")
    print(stdout)
    return True


# Sub-modules with their own go.mod. Each has a <dir>/.cz.toml whose tag_format
# is <dir>/v$version, the tag form the Go toolchain resolves for a sub-module.
SUBMODULES = ["spiffe"]


def submodule_version(name: str) -> str:
    """Return the version recorded in the sub-module's .cz.toml."""
    match = re.search(
        r'^version\s*=\s*"([^"]+)"', (Path(name) / ".cz.toml").read_text(), re.M
    )
    return match.group(1) if match else "0.0.0"


def submodule_increment(name: str) -> str | None:
    """Return the bump increment from commits touching the sub-module since its last tag."""
    _, last_tag, _ = run_command(
        ["git", "describe", "--tags", "--abbrev=0", "--match", f"{name}/v*"]
    )
    rev_range = f"{last_tag}..HEAD" if last_tag else "HEAD"
    exit_code, log, _ = run_command(
        ["git", "log", "--format=%s%n%b%x00", rev_range, "--", f"{name}/"]
    )
    if exit_code != 0:
        return None
    increment = None
    for message in log.split("\0"):
        subject = message.strip().split("\n", 1)[0]
        match = re.match(r"^(feat|fix|refactor|perf)(\(.+\))?(!)?:", subject)
        if not match:
            continue
        if match.group(3) or re.search(r"^BREAKING[- ]CHANGE", message, re.M):
            # Like major_version_zero, a breaking change below 1.0.0 is a
            # minor bump; a Go v2+ module would also need a new module path.
            return "MINOR" if submodule_version(name).startswith("0.") else "MAJOR"
        if match.group(1) == "feat":
            increment = "MINOR"
        elif increment is None:
            increment = "PATCH"
    return increment


def bump_submodules() -> bool:
    """Tag each sub-module with changes since its last tag as <dir>/vX.Y.Z."""
    for name in SUBMODULES:
        config = Path(name) / ".cz.toml"
        if not config.exists():
            continue
        increment = submodule_increment(name)
        if increment is None:
            print(f"No releasable changes in {name}. Skipping its bump.")
            continue
        print(f"Bumping {name} ({increment})...")
        exit_code, stdout, stderr = run_command(
            ["cz", "--config", str(config), "bump", "--yes", "--increment", increment]
        )
        if exit_code != 0:
            print(f"Failed to bump {name}: {stderr}")
            return False
        print(stdout)
    return True


def push_changes_with_retry(max_attempts: int = 3) -> bool:
    """Push changes to origin/main with retry logic."""
    for attempt in range(1, max_attempts + 1):
        print(f"Attempting to push changes (attempt {attempt}/{max_attempts})...")

        exit_code, _, stderr = run_command(
            ["git", "push", "origin", "main", "--follow-tags"]
        )

        if exit_code == 0:
            print(f"Successfully pushed changes on attempt {attempt}")
            print("Explicitly pushing tags...")
            run_command(["git", "push", "origin", "--tags"])
            return True

        print(f"Push failed on attempt {attempt}: {stderr}")

        if attempt < max_attempts:
            print("Pulling latest changes and retrying...")
            if not pull_latest_changes():
                continue
            print("Waiting 2 seconds before retry...")
            time.sleep(2)
        else:
            print(f"Failed to push after {max_attempts} attempts")

    return False


def main():
    print("Starting version bump for go-sdk...")

    configure_git()

    if not pull_latest_changes():
        sys.exit(1)

    if has_unreleased_changes():
        if not run_bump():
            sys.exit(1)
    else:
        print("No unreleased changes detected. Skipping root bump.")

    if not bump_submodules():
        sys.exit(1)

    exit_code, ahead, _ = run_command(["git", "rev-list", "--count", "origin/main..HEAD"])
    if exit_code == 0 and ahead == "0":
        print("Nothing to push.")
        return

    if not push_changes_with_retry():
        sys.exit(1)

    print("Successfully completed version bump")


if __name__ == "__main__":
    main()
