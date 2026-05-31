"""
GitSentinel Pre-Commit Hook
Integrates with Git to scan staged files before each commit.
Blocks commits when high-severity secrets are detected.
"""

import os
import sys


def run_pre_commit_scan() -> int:
    """
    Execute the pre-commit scan.

    This function is called by the Git pre-commit hook script.
    It scans all staged files and blocks the commit if high-severity
    secrets are detected.

    Returns:
        Exit code: 0 = allow commit, 1 = block commit.
    """
    # Add project root to path for imports
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from gitsentinel.core.scanner import FileScanner, get_staged_files
    from gitsentinel.core.alerts import AlertManager
    from gitsentinel.config.manager import load_config

    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        console = Console(stderr=True)
        rich_available = True
    except ImportError:
        rich_available = False

    # Load configuration
    config = load_config()

    # Get staged files
    staged_files = get_staged_files()
    if not staged_files:
        return 0

    # Initialize scanner
    scanner = FileScanner(
        cache_enabled=config.get("cache", {}).get("enabled", True),
        entropy_enabled=config.get("entropy", {}).get("enabled", True),
        entropy_threshold=config.get("entropy", {}).get("threshold", 4.5),
        hex_entropy_threshold=config.get("entropy", {}).get("hex_threshold", 3.0),
    )

    # Load ignore patterns
    repo_root = os.getcwd()
    scanner.load_ignore_patterns(repo_root)

    # Scan staged files
    alert_manager = scanner.scan_files(staged_files, parallel=len(staged_files) > 3)

    if alert_manager.total_findings == 0:
        if rich_available:
            console.print(
                Panel(
                    "[bold green]✓ GitSentinel: No secrets detected[/bold green]",
                    border_style="green",
                    box=box.ROUNDED,
                )
            )
        else:
            print("✓ GitSentinel: No secrets detected", file=sys.stderr)
        return 0

    # Display findings
    if rich_available:
        _display_rich_findings(console, alert_manager)
    else:
        _display_plain_findings(alert_manager)

    # Determine action
    if alert_manager.should_block_commit:
        if rich_available:
            console.print(
                Panel(
                    "[bold red]✗ COMMIT BLOCKED: High-severity secrets detected![/bold red]\n"
                    "Remove the secrets and try again.\n"
                    "Use 'gitsentinel:ignore' inline comment to suppress false positives.",
                    title="[red]GitSentinel[/red]",
                    border_style="red",
                    box=box.HEAVY,
                )
            )
        else:
            print("\n✗ COMMIT BLOCKED: High-severity secrets detected!", file=sys.stderr)
            print("Remove the secrets and try again.", file=sys.stderr)
        return 1

    # Non-blocking warnings
    if rich_available:
        console.print(
            Panel(
                "[bold yellow]⚠ GitSentinel: Warnings detected (commit allowed)[/bold yellow]\n"
                "Review the findings above.",
                border_style="yellow",
                box=box.ROUNDED,
            )
        )
    else:
        print("\n⚠ GitSentinel: Warnings detected (commit allowed)", file=sys.stderr)

    return 0


def _display_rich_findings(console: "Console", alert_manager: "AlertManager") -> None:
    """Display findings using rich tables."""
    from rich.table import Table
    from rich import box

    summary = alert_manager.get_summary()

    console.print()
    console.print("[bold red]🔒 GitSentinel Secret Scan Results[/bold red]")
    console.print()

    # Summary table
    summary_table = Table(
        title="Scan Summary",
        box=box.SIMPLE_HEAVY,
        show_lines=False,
    )
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")

    severity_styles = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
    }

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = summary["by_severity"][sev]
        if count > 0:
            style = severity_styles[sev]
            summary_table.add_row(f"[{style}]{sev}[/{style}]", str(count))

    console.print(summary_table)
    console.print()

    # Findings detail table
    detail_table = Table(
        title="Findings Detail",
        box=box.ROUNDED,
        show_lines=True,
    )
    detail_table.add_column("File", style="cyan", max_width=40)
    detail_table.add_column("Line", justify="right", style="magenta")
    detail_table.add_column("Rule", style="white")
    detail_table.add_column("Severity", style="bold")
    detail_table.add_column("Match", style="dim")

    for finding in alert_manager.findings:
        sev = finding.severity
        style = severity_styles.get(sev, "white")
        detail_table.add_row(
            finding.file_path,
            str(finding.line_number),
            finding.rule_id,
            f"[{style}]{sev}[/{style}]",
            finding.matched_value,
        )

    console.print(detail_table)


def _display_plain_findings(alert_manager: "AlertManager") -> None:
    """Display findings as plain text (fallback when rich is not available)."""
    print("\n🔒 GitSentinel Secret Scan Results", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    for finding in alert_manager.findings:
        print(
            f"  [{finding.severity}] {finding.file_path}:{finding.line_number} "
            f"- {finding.rule_id}: {finding.matched_value}",
            file=sys.stderr,
        )

    summary = alert_manager.get_summary()
    print(f"\nTotal: {summary['total']} findings", file=sys.stderr)


# Hook script content template
PRE_COMMIT_HOOK_SCRIPT = """#!/usr/bin/env python3
\"\"\"GitSentinel pre-commit hook. Auto-installed by 'gitsentinel install'.\"\"\"
import sys
import os

# Add project to path
hook_dir = os.path.dirname(os.path.abspath(__file__))
repo_root = os.path.dirname(os.path.dirname(hook_dir))
sys.path.insert(0, repo_root)

try:
    from gitsentinel.hooks.pre_commit import run_pre_commit_scan
    sys.exit(run_pre_commit_scan())
except ImportError:
    # Fallback: try running as module
    import subprocess
    result = subprocess.run(
        [sys.executable, "-m", "gitsentinel", "scan", "--staged"],
        cwd=repo_root,
    )
    sys.exit(result.returncode)
except Exception as e:
    print(f"GitSentinel hook error: {e}", file=sys.stderr)
    sys.exit(0)  # Don't block commit on hook errors
"""

SHELL_HOOK_SCRIPT = """#!/bin/sh
# GitSentinel pre-commit hook
python3 -c "
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath('$0')))))
try:
    from gitsentinel.hooks.pre_commit import run_pre_commit_scan
    sys.exit(run_pre_commit_scan())
except Exception as e:
    print(f'GitSentinel error: {e}', file=sys.stderr)
    sys.exit(0)
" "$0"
"""


def install_hook(repo_path: str = ".") -> str:
    """
    Install the pre-commit hook into the Git repository.

    Writes the hook script to .git/hooks/pre-commit and makes it executable.

    Args:
        repo_path: Path to the repository root. Defaults to current directory.

    Returns:
        Path to the installed hook file.

    Raises:
        FileNotFoundError: If the .git directory is not found.
    """
    git_dir = os.path.join(repo_path, ".git")
    if not os.path.isdir(git_dir):
        raise FileNotFoundError(
            f"No .git directory found at '{os.path.abspath(repo_path)}'. "
            "Are you in a Git repository?"
        )

    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)

    hook_path = os.path.join(hooks_dir, "pre-commit")

    # Check for existing hook
    if os.path.exists(hook_path):
        # Read existing hook to check if it's ours
        with open(hook_path, "r", encoding="utf-8", errors="replace") as fh:
            existing = fh.read()
        if "gitsentinel" not in existing.lower():
            # Back up existing hook
            backup_path = hook_path + ".backup"
            os.rename(hook_path, backup_path)

    # Write hook script
    with open(hook_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(PRE_COMMIT_HOOK_SCRIPT)

    # Make executable on Unix
    if os.name != "nt":
        os.chmod(hook_path, 0o755)

    return hook_path


if __name__ == "__main__":
    sys.exit(run_pre_commit_scan())
