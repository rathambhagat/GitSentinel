"""
GitSentinel CLI Entry Point
Provides the command-line interface using argparse.
Commands: install, scan, report, config, rules
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import List, Optional


def _get_console():
    """Get a rich Console instance, or None if unavailable."""
    try:
        from rich.console import Console
        return Console()
    except ImportError:
        return None



def _print(msg: str, style: str = "", console=None) -> None:
    """Print with optional rich styling."""
    if console and style:
        console.print(f"[{style}]{msg}[/{style}]")
    elif console:
        console.print(msg)
    else:
        print(msg)


def cmd_install(args: argparse.Namespace) -> int:
    """Install the pre-commit hook into the current Git repository."""
    console = _get_console()

    repo_path = args.path if hasattr(args, "path") and args.path else "."

    try:
        from gitsentinel.hooks.pre_commit import install_hook

        hook_path = install_hook(repo_path)
        _print(f"[+] Pre-commit hook installed at: {hook_path}", "bold green", console)
        _print("GitSentinel will now scan staged files before each commit.", "", console)
        return 0
    except FileNotFoundError as e:
        _print(f"[!] Error: {e}", "bold red", console)
        return 1
    except Exception as e:
        _print(f"[!] Unexpected error: {e}", "bold red", console)
        return 1


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan files for secrets."""
    console = _get_console()

    from gitsentinel.core.scanner import FileScanner, get_staged_files, get_all_tracked_files
    from gitsentinel.config.manager import load_config

    config = load_config(getattr(args, "config", None))

    scanner = FileScanner(
        cache_enabled=config.get("cache", {}).get("enabled", True),
        entropy_enabled=config.get("entropy", {}).get("enabled", True),
        entropy_threshold=config.get("entropy", {}).get("threshold", 4.5),
        hex_entropy_threshold=config.get("entropy", {}).get("hex_threshold", 3.0),
    )

    repo_root = os.getcwd()
    scanner.load_ignore_patterns(repo_root)

    # Determine which files to scan
    if getattr(args, "staged", False):
        files = get_staged_files()
        scan_type = "staged files"
    elif getattr(args, "files", None):
        files = args.files
        scan_type = f"{len(files)} specified file(s)"
    else:
        files = get_all_tracked_files()
        # Convert to absolute paths
        files = [
            os.path.join(repo_root, f) if not os.path.isabs(f) else f
            for f in files
        ]
        scan_type = "all tracked files"

    if not files:
        _print("No files to scan.", "yellow", console)
        return 0

    _print(f"[*] Scanning {scan_type}...", "bold cyan", console)

    alert_manager = scanner.scan_files(files, parallel=len(files) > 3)

    # Display results
    if alert_manager.total_findings == 0:
        _print("[+] No secrets detected!", "bold green", console)
        return 0

    # Display findings
    _display_findings(alert_manager, console)

    # Generate report if requested
    if getattr(args, "output", None):
        report = alert_manager.generate_report(args.output)
        _print(f"\n[>] Report saved to: {args.output}", "bold cyan", console)

    if alert_manager.should_block_commit:
        _print(
            f"\n[!] Found {alert_manager.total_findings} secret(s) "
            f"(max severity: {alert_manager.max_severity})",
            "bold red",
            console,
        )
        return 1

    _print(
        f"\n[~] Found {alert_manager.total_findings} finding(s) (warnings only)",
        "yellow",
        console,
    )
    return 0


def _display_findings(alert_manager, console) -> None:
    """Display findings with rich formatting if available."""
    try:
        from rich.table import Table
        from rich import box

        table = Table(
            title="GitSentinel Findings",
            box=box.ROUNDED,
            show_lines=True,
        )
        table.add_column("File", style="cyan", max_width=45)
        table.add_column("Line", justify="right", style="magenta")
        table.add_column("Rule", style="white")
        table.add_column("Severity", style="bold")
        table.add_column("Method", style="dim")
        table.add_column("Match", style="dim", max_width=30)

        severity_styles = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
        }

        for f in alert_manager.findings:
            sev_style = severity_styles.get(f.severity, "white")
            table.add_row(
                f.file_path,
                str(f.line_number),
                f.rule_id,
                f"[{sev_style}]{f.severity}[/{sev_style}]",
                f.detection_method,
                f.matched_value,
            )

        if console:
            console.print(table)
        else:
            # Fallback
            for f in alert_manager.findings:
                print(
                    f"  [{f.severity}] {f.file_path}:{f.line_number} "
                    f"- {f.rule_id}: {f.matched_value}"
                )
    except ImportError:
        for f in alert_manager.findings:
            print(
                f"  [{f.severity}] {f.file_path}:{f.line_number} "
                f"- {f.rule_id}: {f.matched_value}"
            )


def cmd_report(args: argparse.Namespace) -> int:
    """Generate a scan report."""
    console = _get_console()

    from gitsentinel.core.scanner import FileScanner, get_all_tracked_files
    from gitsentinel.config.manager import load_config

    config = load_config(getattr(args, "config", None))
    output_dir = config.get("reporting", {}).get("output_dir", "reports")

    scanner = FileScanner(
        cache_enabled=config.get("cache", {}).get("enabled", True),
        entropy_enabled=config.get("entropy", {}).get("enabled", True),
        entropy_threshold=config.get("entropy", {}).get("threshold", 4.5),
    )

    repo_root = os.getcwd()
    scanner.load_ignore_patterns(repo_root)

    files = get_all_tracked_files()
    files = [
        os.path.join(repo_root, f) if not os.path.isabs(f) else f
        for f in files
    ]

    _print("[*] Scanning repository for report generation...", "bold cyan", console)

    alert_manager = scanner.scan_files(files, parallel=len(files) > 3)

    # Generate report filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = getattr(args, "output", None) or os.path.join(
        output_dir, f"gitsentinel_report_{timestamp}.json"
    )

    report = alert_manager.generate_report(output_path)

    _print(f"[+] Report generated: {output_path}", "bold green", console)
    _print(f"  Total findings: {report['summary']['total']}", "", console)
    _print(f"  Files affected: {len(report['summary']['files_affected'])}", "", console)

    return 0


def cmd_config(args: argparse.Namespace) -> int:
    """Manage configuration."""
    console = _get_console()

    from gitsentinel.config.manager import save_default_config, load_config

    action = getattr(args, "action", "show")

    if action == "init":
        output = getattr(args, "output", None) or ".gitsentinel.yml"
        path = save_default_config(output)
        _print(f"[+] Configuration file created: {path}", "bold green", console)
        return 0

    if action == "show":
        config = load_config(getattr(args, "config_file", None))
        _print("Current Configuration:", "bold cyan", console)
        print(json.dumps(config, indent=2))
        return 0

    _print(f"Unknown config action: {action}", "red", console)
    return 1


def cmd_rules(args: argparse.Namespace) -> int:
    """List available detection rules."""
    console = _get_console()

    from gitsentinel.core.detector import load_all_rules

    rules = load_all_rules()

    try:
        from rich.table import Table
        from rich import box

        table = Table(
            title="GitSentinel Detection Rules",
            box=box.ROUNDED,
            show_lines=False,
        )
        table.add_column("#", justify="right", style="dim")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Description", style="white")
        table.add_column("Severity", style="bold")

        severity_styles = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
        }

        for i, rule in enumerate(rules, 1):
            sev_style = severity_styles.get(rule.severity, "white")
            table.add_row(
                str(i),
                rule.rule_id,
                rule.description,
                f"[{sev_style}]{rule.severity}[/{sev_style}]",
            )

        if console:
            console.print(table)
        else:
            for rule in rules:
                print(f"  {rule.rule_id}: {rule.description} [{rule.severity}]")

    except ImportError:
        for rule in rules:
            print(f"  {rule.rule_id}: {rule.description} [{rule.severity}]")

    _print(f"\nTotal: {len(rules)} rules loaded", "bold", console)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="gitsentinel",
        description="GitSentinel - Intelligent Git Secret Scanner",
        epilog="Protect your repositories from accidental secret exposure.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="GitSentinel 1.0.0",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # install command
    install_parser = subparsers.add_parser(
        "install", help="Install pre-commit hook"
    )
    install_parser.add_argument(
        "--path", default=".", help="Repository path (default: current directory)"
    )

    # scan command
    scan_parser = subparsers.add_parser(
        "scan", help="Scan files for secrets"
    )
    scan_parser.add_argument(
        "--staged", action="store_true", help="Scan only staged files"
    )
    scan_parser.add_argument(
        "--files", nargs="+", help="Specific files to scan"
    )
    scan_parser.add_argument(
        "--output", "-o", help="Output report file path"
    )
    scan_parser.add_argument(
        "--config", help="Path to config file"
    )

    # report command
    report_parser = subparsers.add_parser(
        "report", help="Generate a scan report"
    )
    report_parser.add_argument(
        "--output", "-o", help="Output file path"
    )
    report_parser.add_argument(
        "--config", help="Path to config file"
    )

    # config command
    config_parser = subparsers.add_parser(
        "config", help="Manage configuration"
    )
    config_parser.add_argument(
        "action",
        nargs="?",
        default="show",
        choices=["init", "show"],
        help="Config action: init (create default), show (display current)",
    )
    config_parser.add_argument(
        "--output", "-o", help="Output path for config init"
    )

    # rules command
    rules_parser = subparsers.add_parser(
        "rules", help="Manage detection rules"
    )
    rules_parser.add_argument(
        "action",
        nargs="?",
        default="list",
        choices=["list"],
        help="Rules action",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point for the GitSentinel CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    commands = {
        "install": cmd_install,
        "scan": cmd_scan,
        "report": cmd_report,
        "config": cmd_config,
        "rules": cmd_rules,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
