"""
GitSentinel Alert System
Severity-based alerting with rich terminal output and commit blocking logic.
"""

import json
import os
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Dict, List, Optional


class Severity(IntEnum):
    """Severity levels for detected secrets, ordered by criticality."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# Map severity to action descriptions
SEVERITY_ACTIONS = {
    Severity.LOW: "Warning",
    Severity.MEDIUM: "Warning + Confirmation",
    Severity.HIGH: "Commit Block",
    Severity.CRITICAL: "Force Block",
}

# Map string severity names to enum values
SEVERITY_MAP = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def parse_severity(name: str) -> Severity:
    """
    Parse a severity name string into a Severity enum.

    Args:
        name: Severity name (case-insensitive).

    Returns:
        Corresponding Severity enum value.

    Raises:
        ValueError: If the severity name is not recognized.
    """
    upper = name.upper().strip()
    if upper not in SEVERITY_MAP:
        raise ValueError(
            f"Unknown severity '{name}'. Valid values: {list(SEVERITY_MAP.keys())}"
        )
    return SEVERITY_MAP[upper]


class Finding:
    """Represents a single secret finding with all associated metadata."""

    __slots__ = (
        "file_path", "line_number", "rule_id", "description",
        "severity", "matched_value", "raw_value", "detection_method",
    )

    def __init__(
        self,
        file_path: str,
        line_number: int,
        rule_id: str,
        description: str,
        severity: str,
        matched_value: str,
        raw_value: str = "",
        detection_method: str = "regex",
    ):
        self.file_path = file_path
        self.line_number = line_number
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.matched_value = matched_value
        self.raw_value = raw_value
        self.detection_method = detection_method

    def to_dict(self) -> Dict[str, Any]:
        """Serialize finding to dictionary (excluding raw_value for safety)."""
        return {
            "file": self.file_path,
            "line": self.line_number,
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "matched_value": self.matched_value,
            "detection_method": self.detection_method,
        }

    def __repr__(self) -> str:
        return (
            f"Finding(file={self.file_path!r}, line={self.line_number}, "
            f"rule={self.rule_id!r}, severity={self.severity!r})"
        )


class AlertManager:
    """
    Manages findings, determines commit blocking, and generates reports.

    Collects all findings from a scan, determines the overall action
    (allow/block commit), and generates JSON reports.
    """

    def __init__(self, block_severity: str = "HIGH"):
        """
        Initialize the alert manager.

        Args:
            block_severity: Minimum severity level that triggers a commit block.
                           Findings at or above this level block the commit.
        """
        self.findings: List[Finding] = []
        self.block_threshold = parse_severity(block_severity)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the collection."""
        self.findings.append(finding)

    def add_findings(self, findings: List[Finding]) -> None:
        """Add multiple findings to the collection."""
        self.findings.extend(findings)

    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def should_block_commit(self) -> bool:
        """
        Determine if the commit should be blocked based on findings.

        Returns True if any finding has severity >= block_threshold.
        """
        for finding in self.findings:
            severity_enum = parse_severity(finding.severity)
            if severity_enum >= self.block_threshold:
                return True
        return False

    @property
    def max_severity(self) -> Optional[str]:
        """Get the highest severity level among all findings."""
        if not self.findings:
            return None
        max_sev = Severity.LOW
        for finding in self.findings:
            sev = parse_severity(finding.severity)
            if sev > max_sev:
                max_sev = sev
        return max_sev.name

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        """Filter findings by severity level."""
        return [f for f in self.findings if f.severity.upper() == severity.upper()]

    def get_findings_by_file(self, file_path: str) -> List[Finding]:
        """Filter findings by file path."""
        return [f for f in self.findings if f.file_path == file_path]

    def get_summary(self) -> Dict[str, Any]:
        """
        Generate a summary of all findings.

        Returns:
            Dictionary with counts by severity, total count, and block decision.
        """
        summary = {
            "total": self.total_findings,
            "by_severity": {
                "CRITICAL": len(self.get_findings_by_severity("CRITICAL")),
                "HIGH": len(self.get_findings_by_severity("HIGH")),
                "MEDIUM": len(self.get_findings_by_severity("MEDIUM")),
                "LOW": len(self.get_findings_by_severity("LOW")),
            },
            "should_block": self.should_block_commit,
            "max_severity": self.max_severity,
            "files_affected": list({f.file_path for f in self.findings}),
        }
        return summary

    def generate_report(
        self, output_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate a JSON report of all findings.

        Args:
            output_path: If provided, write the report to this file path.

        Returns:
            Complete report as dictionary.
        """
        report = {
            "tool": "GitSentinel",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": self.get_summary(),
            "findings": [f.to_dict() for f in self.findings],
        }

        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, ensure_ascii=False)

        return report

    def clear(self) -> None:
        """Clear all findings."""
        self.findings.clear()
