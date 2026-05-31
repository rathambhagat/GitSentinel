"""
GitSentinel Secret Detector
Regex-based detection engine that loads rules and matches against file content.
All regex patterns are compiled at module load time for performance.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from gitsentinel.core.alerts import Finding
from gitsentinel.core.entropy import analyze_entropy


class SecretRule:
    """
    A single detection rule with a compiled regex pattern.

    Attributes:
        rule_id: Unique identifier for the rule (e.g., 'aws-access-key').
        description: Human-readable description of what this rule detects.
        pattern: Pre-compiled regex pattern.
        severity: Severity level (LOW, MEDIUM, HIGH, CRITICAL).
        keywords: Optional list of keywords to pre-filter lines (performance optimization).
    """

    __slots__ = ("rule_id", "description", "pattern", "severity", "keywords")

    def __init__(
        self,
        rule_id: str,
        description: str,
        pattern: "re.Pattern[str]",
        severity: str = "HIGH",
        keywords: Optional[List[str]] = None,
    ):
        self.rule_id = rule_id
        self.description = description
        self.pattern = pattern
        self.severity = severity
        self.keywords = keywords or []

    def matches(self, line: str) -> List[str]:
        """
        Check if a line matches this rule.

        If keywords are defined, the line is pre-filtered for performance.
        Only lines containing at least one keyword are tested against the regex.

        Args:
            line: Line of text to check.

        Returns:
            List of matched strings found in the line.
        """
        # Keyword pre-filter: skip regex if no keywords found in line
        if self.keywords:
            line_lower = line.lower()
            if not any(kw in line_lower for kw in self.keywords):
                return []

        return self.pattern.findall(line)


class SecretDetector:
    """
    Main detection engine that combines regex rules and entropy analysis.

    Loads rules from rule modules, scans file content line by line,
    and produces Finding objects for each detected secret.
    """

    def __init__(
        self,
        entropy_enabled: bool = True,
        entropy_threshold: float = 4.5,
        hex_entropy_threshold: float = 3.0,
    ):
        """
        Initialize the detector.

        Args:
            entropy_enabled: Whether to run entropy analysis.
            entropy_threshold: Shannon entropy threshold for generic strings.
            hex_entropy_threshold: Shannon entropy threshold for hex strings.
        """
        self.rules: List[SecretRule] = []
        self.entropy_enabled = entropy_enabled
        self.entropy_threshold = entropy_threshold
        self.hex_entropy_threshold = hex_entropy_threshold
        self._ignore_patterns: List[re.Pattern] = []
        self._allowlist: List[str] = []

    def add_rule(self, rule: SecretRule) -> None:
        """Add a detection rule."""
        self.rules.append(rule)

    def add_rules(self, rules: List[SecretRule]) -> None:
        """Add multiple detection rules."""
        self.rules.extend(rules)

    def set_ignore_patterns(self, patterns: List[str]) -> None:
        """
        Set patterns for lines to ignore (e.g., test fixtures, examples).

        Args:
            patterns: List of regex pattern strings.
        """
        self._ignore_patterns = [re.compile(p) for p in patterns]

    def set_allowlist(self, values: List[str]) -> None:
        """
        Set allowlisted values that should not trigger findings.

        Args:
            values: List of known-safe values to allowlist.
        """
        self._allowlist = [v.lower() for v in values]

    def _should_ignore_line(self, line: str) -> bool:
        """
        Check if a line should be ignored based on ignore patterns
        or inline ignore comments.

        Args:
            line: Line of text to check.

        Returns:
            True if the line should be skipped.
        """
        # Check for inline ignore directive
        if "gitsentinel:ignore" in line:
            return True

        # Check against ignore patterns
        for pattern in self._ignore_patterns:
            if pattern.search(line):
                return True

        return False

    def _is_allowlisted(self, value: str) -> bool:
        """Check if a matched value is in the allowlist."""
        return value.lower() in self._allowlist

    def scan_content(
        self, content: str, file_path: str
    ) -> List[Finding]:
        """
        Scan text content for secrets using all loaded rules and entropy analysis.

        Args:
            content: Full text content of the file.
            file_path: Path to the file (for findings metadata).

        Returns:
            List of Finding objects for all detected secrets.
        """
        findings: List[Finding] = []
        lines = content.split("\n")

        for line_number, line in enumerate(lines, start=1):
            # Skip empty lines and ignored lines
            if not line.strip():
                continue
            if self._should_ignore_line(line):
                continue

            # Regex-based detection
            for rule in self.rules:
                matches = rule.matches(line)
                for match_value in matches:
                    # Handle tuple matches from regex groups
                    if isinstance(match_value, tuple):
                        match_value = match_value[0] if match_value else ""

                    if not match_value or self._is_allowlisted(match_value):
                        continue

                    masked = _mask_value(match_value)
                    finding = Finding(
                        file_path=file_path,
                        line_number=line_number,
                        rule_id=rule.rule_id,
                        description=rule.description,
                        severity=rule.severity,
                        matched_value=masked,
                        raw_value=match_value,
                        detection_method="regex",
                    )
                    findings.append(finding)

            # Entropy-based detection
            if self.entropy_enabled:
                entropy_findings = analyze_entropy(
                    line,
                    line_number,
                    entropy_threshold=self.entropy_threshold,
                    hex_entropy_threshold=self.hex_entropy_threshold,
                )
                for ef in entropy_findings:
                    raw_val = ef.get("raw_value", "")
                    if self._is_allowlisted(raw_val):
                        continue

                    # Avoid duplicate findings from regex + entropy
                    if any(
                        f.line_number == line_number and f.raw_value == raw_val
                        for f in findings
                    ):
                        continue

                    finding = Finding(
                        file_path=file_path,
                        line_number=line_number,
                        rule_id="entropy-detection",
                        description=ef["description"],
                        severity=ef["severity"],
                        matched_value=ef["value"],
                        raw_value=raw_val,
                        detection_method="entropy",
                    )
                    findings.append(finding)

        return findings


def _mask_value(value: str, visible: int = 4) -> str:
    """Mask a secret value for safe display."""
    if len(value) <= visible:
        return "*" * len(value)
    return value[:visible] + "*" * min(len(value) - visible, 20)


def load_all_rules() -> List[SecretRule]:
    """
    Load all built-in detection rules from the rules modules.

    Returns:
        Combined list of all SecretRule objects from all rule modules.
    """
    from gitsentinel.rules.aws import get_aws_rules
    from gitsentinel.rules.jwt import get_jwt_rules
    from gitsentinel.rules.github import get_github_rules
    from gitsentinel.rules.generic import get_generic_rules

    all_rules: List[SecretRule] = []
    all_rules.extend(get_aws_rules())
    all_rules.extend(get_jwt_rules())
    all_rules.extend(get_github_rules())
    all_rules.extend(get_generic_rules())
    return all_rules
