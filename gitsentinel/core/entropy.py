"""
GitSentinel Entropy Analyzer
Shannon entropy calculation for detecting high-entropy strings (secrets/tokens).
Uses optimized collections.Counter approach with configurable thresholds.
"""

import math
import re
from collections import Counter
from typing import List, Tuple

# Pre-compiled regex patterns for extracting candidate secret strings
# Matches quoted strings, assignments, and standalone high-entropy tokens
# Safe patterns: no nested quantifiers, bounded repetitions
_RE_QUOTED_STRING = re.compile(r"""(?:["'])([A-Za-z0-9+/=_\-]{12,})(?:["'])""")
_RE_ASSIGNMENT_VALUE = re.compile(
    r"""(?:=|:)\s*["']?([A-Za-z0-9+/=_\-]{12,})["']?"""
)
_RE_STANDALONE_TOKEN = re.compile(
    r"""\b([A-Za-z0-9+/=_\-]{20,})\b"""
)

# Character sets for refined entropy analysis
_HEX_CHARS = set("0123456789abcdefABCDEF")
_BASE64_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)

# Default thresholds
DEFAULT_ENTROPY_THRESHOLD = 4.5
DEFAULT_HEX_ENTROPY_THRESHOLD = 3.0
DEFAULT_MIN_LENGTH = 12
DEFAULT_MAX_LENGTH = 256


def shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string using optimized Counter approach.

    Shannon entropy H = -sum(p * log2(p)) for each unique character probability p.
    Higher entropy indicates more randomness (likely a secret/token).

    Args:
        data: Input string to calculate entropy for.

    Returns:
        Shannon entropy value as float. Range: 0.0 (all same chars) to ~log2(charset_size).
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def is_hex_string(data: str) -> bool:
    """Check if a string contains only hexadecimal characters."""
    return all(c in _HEX_CHARS for c in data)


def is_base64_string(data: str) -> bool:
    """Check if a string contains only base64 characters."""
    return all(c in _BASE64_CHARS for c in data)


def _classify_string_type(data: str) -> str:
    """
    Classify the type of a candidate string for threshold selection.

    Returns:
        One of 'hex', 'base64', or 'generic'.
    """
    if is_hex_string(data):
        return "hex"
    if is_base64_string(data):
        return "base64"
    return "generic"


def extract_candidate_strings(
    line: str, min_length: int = DEFAULT_MIN_LENGTH, max_length: int = DEFAULT_MAX_LENGTH
) -> List[str]:
    """
    Extract candidate secret strings from a line of text.

    Uses multiple regex patterns to find potential secrets:
    1. Quoted strings (single or double quotes)
    2. Assignment values (after = or :)
    3. Standalone high-entropy tokens

    Args:
        line: A single line of text to extract candidates from.
        min_length: Minimum length for a candidate string.
        max_length: Maximum length for a candidate string.

    Returns:
        Deduplicated list of candidate strings.
    """
    candidates = set()

    for pattern in (_RE_QUOTED_STRING, _RE_ASSIGNMENT_VALUE, _RE_STANDALONE_TOKEN):
        for match in pattern.finditer(line):
            token = match.group(1)
            if min_length <= len(token) <= max_length:
                candidates.add(token)

    return list(candidates)


def analyze_entropy(
    line: str,
    line_number: int,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    hex_entropy_threshold: float = DEFAULT_HEX_ENTROPY_THRESHOLD,
    min_length: int = DEFAULT_MIN_LENGTH,
    max_length: int = DEFAULT_MAX_LENGTH,
) -> List[dict]:
    """
    Analyze a line of text for high-entropy strings that may be secrets.

    Extracts candidate strings and checks their Shannon entropy against
    type-specific thresholds (hex strings use a lower threshold).

    Args:
        line: Line of text to analyze.
        line_number: Line number in the source file (1-indexed).
        entropy_threshold: Entropy threshold for generic/base64 strings.
        hex_entropy_threshold: Entropy threshold for hex strings.
        min_length: Minimum candidate string length.
        max_length: Maximum candidate string length.

    Returns:
        List of finding dicts with keys: type, value, line, entropy, string_type, severity.
    """
    findings = []
    candidates = extract_candidate_strings(line, min_length, max_length)

    for candidate in candidates:
        entropy_value = shannon_entropy(candidate)
        string_type = _classify_string_type(candidate)

        # Select threshold based on string type
        threshold = hex_entropy_threshold if string_type == "hex" else entropy_threshold

        if entropy_value >= threshold:
            severity = _calculate_severity(entropy_value, len(candidate), string_type)
            findings.append(
                {
                    "type": "High Entropy String",
                    "value": _mask_secret(candidate),
                    "raw_value": candidate,
                    "line": line_number,
                    "entropy": round(entropy_value, 4),
                    "string_type": string_type,
                    "severity": severity,
                    "description": (
                        f"High entropy {string_type} string detected "
                        f"(entropy: {entropy_value:.2f}, threshold: {threshold:.2f})"
                    ),
                }
            )

    return findings


def _calculate_severity(entropy: float, length: int, string_type: str) -> str:
    """
    Calculate severity level based on entropy value, string length, and type.

    Higher entropy and longer strings indicate higher likelihood of being a real secret.

    Returns:
        Severity level: LOW, MEDIUM, HIGH, or CRITICAL.
    """
    score = entropy

    # Length bonus: longer secrets are more likely real
    if length > 40:
        score += 0.5
    elif length > 30:
        score += 0.3

    # Type bonus: hex and base64 are common secret formats
    if string_type in ("hex", "base64"):
        score += 0.2

    if score >= 5.5:
        return "CRITICAL"
    if score >= 5.0:
        return "HIGH"
    if score >= 4.5:
        return "MEDIUM"
    return "LOW"


def _mask_secret(value: str, visible_chars: int = 4) -> str:
    """
    Mask a secret value for safe display in logs and reports.

    Shows only the first few characters followed by asterisks.

    Args:
        value: The secret value to mask.
        visible_chars: Number of characters to leave visible.

    Returns:
        Masked string like 'AKIA****'.
    """
    if len(value) <= visible_chars:
        return "*" * len(value)
    return value[:visible_chars] + "*" * (len(value) - visible_chars)
