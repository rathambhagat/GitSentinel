"""Tests for the GitSentinel entropy analyzer."""

import pytest
from gitsentinel.core.entropy import (
    shannon_entropy,
    is_hex_string,
    is_base64_string,
    extract_candidate_strings,
    analyze_entropy,
    _mask_secret,
    _calculate_severity,
)


class TestShannonEntropy:
    """Tests for Shannon entropy calculation."""

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_character(self):
        assert shannon_entropy("a") == 0.0

    def test_repeated_character(self):
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_two_characters_equal(self):
        # "ab" -> each has probability 0.5, entropy = -2*(0.5*log2(0.5)) = 1.0
        result = shannon_entropy("ab")
        assert abs(result - 1.0) < 0.001

    def test_high_entropy_random(self):
        # A random-looking string should have high entropy
        high_entropy_str = "aB3kL9mP2xQ7wR5"
        result = shannon_entropy(high_entropy_str)
        assert result > 3.5

    def test_low_entropy_pattern(self):
        # A string with few unique characters should have low entropy
        result = shannon_entropy("aaabbb")
        assert result < 1.5

    def test_known_entropy_value(self):
        # "abcd" has 4 unique chars, each with probability 0.25
        # H = -4 * (0.25 * log2(0.25)) = -4 * (0.25 * -2) = 2.0
        result = shannon_entropy("abcd")
        assert abs(result - 2.0) < 0.001

    def test_hex_string_entropy(self):
        result = shannon_entropy("deadbeef1234abcd")
        assert result > 2.0

    def test_real_api_key_entropy(self):
        # A typical API key should have high entropy
        fake_key = "sk_live_92js82js82js82js82kd92"
        result = shannon_entropy(fake_key)
        assert result > 3.0


class TestStringClassification:
    """Tests for hex/base64 string classification."""

    def test_hex_string_valid(self):
        assert is_hex_string("deadbeef1234") is True

    def test_hex_string_invalid(self):
        assert is_hex_string("not_hex_xyz") is False

    def test_hex_string_empty(self):
        assert is_hex_string("") is True  # vacuously true

    def test_base64_string_valid(self):
        assert is_base64_string("SGVsbG8gV29ybGQ=") is True

    def test_base64_string_invalid(self):
        assert is_base64_string("has spaces!") is False

    def test_base64_with_plus_slash(self):
        assert is_base64_string("abc+def/ghi=") is True


class TestExtractCandidateStrings:
    """Tests for candidate string extraction from lines."""

    def test_quoted_string(self):
        line = 'API_KEY = "sk_live_1234567890abcdef"'
        candidates = extract_candidate_strings(line)
        assert any("sk_live_1234567890abcdef" in c for c in candidates)

    def test_single_quoted_string(self):
        line = "SECRET = 'aVeryLongSecretValue123'"
        candidates = extract_candidate_strings(line)
        assert any("aVeryLongSecretValue123" in c for c in candidates)

    def test_assignment_value(self):
        line = "token = abcdef123456789012"
        candidates = extract_candidate_strings(line)
        assert any("abcdef123456789012" in c for c in candidates)

    def test_short_string_filtered(self):
        line = 'KEY = "short"'
        candidates = extract_candidate_strings(line, min_length=12)
        assert len(candidates) == 0

    def test_empty_line(self):
        candidates = extract_candidate_strings("")
        assert candidates == []

    def test_no_candidates(self):
        line = "just a normal comment with no secrets"
        candidates = extract_candidate_strings(line)
        assert len(candidates) == 0


class TestAnalyzeEntropy:
    """Tests for the full entropy analysis pipeline."""

    def test_high_entropy_detection(self):
        line = 'API_KEY = "k9X2mP7qL4wR8nT5vB3jH6dF1cY0aE9"'
        findings = analyze_entropy(line, 1, entropy_threshold=3.5)
        assert len(findings) > 0
        assert findings[0]["type"] == "High Entropy String"

    def test_low_entropy_no_detection(self):
        line = 'message = "hello world hello world"'
        findings = analyze_entropy(line, 1, entropy_threshold=4.5)
        assert len(findings) == 0

    def test_finding_has_correct_fields(self):
        line = 'token = "xK9m2P7qL4wR8nT5vB3jH6dF"'
        findings = analyze_entropy(line, 42, entropy_threshold=3.0)
        if findings:
            f = findings[0]
            assert "type" in f
            assert "value" in f
            assert "line" in f
            assert f["line"] == 42
            assert "entropy" in f
            assert "severity" in f

    def test_masked_value(self):
        line = 'secret = "ABCDEFGHIJKLMNOPQRST"'
        findings = analyze_entropy(line, 1, entropy_threshold=2.0)
        if findings:
            # Masked value should not reveal the full secret
            assert "****" in findings[0]["value"]


class TestMaskSecret:
    """Tests for the secret masking function."""

    def test_normal_masking(self):
        result = _mask_secret("AKIAIOSFODNN7EXAMPLE")
        assert result.startswith("AKIA")
        assert "****" in result

    def test_short_string_fully_masked(self):
        result = _mask_secret("abc", visible_chars=4)
        assert result == "***"

    def test_exact_length(self):
        result = _mask_secret("abcd", visible_chars=4)
        assert result == "****"

    def test_empty_string(self):
        result = _mask_secret("")
        assert result == ""


class TestCalculateSeverity:
    """Tests for severity calculation."""

    def test_critical_severity(self):
        result = _calculate_severity(5.5, 45, "base64")
        assert result == "CRITICAL"

    def test_high_severity(self):
        result = _calculate_severity(5.0, 20, "generic")
        assert result == "HIGH"

    def test_medium_severity(self):
        result = _calculate_severity(4.5, 15, "generic")
        assert result == "MEDIUM"

    def test_low_severity(self):
        result = _calculate_severity(3.5, 15, "generic")
        assert result == "LOW"

    def test_length_bonus(self):
        # Long secret should get higher severity
        short_sev = _calculate_severity(4.3, 15, "generic")
        long_sev = _calculate_severity(4.3, 45, "generic")
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        assert severity_order[long_sev] >= severity_order[short_sev]
