"""Tests for the GitSentinel scanner and detector."""

import os
import tempfile
import pytest

from gitsentinel.core.detector import SecretDetector, SecretRule, load_all_rules, _mask_value
from gitsentinel.core.alerts import Finding, AlertManager, Severity, parse_severity
from gitsentinel.core.scanner import is_binary_file, read_file_content, _should_ignore_file
from gitsentinel.core.cache import FileHashCache, compute_file_hash


class TestSecretRule:
    """Tests for individual SecretRule matching."""

    def test_rule_matches(self):
        import re
        pattern = re.compile(r"(AKIA[A-Z0-9]{16})")
        rule = SecretRule(
            rule_id="test-aws",
            description="Test AWS key",
            pattern=pattern,
            severity="CRITICAL",
        )
        matches = rule.matches("my key is AKIAIOSFODNN7EXAMPLE here")
        assert len(matches) == 1
        assert matches[0] == "AKIAIOSFODNN7EXAMPLE"

    def test_rule_no_match(self):
        import re
        pattern = re.compile(r"(AKIA[A-Z0-9]{16})")
        rule = SecretRule(
            rule_id="test-aws",
            description="Test AWS key",
            pattern=pattern,
            severity="CRITICAL",
        )
        matches = rule.matches("nothing secret here")
        assert len(matches) == 0

    def test_rule_keyword_filter(self):
        import re
        pattern = re.compile(r"(AKIA[A-Z0-9]{16})")
        rule = SecretRule(
            rule_id="test-aws",
            description="Test AWS key",
            pattern=pattern,
            severity="CRITICAL",
            keywords=["akia"],
        )
        # Line contains keyword -> should check regex
        matches = rule.matches("AKIAIOSFODNN7EXAMPLE")
        assert len(matches) == 1

    def test_rule_keyword_skip(self):
        import re
        pattern = re.compile(r"(AKIA[A-Z0-9]{16})")
        rule = SecretRule(
            rule_id="test-aws",
            description="Test AWS key",
            pattern=pattern,
            severity="CRITICAL",
            keywords=["akia"],
        )
        # Line does NOT contain keyword -> should skip regex
        matches = rule.matches("just a normal line")
        assert len(matches) == 0


class TestSecretDetector:
    """Tests for the SecretDetector engine."""

    def test_scan_aws_key(self):
        detector = SecretDetector(entropy_enabled=False)
        detector.add_rules(load_all_rules())

        content = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"'
        findings = detector.scan_content(content, "test.py")
        # Should detect the AWS key
        aws_findings = [f for f in findings if "aws" in f.rule_id]
        assert len(aws_findings) >= 1

    def test_scan_github_token(self):
        detector = SecretDetector(entropy_enabled=False)
        detector.add_rules(load_all_rules())

        # ghp_ + exactly 36 alphanumeric chars = valid GitHub PAT
        content = 'token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij end'
        findings = detector.scan_content(content, "test.py")
        github_findings = [f for f in findings if "github" in f.rule_id]
        assert len(github_findings) >= 1

    def test_scan_stripe_key(self):
        detector = SecretDetector(entropy_enabled=False)
        detector.add_rules(load_all_rules())

        content = 'STRIPE_KEY = "sk_live_abcdefghijklmnopqrst1234"'
        findings = detector.scan_content(content, "config.py")
        stripe_findings = [f for f in findings if "stripe" in f.rule_id]
        assert len(stripe_findings) >= 1

    def test_scan_ssh_private_key(self):
        detector = SecretDetector(entropy_enabled=False)
        detector.add_rules(load_all_rules())

        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        findings = detector.scan_content(content, "id_rsa")
        ssh_findings = [f for f in findings if "ssh" in f.rule_id]
        assert len(ssh_findings) >= 1

    def test_inline_ignore(self):
        detector = SecretDetector(entropy_enabled=False)
        detector.add_rules(load_all_rules())

        content = 'API_KEY = "AKIAIOSFODNN7EXAMPLE"  # gitsentinel:ignore'
        findings = detector.scan_content(content, "test.py")
        assert len(findings) == 0

    def test_allowlist(self):
        detector = SecretDetector(entropy_enabled=False)
        detector.add_rules(load_all_rules())
        detector.set_allowlist(["AKIAIOSFODNN7EXAMPLE"])

        content = 'KEY = "AKIAIOSFODNN7EXAMPLE"'
        findings = detector.scan_content(content, "test.py")
        aws_findings = [f for f in findings if f.rule_id == "aws-access-key-id"]
        assert len(aws_findings) == 0

    def test_empty_content(self):
        detector = SecretDetector(entropy_enabled=False)
        detector.add_rules(load_all_rules())

        findings = detector.scan_content("", "empty.py")
        assert len(findings) == 0

    def test_entropy_detection(self):
        detector = SecretDetector(
            entropy_enabled=True,
            entropy_threshold=3.5,
        )
        # Don't add regex rules, test entropy only
        content = 'secret = "k9X2mP7qL4wR8nT5vB3jH6dF1cY0aE9zU"'
        findings = detector.scan_content(content, "test.py")
        entropy_findings = [f for f in findings if f.detection_method == "entropy"]
        assert len(entropy_findings) >= 1

    def test_database_url_detection(self):
        detector = SecretDetector(entropy_enabled=False)
        detector.add_rules(load_all_rules())

        content = 'DATABASE_URL = "postgres://admin:supersecretpassword@localhost:5432/mydb"'
        findings = detector.scan_content(content, "config.py")
        db_findings = [f for f in findings if "database" in f.rule_id or "password" in f.rule_id]
        assert len(db_findings) >= 1


class TestFinding:
    """Tests for the Finding class."""

    def test_finding_creation(self):
        f = Finding(
            file_path="test.py",
            line_number=10,
            rule_id="test-rule",
            description="Test finding",
            severity="HIGH",
            matched_value="AKIA****",
            raw_value="AKIAIOSFODNN7EXAMPLE",
        )
        assert f.file_path == "test.py"
        assert f.line_number == 10
        assert f.severity == "HIGH"

    def test_finding_to_dict(self):
        f = Finding(
            file_path="test.py",
            line_number=10,
            rule_id="test-rule",
            description="Test finding",
            severity="HIGH",
            matched_value="AKIA****",
            raw_value="AKIAIOSFODNN7EXAMPLE",
        )
        d = f.to_dict()
        assert d["file"] == "test.py"
        assert d["line"] == 10
        assert d["severity"] == "HIGH"
        # raw_value should NOT be in the dict (security)
        assert "raw_value" not in d

    def test_finding_repr(self):
        f = Finding(
            file_path="test.py",
            line_number=10,
            rule_id="test-rule",
            description="Test",
            severity="HIGH",
            matched_value="****",
        )
        repr_str = repr(f)
        assert "test.py" in repr_str
        assert "test-rule" in repr_str


class TestAlertManager:
    """Tests for the AlertManager."""

    def _make_finding(self, severity="HIGH"):
        return Finding(
            file_path="test.py",
            line_number=1,
            rule_id="test",
            description="Test",
            severity=severity,
            matched_value="****",
        )

    def test_empty_manager(self):
        mgr = AlertManager()
        assert mgr.total_findings == 0
        assert mgr.should_block_commit is False
        assert mgr.max_severity is None

    def test_add_finding(self):
        mgr = AlertManager()
        mgr.add_finding(self._make_finding("HIGH"))
        assert mgr.total_findings == 1

    def test_should_block_high(self):
        mgr = AlertManager(block_severity="HIGH")
        mgr.add_finding(self._make_finding("HIGH"))
        assert mgr.should_block_commit is True

    def test_should_not_block_low(self):
        mgr = AlertManager(block_severity="HIGH")
        mgr.add_finding(self._make_finding("LOW"))
        assert mgr.should_block_commit is False

    def test_should_block_critical(self):
        mgr = AlertManager(block_severity="HIGH")
        mgr.add_finding(self._make_finding("CRITICAL"))
        assert mgr.should_block_commit is True

    def test_max_severity(self):
        mgr = AlertManager()
        mgr.add_finding(self._make_finding("LOW"))
        mgr.add_finding(self._make_finding("CRITICAL"))
        mgr.add_finding(self._make_finding("MEDIUM"))
        assert mgr.max_severity == "CRITICAL"

    def test_get_summary(self):
        mgr = AlertManager()
        mgr.add_finding(self._make_finding("HIGH"))
        mgr.add_finding(self._make_finding("LOW"))
        summary = mgr.get_summary()
        assert summary["total"] == 2
        assert summary["by_severity"]["HIGH"] == 1
        assert summary["by_severity"]["LOW"] == 1

    def test_generate_report(self):
        mgr = AlertManager()
        mgr.add_finding(self._make_finding("HIGH"))
        report = mgr.generate_report()
        assert report["tool"] == "GitSentinel"
        assert report["summary"]["total"] == 1
        assert len(report["findings"]) == 1

    def test_generate_report_to_file(self, tmp_path):
        mgr = AlertManager()
        mgr.add_finding(self._make_finding("MEDIUM"))
        output_path = str(tmp_path / "report.json")
        report = mgr.generate_report(output_path)
        assert os.path.isfile(output_path)

    def test_clear(self):
        mgr = AlertManager()
        mgr.add_finding(self._make_finding("HIGH"))
        mgr.clear()
        assert mgr.total_findings == 0

    def test_findings_by_severity(self):
        mgr = AlertManager()
        mgr.add_finding(self._make_finding("HIGH"))
        mgr.add_finding(self._make_finding("HIGH"))
        mgr.add_finding(self._make_finding("LOW"))
        high_findings = mgr.get_findings_by_severity("HIGH")
        assert len(high_findings) == 2

    def test_findings_by_file(self):
        mgr = AlertManager()
        f1 = Finding("a.py", 1, "r1", "d", "HIGH", "****")
        f2 = Finding("b.py", 1, "r1", "d", "HIGH", "****")
        mgr.add_findings([f1, f2])
        assert len(mgr.get_findings_by_file("a.py")) == 1


class TestSeverity:
    """Tests for severity parsing."""

    def test_parse_valid(self):
        assert parse_severity("HIGH") == Severity.HIGH
        assert parse_severity("low") == Severity.LOW
        assert parse_severity("CRITICAL") == Severity.CRITICAL

    def test_parse_invalid(self):
        with pytest.raises(ValueError):
            parse_severity("INVALID")

    def test_severity_ordering(self):
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH < Severity.CRITICAL


class TestBinaryFileDetection:
    """Tests for binary file detection."""

    def test_png_extension(self):
        assert is_binary_file("image.png") is True

    def test_exe_extension(self):
        assert is_binary_file("program.exe") is True

    def test_py_extension(self, tmp_path):
        # Create a real .py file
        py_file = tmp_path / "test.py"
        py_file.write_text("print('hello')")
        assert is_binary_file(str(py_file)) is False

    def test_file_with_null_bytes(self, tmp_path):
        bin_file = tmp_path / "test.dat"
        bin_file.write_bytes(b"hello\x00world")
        assert is_binary_file(str(bin_file)) is True

    def test_png_magic_number(self, tmp_path):
        png_file = tmp_path / "test.data"
        png_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        assert is_binary_file(str(png_file)) is True


class TestReadFileContent:
    """Tests for file reading."""

    def test_read_normal_file(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        content = read_file_content(str(f))
        assert content == "hello world"

    def test_read_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        content = read_file_content(str(f))
        assert content == ""

    def test_read_nonexistent(self):
        content = read_file_content("/nonexistent/path/file.txt")
        assert content is None

    def test_read_large_file_skipped(self, tmp_path):
        f = tmp_path / "large.txt"
        f.write_text("x" * 100)
        content = read_file_content(str(f), max_size=50)
        assert content is None


class TestIgnorePatterns:
    """Tests for file ignore patterns."""

    def test_exact_match(self):
        assert _should_ignore_file("secret.key", ["secret.key"]) is True

    def test_glob_match(self):
        assert _should_ignore_file("test.log", ["*.log"]) is True

    def test_no_match(self):
        assert _should_ignore_file("important.py", ["*.log"]) is False

    def test_directory_prefix(self):
        assert _should_ignore_file("vendor/lib.py", ["vendor/"]) is True

    def test_empty_patterns(self):
        assert _should_ignore_file("test.py", []) is False


class TestFileHashCache:
    """Tests for the file hash cache."""

    def test_cache_creation(self, tmp_path):
        cache_path = str(tmp_path / "test_cache.db")
        cache = FileHashCache(cache_path)
        assert os.path.isfile(cache_path)

    def test_cache_miss(self, tmp_path):
        cache_path = str(tmp_path / "test_cache.db")
        cache = FileHashCache(cache_path)
        assert cache.get_cached_hash("nonexistent.py") is None

    def test_cache_update_and_retrieve(self, tmp_path):
        cache_path = str(tmp_path / "test_cache.db")
        cache = FileHashCache(cache_path)

        test_file = str(tmp_path / "test.py")
        with open(test_file, "w") as f:
            f.write("content")

        file_hash = compute_file_hash(test_file)
        cache.update_cache(test_file, file_hash, 0)

        cached = cache.get_cached_hash(test_file)
        assert cached == file_hash

    def test_has_changed_new_file(self, tmp_path):
        cache_path = str(tmp_path / "test_cache.db")
        cache = FileHashCache(cache_path)

        test_file = str(tmp_path / "test.py")
        with open(test_file, "w") as f:
            f.write("content")

        assert cache.has_changed(test_file) is True

    def test_has_changed_cached_file(self, tmp_path):
        cache_path = str(tmp_path / "test_cache.db")
        cache = FileHashCache(cache_path)

        test_file = str(tmp_path / "test.py")
        with open(test_file, "w") as f:
            f.write("content")

        file_hash = compute_file_hash(test_file)
        cache.update_cache(test_file, file_hash)

        assert cache.has_changed(test_file) is False

    def test_has_changed_modified_file(self, tmp_path):
        cache_path = str(tmp_path / "test_cache.db")
        cache = FileHashCache(cache_path)

        test_file = str(tmp_path / "test.py")
        with open(test_file, "w") as f:
            f.write("content")

        file_hash = compute_file_hash(test_file)
        cache.update_cache(test_file, file_hash)

        # Modify the file
        with open(test_file, "w") as f:
            f.write("modified content")

        assert cache.has_changed(test_file) is True

    def test_cache_clear(self, tmp_path):
        cache_path = str(tmp_path / "test_cache.db")
        cache = FileHashCache(cache_path)
        cache.update_cache("test.py", "abc123")
        cache.clear()
        assert cache.get_cached_hash("test.py") is None

    def test_cache_stats(self, tmp_path):
        cache_path = str(tmp_path / "test_cache.db")
        cache = FileHashCache(cache_path)
        cache.update_cache("a.py", "hash1", findings_count=3)
        cache.update_cache("b.py", "hash2", findings_count=1)
        stats = cache.get_stats()
        assert stats["cached_files"] == 2
        assert stats["total_findings"] == 4

    def test_compute_file_hash(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        h1 = compute_file_hash(str(f))
        assert len(h1) == 64  # SHA-256 hex digest

        # Same content -> same hash
        h2 = compute_file_hash(str(f))
        assert h1 == h2

        # Different content -> different hash
        f.write_text("world")
        h3 = compute_file_hash(str(f))
        assert h1 != h3


class TestMaskValue:
    """Tests for the mask_value utility in detector."""

    def test_mask_normal(self):
        result = _mask_value("AKIAIOSFODNN7EXAMPLE")
        assert result.startswith("AKIA")
        assert "****" in result

    def test_mask_short(self):
        result = _mask_value("ab")
        assert result == "**"


class TestLoadAllRules:
    """Tests for loading all rules."""

    def test_load_all_rules(self):
        rules = load_all_rules()
        assert len(rules) > 10  # Should have many rules

    def test_all_rules_have_ids(self):
        rules = load_all_rules()
        for rule in rules:
            assert rule.rule_id
            assert rule.description
            assert rule.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            assert rule.pattern is not None
