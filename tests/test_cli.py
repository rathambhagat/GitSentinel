"""Tests for the GitSentinel CLI."""

import os
import sys
import pytest

from gitsentinel.main import build_parser, main, cmd_rules
from gitsentinel.config.manager import load_config, save_default_config, DEFAULT_CONFIG, _deep_merge


class TestCLIParser:
    """Tests for CLI argument parsing."""

    def test_parser_creation(self):
        parser = build_parser()
        assert parser is not None

    def test_scan_command(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--staged"])
        assert args.command == "scan"
        assert args.staged is True

    def test_scan_with_files(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "--files", "a.py", "b.py"])
        assert args.command == "scan"
        assert args.files == ["a.py", "b.py"]

    def test_scan_with_output(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "-o", "report.json"])
        assert args.command == "scan"
        assert args.output == "report.json"

    def test_install_command(self):
        parser = build_parser()
        args = parser.parse_args(["install"])
        assert args.command == "install"

    def test_install_with_path(self):
        parser = build_parser()
        args = parser.parse_args(["install", "--path", "/repo"])
        assert args.command == "install"
        assert args.path == "/repo"

    def test_report_command(self):
        parser = build_parser()
        args = parser.parse_args(["report"])
        assert args.command == "report"

    def test_config_init(self):
        parser = build_parser()
        args = parser.parse_args(["config", "init"])
        assert args.command == "config"
        assert args.action == "init"

    def test_config_show(self):
        parser = build_parser()
        args = parser.parse_args(["config", "show"])
        assert args.command == "config"
        assert args.action == "show"

    def test_rules_list(self):
        parser = build_parser()
        args = parser.parse_args(["rules", "list"])
        assert args.command == "rules"
        assert args.action == "list"

    def test_no_command(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.command is None


class TestMainFunction:
    """Tests for the main CLI entry point."""

    def test_no_args_returns_zero(self):
        result = main([])
        assert result == 0

    def test_rules_list(self):
        result = main(["rules", "list"])
        assert result == 0

    def test_config_show(self):
        result = main(["config", "show"])
        assert result == 0

    def test_install_no_git(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = main(["install", "--path", str(tmp_path)])
        assert result == 1  # No .git directory

    def test_scan_no_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = main(["scan", "--files", str(tmp_path / "nonexistent.py")])
        assert result == 0  # No files found is not an error


class TestConfigManager:
    """Tests for configuration management."""

    def test_default_config(self):
        config = DEFAULT_CONFIG
        assert config["gitsentinel"]["version"] == "1.0.0"
        assert config["entropy"]["enabled"] is True
        assert config["scanning"]["parallel"] is True

    def test_load_config_defaults(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config = load_config()
        assert config["gitsentinel"]["enabled"] is True

    def test_load_config_from_file(self, tmp_path):
        config_file = tmp_path / ".gitsentinel.yml"
        config_file.write_text(
            "entropy:\n  threshold: 5.0\n  enabled: false\n"
        )
        config = load_config(str(config_file))
        assert config["entropy"]["threshold"] == 5.0
        assert config["entropy"]["enabled"] is False
        # Other defaults should still be present
        assert config["scanning"]["parallel"] is True

    def test_save_default_config(self, tmp_path):
        output = str(tmp_path / "config.yml")
        path = save_default_config(output)
        assert os.path.isfile(path)

    def test_deep_merge(self):
        base = {"a": 1, "b": {"c": 2, "d": 3}}
        override = {"b": {"c": 99}, "e": 5}
        result = _deep_merge(base, override)
        assert result["a"] == 1
        assert result["b"]["c"] == 99
        assert result["b"]["d"] == 3
        assert result["e"] == 5

    def test_invalid_yaml_fallback(self, tmp_path):
        config_file = tmp_path / ".gitsentinel.yml"
        config_file.write_text(":::invalid yaml{{{")
        config = load_config(str(config_file))
        # Should fallback to defaults
        assert config["gitsentinel"]["enabled"] is True


class TestConfigInit:
    """Tests for config init command."""

    def test_config_init_creates_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        output = str(tmp_path / ".gitsentinel.yml")
        result = main(["config", "init", "-o", output])
        assert result == 0
        assert os.path.isfile(output)


class TestRulesCommand:
    """Tests for the rules command."""

    def test_rules_list_succeeds(self):
        result = main(["rules"])
        assert result == 0

    def test_rules_list_explicit(self):
        result = main(["rules", "list"])
        assert result == 0
