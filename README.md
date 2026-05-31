# GitSentinel 
**Intelligent Git Secret Scanner** — Detect and prevent sensitive credentials, API keys, authentication tokens, and private secrets from being committed into repository history.

## Features

- **Git pre-commit hook integration** — Automatically scans staged files before each commit
- **Regex-based secret detection** — 25+ built-in rules for AWS, GitHub, Stripe, JWT, and more
- **Entropy-based analysis** — Detects high-entropy strings that may be secrets
- **Commit blocking** — Blocks commits containing high-severity secrets
- **High performance** — Parallel scanning, binary file skipping, hash-based caching
- **JSON reports** — Generate detailed scan reports
- **Configurable** — YAML-based configuration with ignore/allowlist support
- **Rich CLI** — Beautiful terminal output with severity-colored tables

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Install Pre-Commit Hook

```bash
python -m gitsentinel install
```

### Scan Repository

```bash
python -m gitsentinel scan
```

### Scan Staged Files Only

```bash
python -m gitsentinel scan --staged
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `gitsentinel install` | Install pre-commit hook |
| `gitsentinel scan` | Scan files for secrets |
| `gitsentinel scan --staged` | Scan only staged files |
| `gitsentinel report` | Generate JSON report |
| `gitsentinel config init` | Create default config file |
| `gitsentinel config show` | Display current configuration |
| `gitsentinel rules list` | List all detection rules |

## Supported Secret Types

| Type | Detection Method | Severity |
|------|-----------------|----------|
| AWS Access Keys | Regex | CRITICAL |
| AWS Secret Keys | Regex | CRITICAL |
| GitHub PATs | Regex | CRITICAL |
| JWT Tokens | Regex | HIGH |
| Stripe Keys | Regex | CRITICAL |
| SSH Private Keys | Signature | CRITICAL |
| Database URLs | Regex | CRITICAL |
| .env Secrets | Pattern | HIGH |
| Slack Tokens | Regex | HIGH |
| SendGrid Keys | Regex | HIGH |
| Google API Keys | Regex | HIGH |
| Generic API Keys | Regex + Entropy | MEDIUM |
| High Entropy Strings | Entropy | Variable |

## Configuration

Create a `.gitsentinel.yml` in your repository root:

```yaml
entropy:
  enabled: true
  threshold: 4.5

severity:
  block_level: HIGH

cache:
  enabled: true

rules:
  aws: true
  jwt: true
  github: true
  generic: true
```

## Ignore System

### File-level ignoring (`.gitsentinelignore`)

```
# Ignore test fixtures
tests/fixtures/*
*.test.key
vendor/
```

### Inline ignoring

```python
API_KEY = "fake_key_for_testing"  # gitsentinel:ignore
```

## Running Tests

```bash
pytest tests/ -v
```

## Architecture

```
gitsentinel/
├── core/
│   ├── scanner.py    # File scanning with parallel processing
│   ├── detector.py   # Regex + entropy detection engine
│   ├── entropy.py    # Shannon entropy analyzer
│   ├── alerts.py     # Severity system & report generation
│   └── cache.py      # SQLite hash cache for incremental scanning
├── hooks/
│   └── pre_commit.py # Git hook integration
├── rules/
│   ├── aws.py        # AWS credential rules
│   ├── jwt.py        # JWT token rules
│   ├── github.py     # GitHub token rules
│   └── generic.py    # Database, Slack, Stripe, etc.
├── config/
│   ├── manager.py    # YAML config loading & merging
│   └── default.yaml  # Default configuration
├── main.py           # CLI entry point
└── __main__.py       # Module execution support
```

## License

MIT
