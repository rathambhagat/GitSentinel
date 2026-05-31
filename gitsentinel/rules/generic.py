"""
Generic Secret Detection Rules
Detects database credentials, .env secrets, private keys, Slack tokens,
Stripe keys, SendGrid keys, Twilio keys, and other common secret patterns.
All patterns compiled at module load time.
"""

import re
from typing import List

from gitsentinel.core.detector import SecretRule

# ─── Database Connection Strings ────────────────────────────────────────────

# Generic database URL with credentials
_DB_URL_PATTERN = re.compile(
    r"""(?:mysql|postgres|postgresql|mongodb|redis|amqp|mssql)"""
    r"""://[^:\s]+:([^@\s]{8,})@""",
    re.IGNORECASE,
)

# Database password in config files
_DB_PASSWORD_PATTERN = re.compile(
    r"""(?:db_password|database_password|db_pass|mysql_password|pg_password|postgres_password|mongo_password)"""
    r"""[\s]*[=:]\s*["']?"""
    r"""([^\s"']{8,})"""
    r"""["']?""",
    re.IGNORECASE,
)

# ─── SSH and RSA Private Keys ───────────────────────────────────────────────

_SSH_PRIVATE_KEY_PATTERN = re.compile(
    r"""-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----"""
)

# ─── .env Secrets ───────────────────────────────────────────────────────────

# Generic secrets in .env-style files: KEY=value patterns
_ENV_SECRET_PATTERN = re.compile(
    r"""(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|AUTH)"""
    r"""[\s]*[=:]\s*["']?"""
    r"""([^\s"'#]{8,})"""
    r"""["']?""",
    re.IGNORECASE,
)

# ─── Slack Tokens ───────────────────────────────────────────────────────────

_SLACK_TOKEN_PATTERN = re.compile(
    r"""(xox[bpors]-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{10,})"""
)

_SLACK_WEBHOOK_PATTERN = re.compile(
    r"""(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,})"""
)

# ─── Stripe Keys ────────────────────────────────────────────────────────────

_STRIPE_SECRET_KEY_PATTERN = re.compile(
    r"""(?:^|[^A-Za-z0-9_])"""
    r"""(sk_(?:live|test)_[A-Za-z0-9]{20,})"""
    r"""(?:$|[^A-Za-z0-9_])"""
)

_STRIPE_PUBLISHABLE_KEY_PATTERN = re.compile(
    r"""(?:^|[^A-Za-z0-9_])"""
    r"""(pk_(?:live|test)_[A-Za-z0-9]{20,})"""
    r"""(?:$|[^A-Za-z0-9_])"""
)

# ─── SendGrid API Key ──────────────────────────────────────────────────────

_SENDGRID_API_KEY_PATTERN = re.compile(
    r"""(?:^|[^A-Za-z0-9._])"""
    r"""(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})"""
    r"""(?:$|[^A-Za-z0-9._])"""
)

# ─── Twilio ─────────────────────────────────────────────────────────────────

_TWILIO_API_KEY_PATTERN = re.compile(
    r"""(?:^|[^A-Za-z0-9])"""
    r"""(SK[0-9a-fA-F]{32})"""
    r"""(?:$|[^A-Za-z0-9])"""
)

# ─── Google API Key ─────────────────────────────────────────────────────────

_GOOGLE_API_KEY_PATTERN = re.compile(
    r"""(?:^|[^A-Za-z0-9_])"""
    r"""(AIza[0-9A-Za-z_-]{35})"""
    r"""(?:$|[^A-Za-z0-9_])"""
)

# ─── Heroku API Key ─────────────────────────────────────────────────────────

_HEROKU_API_KEY_PATTERN = re.compile(
    r"""(?:heroku_api_key|heroku_key|heroku_token)"""
    r"""[\s]*[=:]\s*["']?"""
    r"""([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"""
    r"""["']?""",
    re.IGNORECASE,
)

# ─── Generic API Key Pattern ────────────────────────────────────────────────

_GENERIC_API_KEY_PATTERN = re.compile(
    r"""(?:api_key|apikey|api-key|x-api-key)"""
    r"""[\s]*[=:]\s*["']?"""
    r"""([A-Za-z0-9_\-]{20,})"""
    r"""["']?""",
    re.IGNORECASE,
)

# ─── Password in URL ────────────────────────────────────────────────────────

_PASSWORD_IN_URL_PATTERN = re.compile(
    r"""://[^:\s]+:([^@\s]{8,})@[^\s]+"""
)


def get_generic_rules() -> List[SecretRule]:
    """
    Return all generic/common secret detection rules.

    Returns:
        List of SecretRule objects for various common secrets.
    """
    return [
        # Database
        SecretRule(
            rule_id="database-url-credentials",
            description="Database connection string with embedded credentials",
            pattern=_DB_URL_PATTERN,
            severity="CRITICAL",
            keywords=["mysql://", "postgres://", "postgresql://", "mongodb://", "redis://", "amqp://", "mssql://"],
        ),
        SecretRule(
            rule_id="database-password",
            description="Database password in configuration",
            pattern=_DB_PASSWORD_PATTERN,
            severity="HIGH",
            keywords=["db_password", "database_password", "db_pass", "mysql_password", "pg_password"],
        ),
        # SSH/RSA
        SecretRule(
            rule_id="ssh-private-key",
            description="SSH/RSA Private Key detected",
            pattern=_SSH_PRIVATE_KEY_PATTERN,
            severity="CRITICAL",
            keywords=["-----begin", "private key"],
        ),
        # .env secrets
        SecretRule(
            rule_id="env-secret",
            description="Secret value in environment variable / config",
            pattern=_ENV_SECRET_PATTERN,
            severity="HIGH",
            keywords=["secret", "password", "passwd", "token", "api_key", "apikey", "access_key", "private_key", "auth"],
        ),
        # Slack
        SecretRule(
            rule_id="slack-token",
            description="Slack Token detected",
            pattern=_SLACK_TOKEN_PATTERN,
            severity="HIGH",
            keywords=["xox"],
        ),
        SecretRule(
            rule_id="slack-webhook",
            description="Slack Webhook URL detected",
            pattern=_SLACK_WEBHOOK_PATTERN,
            severity="MEDIUM",
            keywords=["hooks.slack.com"],
        ),
        # Stripe
        SecretRule(
            rule_id="stripe-secret-key",
            description="Stripe Secret Key detected",
            pattern=_STRIPE_SECRET_KEY_PATTERN,
            severity="CRITICAL",
            keywords=["sk_live", "sk_test"],
        ),
        SecretRule(
            rule_id="stripe-publishable-key",
            description="Stripe Publishable Key detected",
            pattern=_STRIPE_PUBLISHABLE_KEY_PATTERN,
            severity="LOW",
            keywords=["pk_live", "pk_test"],
        ),
        # SendGrid
        SecretRule(
            rule_id="sendgrid-api-key",
            description="SendGrid API Key detected",
            pattern=_SENDGRID_API_KEY_PATTERN,
            severity="HIGH",
            keywords=["sg."],
        ),
        # Twilio
        SecretRule(
            rule_id="twilio-api-key",
            description="Twilio API Key detected",
            pattern=_TWILIO_API_KEY_PATTERN,
            severity="HIGH",
            keywords=["sk"],
        ),
        # Google
        SecretRule(
            rule_id="google-api-key",
            description="Google API Key detected",
            pattern=_GOOGLE_API_KEY_PATTERN,
            severity="HIGH",
            keywords=["aiza"],
        ),
        # Heroku
        SecretRule(
            rule_id="heroku-api-key",
            description="Heroku API Key detected",
            pattern=_HEROKU_API_KEY_PATTERN,
            severity="HIGH",
            keywords=["heroku_api_key", "heroku_key", "heroku_token"],
        ),
        # Generic
        SecretRule(
            rule_id="generic-api-key",
            description="Generic API Key detected",
            pattern=_GENERIC_API_KEY_PATTERN,
            severity="MEDIUM",
            keywords=["api_key", "apikey", "api-key", "x-api-key"],
        ),
        SecretRule(
            rule_id="password-in-url",
            description="Password embedded in URL",
            pattern=_PASSWORD_IN_URL_PATTERN,
            severity="HIGH",
            keywords=["://"],
        ),
    ]
