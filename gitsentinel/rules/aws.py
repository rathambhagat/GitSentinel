"""
AWS Secret Detection Rules
Detects AWS Access Key IDs, Secret Access Keys, and Session Tokens.
All patterns compiled at module load time.
"""

import re
from typing import List

from gitsentinel.core.detector import SecretRule

# AWS Access Key ID: starts with AKIA, ABIA, ACCA, ASIA followed by 16 alphanumeric chars
_AWS_ACCESS_KEY_PATTERN = re.compile(
    r"""(?:^|[^A-Za-z0-9])"""
    r"""((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})"""
    r"""(?:$|[^A-Za-z0-9])"""
)

# AWS Secret Access Key: 40-char base64 string typically after a known key name
_AWS_SECRET_KEY_PATTERN = re.compile(
    r"""(?:aws_secret_access_key|aws_secret_key|secret_key|secret_access_key)"""
    r"""[\s]*[=:]\s*["']?"""
    r"""([A-Za-z0-9/+=]{40})"""
    r"""["']?""",
    re.IGNORECASE,
)

# AWS Account ID (12 digits, typically in ARNs or config)
_AWS_ACCOUNT_ID_PATTERN = re.compile(
    r"""(?:arn:aws:[a-z0-9-]+:[a-z0-9-]*:)(\d{12})(?::|$)"""
)

# AWS MWS Auth Token
_AWS_MWS_PATTERN = re.compile(
    r"""amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"""
)

# AWS Session Token (variable length, starts with FwoG or IQoJ)
_AWS_SESSION_TOKEN_PATTERN = re.compile(
    r"""(?:aws_session_token|session_token)"""
    r"""[\s]*[=:]\s*["']?"""
    r"""([A-Za-z0-9/+=]{100,})"""
    r"""["']?""",
    re.IGNORECASE,
)


def get_aws_rules() -> List[SecretRule]:
    """
    Return all AWS-related detection rules.

    Returns:
        List of SecretRule objects for AWS credential detection.
    """
    return [
        SecretRule(
            rule_id="aws-access-key-id",
            description="AWS Access Key ID detected",
            pattern=_AWS_ACCESS_KEY_PATTERN,
            severity="CRITICAL",
            keywords=["akia", "abia", "acca", "asia"],
        ),
        SecretRule(
            rule_id="aws-secret-access-key",
            description="AWS Secret Access Key detected",
            pattern=_AWS_SECRET_KEY_PATTERN,
            severity="CRITICAL",
            keywords=["aws_secret", "secret_key", "secret_access"],
        ),
        SecretRule(
            rule_id="aws-mws-token",
            description="AWS MWS Auth Token detected",
            pattern=_AWS_MWS_PATTERN,
            severity="HIGH",
            keywords=["amzn.mws"],
        ),
        SecretRule(
            rule_id="aws-session-token",
            description="AWS Session Token detected",
            pattern=_AWS_SESSION_TOKEN_PATTERN,
            severity="HIGH",
            keywords=["session_token", "aws_session"],
        ),
    ]
