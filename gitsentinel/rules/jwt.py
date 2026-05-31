"""
JWT Token Detection Rules
Detects JSON Web Tokens in common formats.
All patterns compiled at module load time.
"""

import re
from typing import List

from gitsentinel.core.detector import SecretRule

# JWT Token: three base64url-encoded segments separated by dots
# Header.Payload.Signature format
# Safe regex: bounded character classes, no nested quantifiers
_JWT_TOKEN_PATTERN = re.compile(
    r"""(?:^|[^A-Za-z0-9._-])"""
    r"""(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"""
    r"""(?:$|[^A-Za-z0-9._-])"""
)

# Bearer token in authorization headers
_BEARER_TOKEN_PATTERN = re.compile(
    r"""[Bb]earer\s+([A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"""
)

# JWT assigned to variable or config
_JWT_ASSIGNMENT_PATTERN = re.compile(
    r"""(?:jwt|token|auth_token|access_token|id_token|refresh_token)"""
    r"""[\s]*[=:]\s*["']?"""
    r"""(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"""
    r"""["']?""",
    re.IGNORECASE,
)


def get_jwt_rules() -> List[SecretRule]:
    """
    Return all JWT-related detection rules.

    Returns:
        List of SecretRule objects for JWT detection.
    """
    return [
        SecretRule(
            rule_id="jwt-token",
            description="JWT Token detected",
            pattern=_JWT_TOKEN_PATTERN,
            severity="HIGH",
            keywords=["eyj"],
        ),
        SecretRule(
            rule_id="jwt-bearer-token",
            description="JWT Bearer Token detected in authorization header",
            pattern=_BEARER_TOKEN_PATTERN,
            severity="HIGH",
            keywords=["bearer"],
        ),
        SecretRule(
            rule_id="jwt-assignment",
            description="JWT Token assigned to variable",
            pattern=_JWT_ASSIGNMENT_PATTERN,
            severity="HIGH",
            keywords=["jwt", "token", "auth_token", "access_token", "id_token"],
        ),
    ]
