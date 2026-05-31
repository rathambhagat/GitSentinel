"""
GitHub Token Detection Rules
Detects GitHub Personal Access Tokens, OAuth tokens, and App tokens.
All patterns compiled at module load time.
"""

import re
from typing import List

from gitsentinel.core.detector import SecretRule

# GitHub Personal Access Token (classic): ghp_ prefix + 36 alphanumeric chars
_GITHUB_PAT_PATTERN = re.compile(
    r"""(?:^|[^A-Za-z0-9_])"""
    r"""(ghp_[A-Za-z0-9]{36})"""
    r"""(?:$|[^A-Za-z0-9_])"""
)

# GitHub OAuth Access Token: gho_ prefix
_GITHUB_OAUTH_PATTERN = re.compile(
    r"""(?:^|[^A-Za-z0-9_])"""
    r"""(gho_[A-Za-z0-9]{36})"""
    r"""(?:$|[^A-Za-z0-9_])"""
)

# GitHub User-to-Server Token: ghu_ prefix
_GITHUB_USER_TOKEN_PATTERN = re.compile(
    r"""(?:^|[^A-Za-z0-9_])"""
    r"""(ghu_[A-Za-z0-9]{36})"""
    r"""(?:$|[^A-Za-z0-9_])"""
)

# GitHub Server-to-Server Token: ghs_ prefix
_GITHUB_SERVER_TOKEN_PATTERN = re.compile(
    r"""(?:^|[^A-Za-z0-9_])"""
    r"""(ghs_[A-Za-z0-9]{36})"""
    r"""(?:$|[^A-Za-z0-9_])"""
)

# GitHub Refresh Token: ghr_ prefix
_GITHUB_REFRESH_TOKEN_PATTERN = re.compile(
    r"""(?:^|[^A-Za-z0-9_])"""
    r"""(ghr_[A-Za-z0-9]{36})"""
    r"""(?:$|[^A-Za-z0-9_])"""
)

# GitHub Fine-grained PAT: github_pat_ prefix
_GITHUB_FINE_GRAINED_PAT_PATTERN = re.compile(
    r"""(?:^|[^A-Za-z0-9_])"""
    r"""(github_pat_[A-Za-z0-9_]{22,82})"""
    r"""(?:$|[^A-Za-z0-9_])"""
)


def get_github_rules() -> List[SecretRule]:
    """
    Return all GitHub-related detection rules.

    Returns:
        List of SecretRule objects for GitHub token detection.
    """
    return [
        SecretRule(
            rule_id="github-pat",
            description="GitHub Personal Access Token detected",
            pattern=_GITHUB_PAT_PATTERN,
            severity="CRITICAL",
            keywords=["ghp_"],
        ),
        SecretRule(
            rule_id="github-oauth-token",
            description="GitHub OAuth Access Token detected",
            pattern=_GITHUB_OAUTH_PATTERN,
            severity="CRITICAL",
            keywords=["gho_"],
        ),
        SecretRule(
            rule_id="github-user-token",
            description="GitHub User-to-Server Token detected",
            pattern=_GITHUB_USER_TOKEN_PATTERN,
            severity="HIGH",
            keywords=["ghu_"],
        ),
        SecretRule(
            rule_id="github-server-token",
            description="GitHub Server-to-Server Token detected",
            pattern=_GITHUB_SERVER_TOKEN_PATTERN,
            severity="HIGH",
            keywords=["ghs_"],
        ),
        SecretRule(
            rule_id="github-refresh-token",
            description="GitHub Refresh Token detected",
            pattern=_GITHUB_REFRESH_TOKEN_PATTERN,
            severity="HIGH",
            keywords=["ghr_"],
        ),
        SecretRule(
            rule_id="github-fine-grained-pat",
            description="GitHub Fine-grained PAT detected",
            pattern=_GITHUB_FINE_GRAINED_PAT_PATTERN,
            severity="CRITICAL",
            keywords=["github_pat_"],
        ),
    ]
