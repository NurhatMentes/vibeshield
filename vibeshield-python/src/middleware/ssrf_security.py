"""
VibeShield SSRF Security Middleware

Enforces SSRF URL validation safety checks and raises custom exceptions.
"""

import logging
from ..ssrf_protector import validate_url

logger = logging.getLogger("VibeShield")


class VibeShieldSSRFError(ValueError):
    """
    Custom exception raised when a URL is blocked by VibeShield's SSRF policy.
    """
    def __init__(self, url: str, reason: str):
        super().__init__(f"[VibeShield] SSRF Protection: Blocked URL \"{url}\". Reason: {reason}")
        self.url = url
        self.reason = reason


def enforce_safe_url(target_url: str) -> None:
    """
    Validates a URL and raises an exception if it is not safe.

    Args:
        target_url: The URL string to validate.

    Raises:
        VibeShieldSSRFError: If the URL fails SSRF safety validation.
    """
    result = validate_url(target_url)
    if not result['safe']:
        reason = result.get('reason', 'Blocked by SSRF policy')
        logger.warning("[VibeShield] SSRF safety violation: Blocked URL \"%s\". Reason: %s", target_url, reason)
        raise VibeShieldSSRFError(target_url, reason)
