"""
VibeShield CORS Security Enforcement

Wraps the CORS validator with environment-aware logging and tracking.
"""

import logging
import os
import random
import string

from .cors_validator import validate_cors_config

logger = logging.getLogger("VibeShield")


def _generate_cors_tracking_id() -> str:
    """Generate a unique tracking ID for CORS validation events."""
    random_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"VS-CORS-{random_part}"


def _is_production() -> bool:
    """Check if the current environment is production."""
    for var in ('PYTHON_ENV', 'FLASK_ENV', 'ENV'):
        if os.environ.get(var, '').lower() == 'production':
            return True
    return False


def enforce_cors_policy(config: dict | None = None) -> dict:
    """
    Enforces CORS security policy with environment-aware logging.

    Args:
        config: Dictionary with CORS configuration options.

    Returns:
        Dictionary with keys:
            - allowed (bool): Whether the configuration passes security checks
            - tracking_id (str): Unique tracking ID for this validation event
            - validation (dict): Full validation results from validate_cors_config
    """
    tracking_id = _generate_cors_tracking_id()
    validation = validate_cors_config(config)
    prod = _is_production()

    if not validation['valid']:
        if prod:
            logger.error(
                "[VibeShield] [%s] CORS configuration blocked due to security policy violations.",
                tracking_id,
            )
        else:
            logger.error(
                "\n❌ [VibeShield] CORS Security Errors (%s):", tracking_id
            )
            for error in validation['errors']:
                logger.error("   • %s", error)

        return {
            'allowed': False,
            'tracking_id': tracking_id,
            'validation': validation,
        }

    if validation['warnings'] and not prod:
        logger.warning(
            "\n⚠️ [VibeShield] CORS Security Warnings (%s):", tracking_id
        )
        for warning in validation['warnings']:
            logger.warning("   • %s", warning)
        logger.warning(
            "💡 Tip: Review CORS configuration before deploying to production.\n"
        )

    return {
        'allowed': True,
        'tracking_id': tracking_id,
        'validation': validation,
    }
