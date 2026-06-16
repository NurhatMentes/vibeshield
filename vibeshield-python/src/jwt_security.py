"""
VibeShield JWT Security Middleware (Python)

Intercepts JWT secret usage and enforces validation before any token
operation can proceed. In production, blocks insecure secrets entirely.
In development, logs detailed warnings with tracking IDs.

Zero external dependencies.
"""

import os
import random
import string
import logging

from .jwt_validator import validate_jwt_secret

logger = logging.getLogger("VibeShield")


def _generate_jwt_tracking_id() -> str:
    """Generates a tracking ID of format VS-JWT-XXXX."""
    chars = string.ascii_uppercase + string.digits
    return "VS-JWT-" + "".join(random.choices(chars, k=4))


def _is_production() -> bool:
    """Environment detection: true when ENV/FLASK_ENV/PYTHON_ENV is 'production'."""
    for key in ("PYTHON_ENV", "FLASK_ENV", "ENV"):
        if os.environ.get(key, "").lower() == "production":
            return True
    return False


def enforce_jwt_security(secret: str | None) -> dict:
    """
    Validates a JWT secret and enforces security policy.

    Development mode: Logs detailed warnings to the console but allows
    the operation to proceed if there are only warnings (no errors).

    Production mode: Blocks operations with insecure secrets and logs
    a generic message with a tracking ID. The secret value is NEVER logged.

    Args:
        secret: The JWT secret to validate.

    Returns:
        dict with keys: "allowed" (bool), "tracking_id" (str), "validation" (dict)
    """
    tracking_id = _generate_jwt_tracking_id()
    validation = validate_jwt_secret(secret)
    prod = _is_production()

    if not validation["valid"]:
        if prod:
            # Production: generic message, NEVER log the secret value
            logger.error(
                f"[{tracking_id}] JWT security check FAILED. "
                f"{len(validation['errors'])} error(s) detected. "
                f"Application should not start with an insecure JWT secret."
            )
        else:
            # Development: detailed output for developer feedback
            logger.error(f"\n⚠️  [VIBESHIELD JWT SECURITY CHECK FAILED] ⚠️")
            logger.error(f"Tracking ID: {tracking_id}")
            logger.error("Errors:")
            for err in validation["errors"]:
                logger.error(f"  ❌ {err}")
            if validation["warnings"]:
                logger.error("Warnings:")
                for warn in validation["warnings"]:
                    logger.error(f"  ⚠️  {warn}")
            logger.error(
                "\n💡 Fix: Set a strong secret via environment variable, e.g.:\n"
                "   export JWT_SECRET=$(openssl rand -base64 48)\n"
            )

        return {"allowed": False, "tracking_id": tracking_id, "validation": validation}

    # Valid but may have warnings
    if validation["warnings"] and not prod:
        logger.warning(f"\n⚠️  [VIBESHIELD JWT SECURITY WARNINGS] ⚠️")
        logger.warning(f"Tracking ID: {tracking_id}")
        for warn in validation["warnings"]:
            logger.warning(f"  ⚠️  {warn}")

    return {"allowed": True, "tracking_id": tracking_id, "validation": validation}
