"""
VibeShield CORS Security Validator

Detects insecure CORS configurations commonly produced by AI code generators.
Zero external dependencies — uses only built-in string methods and regex.
"""

import os
import re
from typing import Optional

SENSITIVE_EXPOSED_HEADERS = (
    'authorization',
    'x-api-key',
    'x-csrf-token',
    'set-cookie',
    'cookie',
    'x-forwarded-for',
    'x-real-ip',
    'proxy-authorization',
)

DANGEROUS_METHODS = ('TRACE', 'CONNECT')

DESTRUCTIVE_METHODS = ('DELETE', 'PATCH')

MAX_SAFE_MAX_AGE = 86400  # 24 hours


def _is_production() -> bool:
    """Check if the current environment is production."""
    for var in ('PYTHON_ENV', 'FLASK_ENV', 'ENV'):
        if os.environ.get(var, '').lower() == 'production':
            return True
    return False


def _is_wildcard(origin: str) -> bool:
    return origin.strip() == '*'


def _is_valid_origin_format(origin: str) -> bool:
    if origin == '*':
        return True
    pattern = r'^https?://[a-zA-Z0-9][a-zA-Z0-9\-.]*(:\d{1,5})?$'
    return bool(re.match(pattern, origin))


def _is_localhost_origin(origin: str) -> bool:
    lower = origin.lower()
    return 'localhost' in lower or '127.0.0.1' in lower or '0.0.0.0' in lower


def validate_cors_config(config: Optional[dict] = None) -> dict:
    """
    Validates a CORS configuration for security issues.

    Args:
        config: Dictionary with CORS configuration options:
            - allowed_origins: list of origin strings
            - allowed_methods: list of HTTP method strings
            - allowed_headers: list of header strings
            - exposed_headers: list of header strings
            - allow_credentials: boolean
            - max_age: integer (seconds)

    Returns:
        Dictionary with keys 'valid' (bool), 'errors' (list), 'warnings' (list)
    """
    errors: list[str] = []
    warnings: list[str] = []
    prod = _is_production()

    # 1. Undefined/Empty Config Check
    if config is None:
        errors.append('CORS configuration is missing or undefined.')
        return {'valid': False, 'errors': errors, 'warnings': warnings}

    # 2. Wildcard Origin Check
    origins = config.get('allowed_origins', [])
    has_wildcard = any(_is_wildcard(o) for o in origins)

    if has_wildcard:
        if prod:
            errors.append('Wildcard origin "*" is not allowed in production. Specify explicit allowed origins.')
        else:
            warnings.append('Wildcard origin "*" detected. This is acceptable in development but must be restricted in production.')

    # 3. Wildcard + Credentials (CRITICAL)
    if has_wildcard and config.get('allow_credentials', False):
        errors.append('CRITICAL: Wildcard origin "*" with credentials enabled is a security vulnerability. Browsers will reject this, but it indicates a misconfiguration.')

    # 4. Origin Format Validation
    for origin in origins:
        if not _is_wildcard(origin) and not _is_valid_origin_format(origin):
            errors.append(f'Invalid origin format: "{origin}". Origins must start with http:// or https://.')

    # 5. Localhost in Production
    if prod:
        localhost_origins = [o for o in origins if _is_localhost_origin(o)]
        if localhost_origins:
            errors.append(f'Localhost origins detected in production: {", ".join(localhost_origins)}. Remove development origins from production config.')

    # 6. No origins specified
    if len(origins) == 0:
        warnings.append('No allowed origins specified. All cross-origin requests will be blocked.')

    # 7. Sensitive Exposed Headers
    exposed = [h.lower() for h in config.get('exposed_headers', [])]
    sensitive_found = [h for h in SENSITIVE_EXPOSED_HEADERS if h in exposed]
    if sensitive_found:
        errors.append(f'Sensitive headers exposed to client: {", ".join(sensitive_found)}. Remove these from exposed_headers.')

    # 8. Dangerous HTTP Methods
    methods = [m.upper() for m in config.get('allowed_methods', [])]
    dangerous_found = [m for m in DANGEROUS_METHODS if m in methods]
    if dangerous_found:
        errors.append(f'Dangerous HTTP methods allowed: {", ".join(dangerous_found)}. TRACE and CONNECT should never be allowed in CORS.')

    # 9. Destructive Methods Warning
    destructive_found = [m for m in DESTRUCTIVE_METHODS if m in methods]
    if destructive_found and prod:
        warnings.append(f'Destructive methods ({", ".join(destructive_found)}) are allowed. Ensure these are intentional and properly authorized.')

    # 10. maxAge Check
    max_age = config.get('max_age')
    if max_age is not None:
        if max_age < 0:
            errors.append('maxAge cannot be negative.')
        elif max_age > MAX_SAFE_MAX_AGE:
            warnings.append(f'maxAge ({max_age}s) exceeds recommended maximum of {MAX_SAFE_MAX_AGE}s (24 hours). Long preflight cache may hide configuration changes.')

    # 11. Credentials without specific origins
    if config.get('allow_credentials', False) and len(origins) == 0:
        warnings.append('Credentials enabled but no origins specified. Credentials require explicit allowed origins.')

    # 12. Too many origins
    if len(origins) > 20:
        warnings.append(f'Large number of allowed origins ({len(origins)}). Consider using a pattern-based approach or environment-specific configs.')

    return {'valid': len(errors) == 0, 'errors': errors, 'warnings': warnings}
