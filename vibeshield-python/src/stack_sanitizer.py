"""
VibeShield Stack Trace Sanitizer (Python)

Prevents sensitive information from leaking through error tracebacks.
Redacts file paths, IP addresses, database connection strings, and
environment-specific paths using pure regex-based pattern matching.

Zero external dependencies.
"""

import re
import traceback
from typing import Union

# Redaction markers
MARKERS = {
    "PROJECT_ROOT": "[PROJECT_ROOT]/...",
    "PYTHON_ENV": "[PYTHON_ENV]/...",
    "REDACTED_IP": "[REDACTED_IP]",
    "REDACTED_DB": "[REDACTED_DB_INFO]",
}

# Compiled regex patterns for sensitive data detection.
# Order matters: more specific patterns first to avoid partial matches.
_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Database connection strings (must run before generic path redaction)
    (
        re.compile(
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|mariadb|sqlite)://[^\s'\",)}\]]+",
            re.IGNORECASE,
        ),
        MARKERS["REDACTED_DB"],
    ),

    # Python virtual environment paths
    (
        re.compile(r"(?:venv|\.venv|env|\.env)/[^\s'\",)}\]:]+"),
        MARKERS["PYTHON_ENV"],
    ),

    # site-packages paths
    (
        re.compile(r"site-packages/[^\s'\",)}\]:]+"),
        MARKERS["PYTHON_ENV"],
    ),

    # Absolute Unix/macOS file paths
    (
        re.compile(r"/(?:Users|home|var|tmp|opt|etc|root|app|srv|proc|run|usr/src|workspace|project)/[^\s'\",)}\]:]+"),
        MARKERS["PROJECT_ROOT"],
    ),

    # Windows absolute file paths
    (
        re.compile(r"[A-Z]:\\[^\s'\",)}\]:]+"),
        MARKERS["PROJECT_ROOT"],
    ),

    # IPv6 addresses (common formats including ::1)
    (
        re.compile(
            r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
            r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
            r"|::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"
            r"|::1|::"
        ),
        MARKERS["REDACTED_IP"],
    ),

    # IPv4 addresses
    (
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
        MARKERS["REDACTED_IP"],
    ),

    # SQL table/schema references in error messages
    (
        re.compile(
            r"(FROM|INTO|UPDATE|TABLE|JOIN|ALTER)\s+[`\"']?(?:\w+\.)?(?:\w+)[`\"']?",
            re.IGNORECASE,
        ),
        r"\1 " + MARKERS["REDACTED_DB"],
    ),
]


def sanitize_traceback(exc: Union[Exception, str]) -> str:
    """
    Sanitizes a traceback or error string by redacting sensitive information.

    Processes the input through multiple regex patterns to remove:
    - Absolute file paths (Unix, macOS, Windows)
    - Python virtual environment / site-packages paths
    - IPv4 and IPv6 addresses
    - Database connection URIs (postgres://, mongodb://, etc.)
    - SQL table/schema references

    Args:
        exc: An Exception object or raw string to sanitize.

    Returns:
        The sanitized string with all sensitive data replaced by safe markers.
    """
    if isinstance(exc, Exception):
        raw = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        if not raw.strip():
            raw = str(exc)
    else:
        raw = str(exc)

    sanitized = raw
    for pattern, replacement in _PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized
