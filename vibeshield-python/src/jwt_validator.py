"""
VibeShield JWT Secret Key Validator (Python)

Detects weak, hardcoded, or insecure JWT secret keys that AI code generators
commonly produce. This module performs validation only — it does NOT encode
or decode JWT tokens.

Zero external dependencies.
"""

import math
import re
from typing import Optional

# Well-known weak secrets that AI models frequently hardcode.
# All comparisons are case-insensitive.
HARDCODED_PATTERNS: list[str] = [
    "secret",
    "password",
    "123456",
    "1234567890",
    "qwerty",
    "admin",
    "root",
    "jwt_secret",
    "jwt_key",
    "token_secret",
    "auth_secret",
    "mysecret",
    "my_secret",
    "my-secret",
    "supersecret",
    "super_secret",
    "changeme",
    "change_me",
    "test",
    "testing",
    "default",
    "example",
    "placeholder",
    "your_secret_here",
    "your-secret-here",
    "replace_me",
    "todo",
    "fixme",
    "key",
    "apikey",
    "api_key",
]

# Minimum acceptable secret length.
MIN_SECRET_LENGTH = 10

# Minimum recommended secret length for strong security.
RECOMMENDED_SECRET_LENGTH = 32


def calculate_shannon_entropy(secret: str) -> float:
    """Calculates Shannon entropy (bits per character) for a given string."""
    if not secret:
        return 0.0
    
    frequency: dict[str, int] = {}
    for char in secret:
        frequency[char] = frequency.get(char, 0) + 1
    
    entropy = 0.0
    length = len(secret)
    
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy



def validate_jwt_secret(secret: Optional[str]) -> dict:
    """
    Validates a JWT secret key for common security vulnerabilities.

    Checks for:
    - Missing or empty secrets
    - Known hardcoded/placeholder values
    - Insufficient length
    - Low character diversity (repeating chars, all-numeric, all-lowercase)
    - Low Shannon entropy

    Args:
        secret: The JWT secret string to validate (may be None).

    Returns:
        dict with keys: "valid" (bool), "errors" (list[str]), "warnings" (list[str])
    """
    errors: list[str] = []
    warnings: list[str] = []

    # ── 1. None / Empty Check ──────────────────────────────────────────
    if secret is None:
        errors.append("JWT secret is undefined. Provide a secret via environment variable.")
        return {"valid": False, "errors": errors, "warnings": warnings}

    trimmed = secret.strip()
    if len(trimmed) == 0:
        errors.append("JWT secret is empty or contains only whitespace.")
        return {"valid": False, "errors": errors, "warnings": warnings}

    without_padding = trimmed.rstrip('=')

    # ── 2. Hardcoded Pattern Detection ─────────────────────────────────
    lower = trimmed.lower()
    for pattern in HARDCODED_PATTERNS:
        if lower == pattern:
            errors.append(
                f'JWT secret matches a well-known weak value: "{pattern}". '
                f"Use a cryptographically random secret."
            )
            break

    # ── 3. Length Check ────────────────────────────────────────────────
    if len(trimmed) < MIN_SECRET_LENGTH:
        errors.append(
            f"JWT secret is too short ({len(trimmed)} chars). "
            f"Minimum required: {MIN_SECRET_LENGTH} characters."
        )
    elif len(trimmed) < RECOMMENDED_SECRET_LENGTH:
        warnings.append(
            f"JWT secret is {len(trimmed)} chars. "
            f"Recommended: {RECOMMENDED_SECRET_LENGTH}+ characters for production use."
        )

    # ── 4. Repeating Character / Pattern Check & Sequential Patterns ───
    # Repetitive characters (aaa, 111)
    if re.search(r'(.)\1{2,}', without_padding):
        errors.append('Contains repetitive characters')

    # Repeated patterns (abcabc, 123123)
    if re.search(r'(.+)\1+', without_padding):
        errors.append('Contains repeated patterns')

    # Sequential patterns (abc, 123, qwerty)
    sequential_patterns = [
        r'abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz',
        r'012|123|234|345|456|567|678|789|890',
        r'qwerty|asdfgh|zxcvbn|qazwsx',
    ]

    for pattern in sequential_patterns:
        if re.search(pattern, without_padding, re.IGNORECASE):
            errors.append('Contains sequential patterns')
            break

    # ── 5. Character Class Diversity ───────────────────────────────────
    has_upper = bool(re.search(r"[A-Z]", trimmed))
    has_lower = bool(re.search(r"[a-z]", trimmed))
    has_digit = bool(re.search(r"\d", trimmed))
    has_special = bool(re.search(r"[^A-Za-z0-9]", trimmed))

    # All-numeric
    if re.fullmatch(r"\d+", trimmed):
        errors.append("JWT secret contains only digits. Use a mix of letters, numbers, and symbols.")

    # All same-case letters
    if re.fullmatch(r"[a-z]+", trimmed) and len(trimmed) >= MIN_SECRET_LENGTH:
        warnings.append(
            "JWT secret contains only lowercase letters. "
            "Consider adding uppercase, digits, and symbols."
        )
    if re.fullmatch(r"[A-Z]+", trimmed) and len(trimmed) >= MIN_SECRET_LENGTH:
        warnings.append(
            "JWT secret contains only uppercase letters. "
            "Consider adding lowercase, digits, and symbols."
        )

    # ── 6. Shannon Entropy Check ───────────────────────────────────────
    entropy = calculate_shannon_entropy(without_padding)
    if entropy < 3.5:
        errors.append("Low entropy detected")
        warnings.append(f"Low entropy detected (Shannon entropy: {entropy:.2f})")

    # ── 7. Complexity recommendation ───────────────────────────────────
    class_count = sum([has_upper, has_lower, has_digit, has_special])
    if class_count < 3 and len(trimmed) >= MIN_SECRET_LENGTH and len(errors) == 0:
        warnings.append(
            "JWT secret uses fewer than 3 character classes. "
            "Mix uppercase, lowercase, digits, and symbols."
        )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
    }
