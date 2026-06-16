"""
VibeShield JWT Secret Validator — Python Test Suite

Mirrors the TypeScript test suite for full parity.
"""

import re
import pytest
from src.jwt_validator import validate_jwt_secret
from src.jwt_security import enforce_jwt_security


# ==========================================
# 1. JWT VALIDATOR — CORE VALIDATION TESTS
# ==========================================
class TestJwtValidator:
    # ── None / Empty / Whitespace ──────────────────────────────────────
    def test_reject_none_secret(self):
        result = validate_jwt_secret(None)
        assert result["valid"] is False
        assert len(result["errors"]) > 0
        assert "undefined" in result["errors"][0]

    def test_reject_empty_string_secret(self):
        result = validate_jwt_secret("")
        assert result["valid"] is False
        assert "empty" in result["errors"][0]

    def test_reject_whitespace_only_secret(self):
        result = validate_jwt_secret("     ")
        assert result["valid"] is False
        assert "empty" in result["errors"][0]

    # ── Hardcoded Pattern Detection ────────────────────────────────────
    def test_reject_secret_hardcoded(self):
        result = validate_jwt_secret("secret")
        assert result["valid"] is False
        assert any("well-known weak value" in e for e in result["errors"])

    def test_reject_123456_hardcoded(self):
        result = validate_jwt_secret("123456")
        assert result["valid"] is False
        assert any("well-known weak value" in e for e in result["errors"])

    def test_reject_changeme_case_insensitive(self):
        result = validate_jwt_secret("CHANGEME")
        assert result["valid"] is False
        assert any("well-known weak value" in e for e in result["errors"])

    def test_reject_jwt_secret_hardcoded(self):
        result = validate_jwt_secret("jwt_secret")
        assert result["valid"] is False
        assert any("well-known weak value" in e for e in result["errors"])

    def test_reject_password_hardcoded(self):
        result = validate_jwt_secret("password")
        assert result["valid"] is False
        assert any("well-known weak value" in e for e in result["errors"])

    # ── Length Check ───────────────────────────────────────────────────
    def test_reject_short_secret(self):
        result = validate_jwt_secret("Ab3$xYz!q")  # 9 chars
        assert result["valid"] is False
        assert any("too short" in e for e in result["errors"])

    def test_warn_medium_length_secret(self):
        result = validate_jwt_secret("xK9#mL2$pQ7!nW4@")  # 16 chars, diverse
        assert result["valid"] is True
        assert any("Recommended" in w for w in result["warnings"])

    # ── Repeating Characters ───────────────────────────────────────────
    def test_reject_repeating_chars(self):
        result = validate_jwt_secret("aaaaaaaaaa")
        assert result["valid"] is False
        assert any("repeating character" in e for e in result["errors"])

    def test_reject_repeating_digits(self):
        result = validate_jwt_secret("1111111111")
        assert result["valid"] is False
        assert len(result["errors"]) > 0

    def test_reject_repeating_pattern(self):
        result = validate_jwt_secret("abcabcabcabc")
        assert result["valid"] is False
        assert any("repeating pattern" in e for e in result["errors"])

    # ── All-Digit Secret ───────────────────────────────────────────────
    def test_reject_all_digit_secret(self):
        result = validate_jwt_secret("98765432101234")
        assert result["valid"] is False
        assert any("only digits" in e for e in result["errors"])

    # ── Low Diversity ──────────────────────────────────────────────────
    def test_warn_all_lowercase(self):
        result = validate_jwt_secret("qwertyuiopas")
        assert result["valid"] is True
        assert any("lowercase" in w for w in result["warnings"])

    def test_warn_all_uppercase(self):
        result = validate_jwt_secret("QWERTYUIOPAS")
        assert result["valid"] is True
        assert any("uppercase" in w for w in result["warnings"])

    # ── Valid Strong Secrets ───────────────────────────────────────────
    def test_accept_strong_secret(self):
        strong = "aB3$xYz!qW8#mL2@pQ7&nK4*jR9^tF1%"
        result = validate_jwt_secret(strong)
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    def test_accept_base64_secret(self):
        base64_secret = "dGhpcyBpcyBhIHZlcnkgc3Ryb25nIGFuZCByYW5kb20gc2VjcmV0IGtleQ=="
        result = validate_jwt_secret(base64_secret)
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    # ── Unicode / Special Characters ───────────────────────────────────
    def test_accept_unicode_secret(self):
        unicode_secret = "Kö$$ñ!gstrÆße_T0ken#2024_Sëcürê"
        result = validate_jwt_secret(unicode_secret)
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    # ── Character Class Diversity Warning ──────────────────────────────
    def test_warn_fewer_than_3_classes(self):
        result = validate_jwt_secret("abcdefghij12")  # lower + digits = 2 classes
        assert result["valid"] is True
        assert any("character classes" in w for w in result["warnings"])


# ==========================================
# 2. JWT SECURITY MIDDLEWARE TESTS
# ==========================================
class TestJwtSecurityMiddleware:
    def test_block_insecure_secret(self):
        result = enforce_jwt_security("secret")
        assert result["allowed"] is False
        assert re.match(r"^VS-JWT-[A-Z0-9]{4}$", result["tracking_id"])
        assert result["validation"]["valid"] is False

    def test_allow_strong_secret(self):
        result = enforce_jwt_security("aB3$xYz!qW8#mL2@pQ7&nK4*jR9^tF1%")
        assert result["allowed"] is True
        assert re.match(r"^VS-JWT-[A-Z0-9]{4}$", result["tracking_id"])
        assert result["validation"]["valid"] is True

    def test_logs_sanitized_in_development(self, caplog):
        with caplog.at_level("ERROR", logger="VibeShield"):
            enforce_jwt_security("xQ3$z")
        log_output = caplog.text
        assert "JWT SECURITY CHECK FAILED" in log_output
        # Secret value must NOT appear in logs
        assert "xQ3$z" not in log_output

    def test_never_logs_actual_secret_value(self, caplog):
        dangerous_secret = "my-super-secret-api-key-12345"
        with caplog.at_level("WARNING", logger="VibeShield"):
            enforce_jwt_security(dangerous_secret)
        log_output = caplog.text
        assert dangerous_secret not in log_output
