"""
VibeShield CORS Security Validator — Python Test Suite

Comprehensive tests for CORS configuration validation and enforcement.
"""

import re
import pytest
from src.cors_validator import validate_cors_config
from src.cors_security import enforce_cors_policy


# ==========================================
# 1. CORS VALIDATOR — CORE VALIDATION TESTS
# ==========================================
class TestCorsValidator:
    # ── Missing / None Config ─────────────────────────────────────────
    def test_reject_none_config(self):
        result = validate_cors_config(None)
        assert result["valid"] is False
        assert len(result["errors"]) > 0
        assert "missing" in result["errors"][0]

    def test_reject_missing_config(self):
        result = validate_cors_config()
        assert result["valid"] is False
        assert any("missing" in e for e in result["errors"])

    # ── Valid Minimal Config ──────────────────────────────────────────
    def test_accept_minimal_valid_config(self):
        result = validate_cors_config({
            "allowed_origins": ["https://example.com"],
        })
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    # ── Wildcard Origin in Dev ────────────────────────────────────────
    def test_wildcard_origin_warning_in_dev(self, monkeypatch):
        monkeypatch.delenv("PYTHON_ENV", raising=False)
        monkeypatch.delenv("FLASK_ENV", raising=False)
        monkeypatch.delenv("ENV", raising=False)
        result = validate_cors_config({
            "allowed_origins": ["*"],
        })
        assert result["valid"] is True
        assert any("Wildcard" in w for w in result["warnings"])

    # ── Wildcard Origin in Prod ───────────────────────────────────────
    def test_wildcard_origin_error_in_prod(self, monkeypatch):
        monkeypatch.setenv("PYTHON_ENV", "production")
        result = validate_cors_config({
            "allowed_origins": ["*"],
        })
        assert result["valid"] is False
        assert any("Wildcard" in e and "not allowed" in e for e in result["errors"])

    # ── Wildcard + Credentials (always error) ─────────────────────────
    def test_wildcard_with_credentials_always_error(self, monkeypatch):
        monkeypatch.delenv("PYTHON_ENV", raising=False)
        monkeypatch.delenv("FLASK_ENV", raising=False)
        monkeypatch.delenv("ENV", raising=False)
        result = validate_cors_config({
            "allowed_origins": ["*"],
            "allow_credentials": True,
        })
        assert result["valid"] is False
        assert any("CRITICAL" in e for e in result["errors"])

    # ── Invalid Origin Format ─────────────────────────────────────────
    def test_reject_origin_without_protocol(self):
        result = validate_cors_config({
            "allowed_origins": ["example.com"],
        })
        assert result["valid"] is False
        assert any("Invalid origin format" in e for e in result["errors"])

    def test_reject_origin_with_trailing_slash(self):
        result = validate_cors_config({
            "allowed_origins": ["https://example.com/"],
        })
        assert result["valid"] is False
        assert any("Invalid origin format" in e for e in result["errors"])

    # ── Valid Origin Formats ──────────────────────────────────────────
    def test_accept_http_origin(self):
        result = validate_cors_config({
            "allowed_origins": ["http://example.com"],
        })
        assert result["valid"] is True

    def test_accept_https_origin(self):
        result = validate_cors_config({
            "allowed_origins": ["https://example.com"],
        })
        assert result["valid"] is True

    def test_accept_origin_with_port(self):
        result = validate_cors_config({
            "allowed_origins": ["https://example.com:8443"],
        })
        assert result["valid"] is True

    # ── Localhost in Production ────────────────────────────────────────
    def test_localhost_error_in_prod(self, monkeypatch):
        monkeypatch.setenv("PYTHON_ENV", "production")
        result = validate_cors_config({
            "allowed_origins": ["http://localhost:3000"],
        })
        assert result["valid"] is False
        assert any("Localhost" in e for e in result["errors"])

    def test_127_0_0_1_error_in_prod(self, monkeypatch):
        monkeypatch.setenv("PYTHON_ENV", "production")
        result = validate_cors_config({
            "allowed_origins": ["http://127.0.0.1:8080"],
        })
        assert result["valid"] is False
        assert any("Localhost" in e for e in result["errors"])

    # ── Empty Origins List ────────────────────────────────────────────
    def test_empty_origins_warning(self):
        result = validate_cors_config({
            "allowed_origins": [],
        })
        assert result["valid"] is True
        assert any("No allowed origins" in w for w in result["warnings"])

    # ── Sensitive Exposed Headers ─────────────────────────────────────
    def test_reject_authorization_exposed_header(self):
        result = validate_cors_config({
            "allowed_origins": ["https://example.com"],
            "exposed_headers": ["Authorization"],
        })
        assert result["valid"] is False
        assert any("Sensitive headers" in e for e in result["errors"])

    def test_reject_set_cookie_exposed_header(self):
        result = validate_cors_config({
            "allowed_origins": ["https://example.com"],
            "exposed_headers": ["Set-Cookie"],
        })
        assert result["valid"] is False
        assert any("Sensitive headers" in e for e in result["errors"])

    # ── Non-Sensitive Exposed Headers ─────────────────────────────────
    def test_accept_safe_exposed_headers(self):
        result = validate_cors_config({
            "allowed_origins": ["https://example.com"],
            "exposed_headers": ["Content-Type", "X-Request-Id"],
        })
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    # ── Dangerous Methods ─────────────────────────────────────────────
    def test_reject_trace_method(self):
        result = validate_cors_config({
            "allowed_origins": ["https://example.com"],
            "allowed_methods": ["GET", "TRACE"],
        })
        assert result["valid"] is False
        assert any("TRACE" in e for e in result["errors"])

    def test_reject_connect_method(self):
        result = validate_cors_config({
            "allowed_origins": ["https://example.com"],
            "allowed_methods": ["GET", "CONNECT"],
        })
        assert result["valid"] is False
        assert any("CONNECT" in e for e in result["errors"])

    # ── Destructive Methods in Production ─────────────────────────────
    def test_destructive_methods_warning_in_prod(self, monkeypatch):
        monkeypatch.setenv("PYTHON_ENV", "production")
        result = validate_cors_config({
            "allowed_origins": ["https://example.com"],
            "allowed_methods": ["GET", "DELETE", "PATCH"],
        })
        assert result["valid"] is True
        assert any("Destructive" in w for w in result["warnings"])

    def test_destructive_methods_no_warning_in_dev(self, monkeypatch):
        monkeypatch.delenv("PYTHON_ENV", raising=False)
        monkeypatch.delenv("FLASK_ENV", raising=False)
        monkeypatch.delenv("ENV", raising=False)
        result = validate_cors_config({
            "allowed_origins": ["https://example.com"],
            "allowed_methods": ["GET", "DELETE"],
        })
        assert not any("Destructive" in w for w in result["warnings"])

    # ── maxAge Checks ─────────────────────────────────────────────────
    def test_reject_negative_max_age(self):
        result = validate_cors_config({
            "allowed_origins": ["https://example.com"],
            "max_age": -1,
        })
        assert result["valid"] is False
        assert any("negative" in e for e in result["errors"])

    def test_warn_excessive_max_age(self):
        result = validate_cors_config({
            "allowed_origins": ["https://example.com"],
            "max_age": 100000,
        })
        assert result["valid"] is True
        assert any("exceeds" in w for w in result["warnings"])

    def test_accept_normal_max_age(self):
        result = validate_cors_config({
            "allowed_origins": ["https://example.com"],
            "max_age": 3600,
        })
        assert result["valid"] is True
        assert len(result["warnings"]) == 0

    # ── Credentials Without Origins ───────────────────────────────────
    def test_credentials_without_origins_warning(self):
        result = validate_cors_config({
            "allowed_origins": [],
            "allow_credentials": True,
        })
        assert result["valid"] is True
        assert any("Credentials enabled" in w for w in result["warnings"])

    # ── Too Many Origins ──────────────────────────────────────────────
    def test_too_many_origins_warning(self):
        origins = [f"https://site{i}.example.com" for i in range(25)]
        result = validate_cors_config({
            "allowed_origins": origins,
        })
        assert result["valid"] is True
        assert any("Large number" in w for w in result["warnings"])

    # ── Full Valid Production Config ──────────────────────────────────
    def test_full_valid_production_config(self, monkeypatch):
        monkeypatch.setenv("PYTHON_ENV", "production")
        result = validate_cors_config({
            "allowed_origins": ["https://myapp.com", "https://admin.myapp.com"],
            "allowed_methods": ["GET", "POST", "PUT"],
            "allowed_headers": ["Content-Type", "Authorization"],
            "exposed_headers": ["X-Request-Id"],
            "allow_credentials": True,
            "max_age": 3600,
        })
        assert result["valid"] is True
        assert len(result["errors"]) == 0


# ==========================================
# 2. CORS SECURITY ENFORCEMENT TESTS
# ==========================================
class TestCorsSecurityEnforcement:
    def test_enforce_returns_tracking_id_with_prefix(self):
        result = enforce_cors_policy({
            "allowed_origins": ["https://example.com"],
        })
        assert re.match(r"^VS-CORS-[A-Z0-9]{4}$", result["tracking_id"])

    def test_enforce_blocks_invalid_config(self):
        result = enforce_cors_policy(None)
        assert result["allowed"] is False
        assert re.match(r"^VS-CORS-[A-Z0-9]{4}$", result["tracking_id"])
        assert result["validation"]["valid"] is False

    def test_enforce_allows_valid_config(self):
        result = enforce_cors_policy({
            "allowed_origins": ["https://example.com"],
            "allowed_methods": ["GET", "POST"],
            "allow_credentials": True,
            "max_age": 3600,
        })
        assert result["allowed"] is True
        assert result["validation"]["valid"] is True

    def test_enforce_logs_errors_in_dev(self, monkeypatch, caplog):
        monkeypatch.delenv("PYTHON_ENV", raising=False)
        monkeypatch.delenv("FLASK_ENV", raising=False)
        monkeypatch.delenv("ENV", raising=False)
        with caplog.at_level("ERROR", logger="VibeShield"):
            enforce_cors_policy(None)
        assert "CORS Security Errors" in caplog.text

    def test_enforce_logs_warnings_in_dev(self, monkeypatch, caplog):
        monkeypatch.delenv("PYTHON_ENV", raising=False)
        monkeypatch.delenv("FLASK_ENV", raising=False)
        monkeypatch.delenv("ENV", raising=False)
        with caplog.at_level("WARNING", logger="VibeShield"):
            enforce_cors_policy({
                "allowed_origins": ["*"],
            })
        assert "CORS Security Warnings" in caplog.text

    def test_wildcard_subdomain_support(self):
        result = validate_cors_config({
            "allowed_origins": ["https://example.com", "*.example.com"],
        })
        assert result["valid"] is True
        assert len(result["errors"]) == 0

    def test_invalid_wildcard_subdomain_support(self):
        result = validate_cors_config({
            "allowed_origins": ["*example.com"],
        })
        assert result["valid"] is False
        assert any("Expected: \"https://example.com\" or \"*.example.com\"" in e for e in result["errors"])
