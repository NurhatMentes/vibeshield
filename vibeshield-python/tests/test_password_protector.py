import asyncio
import sys
from unittest.mock import MagicMock, patch
import pytest

from src.password_protector import (
    COMMON_PASSWORDS,
    calculate_shannon_entropy,
    validate_password,
    generate_password_policy_report,
)
from src.middleware.password_validator import validate_password_policy

# Helpers for mocking Starlette/FastAPI requests
class MockFastAPIRequest:
    def __init__(self, body_dict):
        self.scope = {"receive": True}
        self.receive = lambda: None
        self._json = body_dict

# 1. Entropy: Empty string
def test_entropy_empty():
    assert calculate_shannon_entropy("") == 0.0

# 2. Entropy: Single repeated character
def test_entropy_single_repeated():
    assert calculate_shannon_entropy("aaaaa") == 0.0

# 3. Entropy: Two alternating characters
def test_entropy_two_alternating():
    assert calculate_shannon_entropy("abab") == 1.0

# 4. Entropy: Diverse string
def test_entropy_diverse():
    entropy = calculate_shannon_entropy("P@ssw0rd123!")
    assert entropy > 3.0

# 5. Validation: Empty password
def test_validation_empty():
    result = validate_password("")
    assert result["valid"] is False
    assert result["score"] == 0
    assert "Password cannot be empty" in result["errors"]
    assert result["strength"] == "very_weak"

# 6. Validation: Password exceeds maximum limit
def test_validation_max_length():
    result = validate_password("a" * 129)
    assert result["valid"] is False
    assert any("exceeds maximum limit" in e for e in result["errors"])

# 7. Validation: Password too short
def test_validation_min_length():
    result = validate_password("Short1!")
    assert result["valid"] is False
    assert any("too short" in e for e in result["errors"])

# 8. Validation: Custom min length
def test_validation_custom_min_length():
    result = validate_password("Short1!", min_length=6)
    assert result["valid"] is True

# 9. Validation: Custom max length
def test_validation_custom_max_length():
    result = validate_password("a" * 20, max_length=15)
    assert result["valid"] is False
    assert any("exceeds maximum limit" in e for e in result["errors"])

# 10. Validation: Common password
def test_validation_common_password():
    result = validate_password("password123")
    assert result["valid"] is False
    assert any("commonly used passwords" in e for e in result["errors"])

# 11. Validation: Common password case insensitive
def test_validation_common_password_case_insensitive():
    result = validate_password("PASSWORD123")
    assert result["valid"] is False
    assert any("commonly used passwords" in e for e in result["errors"])

# 12. Validation: Not on blacklist
def test_validation_not_common_password():
    # A password that meets other requirements and is not common
    result = validate_password("Tr0ub4dor&3Secure!")
    assert result["valid"] is True
    assert not any("commonly used passwords" in e for e in result["errors"])

# 13. Validation: Complexity pass
def test_validation_complexity_pass():
    result = validate_password("Abcdef1234!!") # Upper, lower, digit, special (all 4)
    assert result["valid"] is True

# 14. Validation: Complexity fail
def test_validation_complexity_fail():
    result = validate_password("abcdefghijklmnop") # Only lowercase
    assert result["valid"] is False
    assert any("complexity groups" in e for e in result["errors"])

# 15. Validation: Complexity requirement disabled
def test_validation_complexity_disabled():
    result = validate_password("abcdefghijklmnop", require_complexity=False)
    assert result["valid"] is True

# 16. Validation: Context leak username
def test_validation_context_username():
    context = {"username": "admin_user"}
    result = validate_password("my_admin_user_pass123!", context=context)
    assert result["valid"] is False
    assert any("username" in e for e in result["errors"])

# 17. Validation: Context leak username too short ignored
def test_validation_context_username_too_short():
    context = {"username": "ad"}
    result = validate_password("my_ad_pass123!", context=context)
    assert result["valid"] is True

# 18. Validation: Context leak firstName
def test_validation_context_first_name():
    context = {"firstName": "Jonathan"}
    result = validate_password("pass_jonathan_123!", context=context)
    assert result["valid"] is False
    assert any("firstName" in e for e in result["errors"])

# 19. Validation: Context leak lastName
def test_validation_context_last_name():
    context = {"lastName": "DoeSmith"}
    result = validate_password("doeSmith_pass123!", context=context)
    assert result["valid"] is False
    assert any("lastName" in e for e in result["errors"])

# 20. Validation: Context leak email parts
def test_validation_context_email_parts():
    context = {"email": "john.doe@company.com"}
    result = validate_password("my_john_pass123!", context=context)
    assert result["valid"] is False
    assert any("email parts" in e for e in result["errors"])

# 21. Validation: Context leak email parts too short ignored
def test_validation_context_email_parts_too_short():
    context = {"email": "ab@cd.com"} # parts: ab, cd, com (ab, cd are < 3)
    result = validate_password("my_ab_pass123!", context=context)
    assert result["valid"] is True

# 22. Validation: Context leak birthdate parts
def test_validation_context_birthdate_parts():
    context = {"birthDate": "1990-12-31"}
    result = validate_password("pass_1990_secret!", context=context)
    assert result["valid"] is False
    assert any("birthDate parts" in e for e in result["errors"])

# 23. Validation: Context leak birthdate parts too short ignored
def test_validation_context_birthdate_parts_too_short():
    context = {"birthDate": "1-2-1990"} # parts: 1, 2, 1990 (1, 2 are < 2)
    result = validate_password("pass_1_secret!", context=context)
    assert result["valid"] is True

# 24. Validation: Repetitive characters warning
def test_validation_repetitive_characters():
    result = validate_password("Abcdef123!!!")
    assert "Password contains repetitive characters" in result["warnings"]

# 25. Validation: Sequential characters warning (ascending)
def test_validation_sequential_characters_ascending():
    result = validate_password("Abc123xyz!!!")
    assert "Password contains sequential characters" in result["warnings"]

# 26. Validation: Sequential characters warning (descending)
def test_validation_sequential_characters_descending():
    result = validate_password("321Abcxyz!!!")
    assert "Password contains sequential characters" in result["warnings"]

# 27. Scoring: Basic strong password
def test_scoring_basic():
    result = validate_password("Tr0ub4dor&3Secure!")
    assert result["score"] >= 80
    assert result["strength"] == "very_strong"

# 28. Scoring: Reductions applied
def test_scoring_reductions():
    # Sequential + Repetitive + Common reductions
    result = validate_password("123456")
    assert result["score"] <= 10
    assert result["strength"] == "very_weak"

# 29. Scoring: Bounds check
def test_scoring_bounds():
    # Make sure score stays in [0, 100]
    result_weak = validate_password("111")
    assert 0 <= result_weak["score"] <= 100
    result_strong = validate_password("A" * 50 + "1a!" + "xyz")
    assert 0 <= result_strong["score"] <= 100

# 30. Strength classification boundaries
def test_strength_classification():
    # very_weak (< 20)
    res = validate_password("123456")
    assert res["strength"] == "very_weak"
    # weak (< 40)
    res = validate_password("abcdef", min_length=6, require_complexity=False)
    assert res["strength"] == "weak"

# 31. Report Generation Content
def test_policy_report_content():
    report = generate_password_policy_report("Tr0ub4dor&3Secure!")
    assert "✅ SECURE" in report or "❌ WEAK" in report
    assert "Strength Score:" in report
    assert "Shannon Entropy:" in report
    assert "Validation Status:" in report
    assert "Errors:" in report
    assert "Warnings:" in report

# 32. FastAPI Async Middleware: Allow valid passwords
@pytest.mark.asyncio
async def test_fastapi_async_middleware_valid():
    @validate_password_policy()
    async def endpoint(request):
        return "success"
    
    req = MockFastAPIRequest({"password": "Tr0ub4dor&3Secure!"})
    res = await endpoint(req)
    assert res == "success"

# 33. FastAPI Async Middleware: Block invalid passwords (status 400 JSONResponse)
@pytest.mark.asyncio
async def test_fastapi_async_middleware_invalid():
    @validate_password_policy(min_length=12)
    async def endpoint(request):
        return "success"
    
    req = MockFastAPIRequest({"password": "short"})
    
    # We mock starlette JSONResponse if not available
    res = await endpoint(req)
    assert res is not None
    assert res.status_code == 400
    import json
    data = json.loads(res.body.decode('utf-8'))
    assert data["error"] == "Bad Request"
    assert data["details"]["valid"] is False

# 34. FastAPI Sync Middleware: Allow valid passwords
def test_fastapi_sync_middleware_valid():
    @validate_password_policy()
    def endpoint(request):
        return "success"
    
    req = MockFastAPIRequest({"password": "Tr0ub4dor&3Secure!"})
    res = endpoint(req)
    assert res == "success"

# 35. FastAPI Sync Middleware: Block invalid passwords
def test_fastapi_sync_middleware_invalid():
    @validate_password_policy(min_length=12)
    def endpoint(request):
        return "success"
    
    req = MockFastAPIRequest({"password": "short"})
    res = endpoint(req)
    assert res is not None
    assert res.status_code == 400

# 36. Flask Middleware: Allow valid passwords
def test_flask_sync_middleware_valid():
    flask_mock = MagicMock()
    flask_mock.request.is_json = True
    flask_mock.request.get_json.return_value = {"password": "Tr0ub4dor&3Secure!"}
    flask_mock.request.method = "POST"

    with patch.dict("sys.modules", {"flask": flask_mock}):
        @validate_password_policy()
        def view():
            return "success"

        res = view()
        assert res == "success"

# 37. Flask Middleware: Block invalid passwords
def test_flask_sync_middleware_invalid():
    flask_mock = MagicMock()
    flask_mock.request.is_json = True
    flask_mock.request.get_json.return_value = {"password": "short"}
    flask_mock.request.method = "POST"
    flask_mock.jsonify = lambda x: x

    with patch.dict("sys.modules", {"flask": flask_mock}):
        @validate_password_policy(min_length=12)
        def view():
            return "success"

        res = view()
        assert res is not None
        assert res[1] == 400
        assert res[0]["error"] == "Bad Request"
        assert res[0]["details"]["valid"] is False
