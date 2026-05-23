import pytest
from src.validation import validate_payload
from src.logging import start_audit_timer, end_audit_timer

schema = {
    "email": {"type": "string", "required": True, "format": "email"},
    "age": {"type": "number", "min": 18, "max": 120},
    "tags": {"type": "array", "min": 1, "max": 3}
}

def test_validation_passes_valid_payload():
    payload = {
        "email": "test@example.com",
        "age": 25,
        "tags": ["premium"]
    }
    is_valid, errors = validate_payload(payload, schema)
    assert is_valid is True
    assert errors is None

def test_validation_fails_missing_required():
    payload = {"age": 25}
    is_valid, errors = validate_payload(payload, schema)
    assert is_valid is False
    assert "email" in errors
    assert "required" in errors["email"]

def test_validation_fails_invalid_email_format():
    payload = {"email": "not-an-email", "age": 25}
    is_valid, errors = validate_payload(payload, schema)
    assert is_valid is False
    assert "email" in errors
    assert "format" in errors["email"]

def test_validation_enforces_numeric_constraints():
    payload = {"email": "test@example.com", "age": 15}
    is_valid, errors = validate_payload(payload, schema)
    assert is_valid is False
    assert "age" in errors
    assert "greater than or equal to 18" in errors["age"]

def test_validation_enforces_array_length_constraints():
    payload = {"email": "test@example.com", "tags": ["a", "b", "c", "d"]}
    is_valid, errors = validate_payload(payload, schema)
    assert is_valid is False
    assert "tags" in errors
    assert "not contain more than 3 items" in errors["tags"]

def test_performance_logging_timer():
    start = start_audit_timer()
    assert isinstance(start, float)
    duration = end_audit_timer(start)
    assert isinstance(duration, float)
    assert duration >= 0.0
