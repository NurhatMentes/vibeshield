import pytest
from src.validation import validate_payload
from src.logging import start_audit_timer, end_audit_timer

schema = {
    "user": {
        "type": "object",
        "required": True,
        "schema": {
            "profile": {
                "type": "object",
                "required": True,
                "schema": {
                    "email": {"type": "string", "required": True, "format": "email"},
                    "age": {"type": "number", "min": 18}
                }
            }
        }
    },
    "cart": {
        "type": "object",
        "schema": {
            "items": {
                "type": "array",
                "min": 1,
                "elementSchema": {
                    "type": "object",
                    "schema": {
                        "productId": {"type": "string", "required": True},
                        "quantity": {"type": "number", "min": 1}
                    }
                }
            }
        }
    },
    "tags": {
        "type": "array",
        "elementSchema": {"type": "string", "min": 2}
    }
}

def test_validation_passes_valid_deep_payload():
    payload = {
        "user": {"profile": {"email": "test@example.com", "age": 25}},
        "cart": {"items": [{"productId": "abc", "quantity": 2}]},
        "tags": ["premium", "vip"]
    }
    is_valid, errors = validate_payload(payload, schema)
    assert is_valid is True
    assert errors is None

def test_validation_fails_missing_deep_required():
    payload = {
        "user": {"profile": {"age": 25}} # missing email
    }
    is_valid, errors = validate_payload(payload, schema)
    assert is_valid is False
    assert "user.profile.email" in errors
    assert "required" in errors["user.profile.email"]

def test_validation_fails_invalid_array_elements():
    payload = {
        "user": {"profile": {"email": "test@example.com", "age": 25}},
        "cart": {"items": [{"productId": "abc", "quantity": 2}, {"productId": "def", "quantity": 0}]} # 0 is invalid
    }
    is_valid, errors = validate_payload(payload, schema)
    assert is_valid is False
    assert "cart.items[1].quantity" in errors
    assert "greater than or equal to 1" in errors["cart.items[1].quantity"]

def test_validation_fails_primitive_array_elements():
    payload = {
        "user": {"profile": {"email": "test@example.com", "age": 25}},
        "tags": ["ok", "a"] # 'a' is too short
    }
    is_valid, errors = validate_payload(payload, schema)
    assert is_valid is False
    assert "tags[1]" in errors
    assert "at least 2 characters" in errors["tags[1]"]

def test_validation_fails_deep_type_mismatch():
    payload = {
        "user": {"profile": {"email": 123, "age": 25}} # email should be string
    }
    is_valid, errors = validate_payload(payload, schema)
    assert is_valid is False
    assert "user.profile.email" in errors
    assert "Expected type 'string'" in errors["user.profile.email"]

def test_validation_enforces_array_length_constraints():
    payload = {
        "user": {"profile": {"email": "test@example.com", "age": 25}},
        "cart": {"items": []} # requires at least 1
    }
    is_valid, errors = validate_payload(payload, schema)
    assert is_valid is False
    assert "cart.items" in errors
    assert "at least 1 items" in errors["cart.items"]

def test_performance_logging_timer():
    start = start_audit_timer()
    assert isinstance(start, float)
    duration = end_audit_timer(start)
    assert isinstance(duration, float)
    assert duration >= 0.0
