import re
import sys
import math
import pytest
from unittest.mock import MagicMock, AsyncMock

from src.schema_validator import validate_schema, is_valid_date
from src.middleware.request_validator import validate_request


# ==========================================
# 1. CORE VALIDATOR - SIMPLE TYPE VALIDATIONS
# ==========================================

class TestSchemaValidatorTypes:
    def test_reject_non_dict_root(self):
        result = validate_schema("not a dict", {"name": {"type": "string"}})
        assert result["valid"] is False
        assert result["errors"] == [{"field": "", "message": "Root data must be a dictionary"}]
        assert result["sanitized_data"] is None

    def test_reject_none_root(self):
        result = validate_schema(None, {"name": {"type": "string"}})
        assert result["valid"] is False
        assert result["errors"] == [{"field": "", "message": "Root data must be a dictionary"}]

    def test_empty_data_empty_schema(self):
        result = validate_schema({}, {})
        assert result["valid"] is True
        assert result["errors"] == []
        assert result["sanitized_data"] == {}

    def test_string_success(self):
        schema = {"name": {"type": "string"}}
        result = validate_schema({"name": "Alice"}, schema)
        assert result["valid"] is True
        assert result["sanitized_data"] == {"name": "Alice"}

    def test_string_invalid_type_int(self):
        schema = {"name": {"type": "string"}}
        result = validate_schema({"name": 123}, schema)
        assert result["valid"] is False
        assert len(result["errors"]) == 1
        assert result["errors"][0]["field"] == "name"
        assert "Expected type string" in result["errors"][0]["message"]

    def test_string_invalid_type_bool(self):
        schema = {"name": {"type": "string"}}
        result = validate_schema({"name": True}, schema)
        assert result["valid"] is False
        assert "Expected type string" in result["errors"][0]["message"]

    def test_string_trim(self):
        schema = {"name": {"type": "string", "trim": True}}
        result = validate_schema({"name": "   Bob   "}, schema)
        assert result["valid"] is True
        assert result["sanitized_data"] == {"name": "Bob"}

    def test_number_success_int(self):
        schema = {"age": {"type": "number"}}
        result = validate_schema({"age": 30}, schema)
        assert result["valid"] is True
        assert result["sanitized_data"] == {"age": 30}

    def test_number_success_float(self):
        schema = {"price": {"type": "number"}}
        result = validate_schema({"price": 19.99}, schema)
        assert result["valid"] is True
        assert result["sanitized_data"] == {"price": 19.99}

    def test_number_invalid_type_bool(self):
        schema = {"age": {"type": "number"}}
        # In Python, isinstance(True, int) is True, so reject explicitly
        result = validate_schema({"age": True}, schema)
        assert result["valid"] is False
        assert "Expected type number" in result["errors"][0]["message"]

    def test_number_invalid_type_str(self):
        schema = {"age": {"type": "number"}}
        result = validate_schema({"age": "30"}, schema)
        assert result["valid"] is False
        assert "Expected type number" in result["errors"][0]["message"]

    def test_number_invalid_type_nan(self):
        schema = {"price": {"type": "number"}}
        result = validate_schema({"price": float("nan")}, schema)
        assert result["valid"] is False
        assert "Expected type number" in result["errors"][0]["message"]

    def test_boolean_success(self):
        schema = {"active": {"type": "boolean"}}
        result = validate_schema({"active": True}, schema)
        assert result["valid"] is True
        assert result["sanitized_data"] == {"active": True}

        result = validate_schema({"active": False}, schema)
        assert result["valid"] is True
        assert result["sanitized_data"] == {"active": False}

    def test_boolean_invalid_type(self):
        schema = {"active": {"type": "boolean"}}
        result = validate_schema({"active": 1}, schema) # In Python 1 can act like True, but reject
        assert result["valid"] is False
        assert "Expected type boolean" in result["errors"][0]["message"]

    def test_object_success(self):
        schema = {"profile": {"type": "object"}}
        result = validate_schema({"profile": {"theme": "dark"}}, schema)
        assert result["valid"] is True
        assert result["sanitized_data"] == {"profile": {"theme": "dark"}}

    def test_object_invalid_type(self):
        schema = {"profile": {"type": "object"}}
        result = validate_schema({"profile": [1, 2, 3]}, schema)
        assert result["valid"] is False
        assert "Expected type object" in result["errors"][0]["message"]

    def test_array_success_list(self):
        schema = {"tags": {"type": "array"}}
        result = validate_schema({"tags": ["a", "b"]}, schema)
        assert result["valid"] is True
        assert result["sanitized_data"] == {"tags": ["a", "b"]}

    def test_array_success_tuple(self):
        schema = {"tags": {"type": "array"}}
        result = validate_schema({"tags": ("a", "b")}, schema)
        assert result["valid"] is True
        # Normalize to list
        assert result["sanitized_data"] == {"tags": ["a", "b"]}

    def test_array_invalid_type(self):
        schema = {"tags": {"type": "array"}}
        result = validate_schema({"tags": "not an array"}, schema)
        assert result["valid"] is False
        assert "Expected type array" in result["errors"][0]["message"]


# ==========================================
# 2. REQUIRED VS OPTIONAL & NULLABILITY
# ==========================================

class TestSchemaValidatorNullability:
    def test_required_missing(self):
        schema = {"name": {"type": "string", "required": True}}
        result = validate_schema({}, schema)
        assert result["valid"] is False
        assert result["errors"] == [{"field": "name", "message": "Field is required", "expected": "string"}]

    def test_required_exists_none_not_allowed(self):
        schema = {"name": {"type": "string", "required": True}}
        result = validate_schema({"name": None}, schema)
        assert result["valid"] is False
        assert result["errors"] == [{"field": "name", "message": "Value cannot be null", "value": None, "expected": "string"}]

    def test_optional_missing(self):
        schema = {"name": {"type": "string", "required": False}}
        result = validate_schema({}, schema)
        assert result["valid"] is True
        # Optional missing is not in sanitized_data
        assert result["sanitized_data"] == {}

    def test_allow_null_true_camelcase(self):
        schema = {"name": {"type": "string", "required": True, "allowNull": True}}
        result = validate_schema({"name": None}, schema)
        assert result["valid"] is True
        assert result["sanitized_data"] == {"name": None}

    def test_allow_null_true_snakecase(self):
        schema = {"name": {"type": "string", "required": True, "allow_null": True}}
        result = validate_schema({"name": None}, schema)
        assert result["valid"] is True
        assert result["sanitized_data"] == {"name": None}

    def test_allow_null_false(self):
        schema = {"name": {"type": "string", "allowNull": False}}
        result = validate_schema({"name": None}, schema)
        assert result["valid"] is False
        assert "Value cannot be null" in result["errors"][0]["message"]


# ==========================================
# 3. MIN/MAX CONSTRAINTS
# ==========================================

class TestSchemaValidatorMinMax:
    def test_string_min_length(self):
        schema = {"username": {"type": "string", "min": 5}}
        result = validate_schema({"username": "abc"}, schema)
        assert result["valid"] is False
        assert "Length must be at least 5" in result["errors"][0]["message"]

    def test_string_max_length(self):
        schema = {"username": {"type": "string", "max": 5}}
        result = validate_schema({"username": "abcdef"}, schema)
        assert result["valid"] is False
        assert "Length must be at most 5" in result["errors"][0]["message"]

    def test_number_min_value(self):
        schema = {"age": {"type": "number", "min": 18}}
        result = validate_schema({"age": 17}, schema)
        assert result["valid"] is False
        assert "Value must be at least 18" in result["errors"][0]["message"]

    def test_number_max_value(self):
        schema = {"age": {"type": "number", "max": 65}}
        result = validate_schema({"age": 66}, schema)
        assert result["valid"] is False
        assert "Value must be at most 65" in result["errors"][0]["message"]

    def test_array_min_items(self):
        schema = {"items": {"type": "array", "min": 3}}
        result = validate_schema({"items": [1, 2]}, schema)
        assert result["valid"] is False
        assert "Array must contain at least 3 items" in result["errors"][0]["message"]

    def test_array_max_items(self):
        schema = {"items": {"type": "array", "max": 3}}
        result = validate_schema({"items": [1, 2, 3, 4]}, schema)
        assert result["valid"] is False
        assert "Array must contain at most 3 items" in result["errors"][0]["message"]


# ==========================================
# 4. FORMATS
# ==========================================

class TestSchemaValidatorFormats:
    def test_email_valid(self):
        schema = {"email": {"type": "string", "format": "email"}}
        result = validate_schema({"email": "test@example.com"}, schema)
        assert result["valid"] is True

    def test_email_invalid(self):
        schema = {"email": {"type": "string", "format": "email"}}
        result = validate_schema({"email": "invalid-email"}, schema)
        assert result["valid"] is False
        assert "Invalid email format" in result["errors"][0]["message"]

    def test_uuid_valid(self):
        schema = {"id": {"type": "string", "format": "uuid"}}
        result = validate_schema({"id": "123e4567-e89b-12d3-a456-426614174000"}, schema)
        assert result["valid"] is True

    def test_uuid_invalid(self):
        schema = {"id": {"type": "string", "format": "uuid"}}
        result = validate_schema({"id": "123e4567-e89b"}, schema)
        assert result["valid"] is False
        assert "Invalid uuid format" in result["errors"][0]["message"]

    def test_url_valid(self):
        schema = {"website": {"type": "string", "format": "url"}}
        result = validate_schema({"website": "https://example.com/path"}, schema)
        assert result["valid"] is True

    def test_url_invalid(self):
        schema = {"website": {"type": "string", "format": "url"}}
        result = validate_schema({"website": "ftp://invalid-url"}, schema)
        assert result["valid"] is False
        assert "Invalid url format" in result["errors"][0]["message"]

    def test_ipv4_valid(self):
        schema = {"ip": {"type": "string", "format": "ipv4"}}
        result = validate_schema({"ip": "192.168.1.1"}, schema)
        assert result["valid"] is True

    def test_ipv4_invalid(self):
        schema = {"ip": {"type": "string", "format": "ipv4"}}
        result = validate_schema({"ip": "256.0.0.1"}, schema)
        assert result["valid"] is False
        assert "Invalid ipv4 format" in result["errors"][0]["message"]

    def test_ipv6_valid(self):
        schema = {"ip": {"type": "string", "format": "ipv6"}}
        result = validate_schema({"ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}, schema)
        assert result["valid"] is True

    def test_ipv6_invalid(self):
        schema = {"ip": {"type": "string", "format": "ipv6"}}
        result = validate_schema({"ip": "2001:xyz"}, schema)
        assert result["valid"] is False
        assert "Invalid ipv6 format" in result["errors"][0]["message"]

    def test_phone_valid(self):
        schema = {"phone": {"type": "string", "format": "phone"}}
        result = validate_schema({"phone": "+1234567890"}, schema)
        assert result["valid"] is True

    def test_phone_invalid(self):
        schema = {"phone": {"type": "string", "format": "phone"}}
        result = validate_schema({"phone": "0"}, schema) # too short or invalid format
        assert result["valid"] is False
        assert "Invalid phone format" in result["errors"][0]["message"]

    def test_date_valid(self):
        schema = {"created_at": {"type": "string", "format": "date"}}
        # YYYY-MM-DD
        result = validate_schema({"created_at": "2026-06-17"}, schema)
        assert result["valid"] is True
        # ISO8601 with tz
        result = validate_schema({"created_at": "2026-06-17T19:53:25Z"}, schema)
        assert result["valid"] is True

    def test_date_invalid(self):
        schema = {"created_at": {"type": "string", "format": "date"}}
        result = validate_schema({"created_at": "2026/06/17"}, schema)
        assert result["valid"] is False
        assert "Invalid date format" in result["errors"][0]["message"]


# ==========================================
# 5. PATTERNS, ENUMS & WHITELIST CHECK
# ==========================================

class TestSchemaValidatorRules:
    def test_pattern_string(self):
        schema = {"code": {"type": "string", "pattern": r"^[A-Z]{3}-\d{3}$"}}
        result = validate_schema({"code": "ABC-123"}, schema)
        assert result["valid"] is True

        result = validate_schema({"code": "abc-123"}, schema)
        assert result["valid"] is False
        assert "does not match pattern" in result["errors"][0]["message"]

    def test_pattern_compiled(self):
        schema = {"code": {"type": "string", "pattern": re.compile(r"^[A-Z]{3}-\d{3}$")}}
        result = validate_schema({"code": "ABC-123"}, schema)
        assert result["valid"] is True

        result = validate_schema({"code": "abc-123"}, schema)
        assert result["valid"] is False

    def test_enum(self):
        schema = {"role": {"type": "string", "enum": ["admin", "user", "guest"]}}
        result = validate_schema({"role": "user"}, schema)
        assert result["valid"] is True

        result = validate_schema({"role": "superadmin"}, schema)
        assert result["valid"] is False
        assert "Value must be one of" in result["errors"][0]["message"]

    def test_whitelist_root_level(self):
        schema = {"name": {"type": "string"}}
        result = validate_schema({"name": "Alice", "age": 30}, schema)
        assert result["valid"] is False
        assert len(result["errors"]) == 1
        assert result["errors"][0]["field"] == "age"
        assert "Unknown field \"age\" is not allowed" in result["errors"][0]["message"]


# ==========================================
# 6. RECURSIVE & NESTED VALIDATIONS
# ==========================================

class TestSchemaValidatorNested:
    def test_nested_object_success(self):
        schema = {
            "user": {
                "type": "object",
                "schema": {
                    "profile": {
                        "type": "object",
                        "schema": {
                            "email": {"type": "string", "format": "email", "required": True}
                        }
                    }
                }
            }
        }
        data = {"user": {"profile": {"email": "test@example.com"}}}
        result = validate_schema(data, schema)
        assert result["valid"] is True
        assert result["sanitized_data"] == data

    def test_nested_object_error_path(self):
        schema = {
            "user": {
                "type": "object",
                "schema": {
                    "profile": {
                        "type": "object",
                        "schema": {
                            "email": {"type": "string", "format": "email", "required": True}
                        }
                    }
                }
            }
        }
        data = {"user": {"profile": {"email": "invalid-email"}}}
        result = validate_schema(data, schema)
        assert result["valid"] is False
        assert result["errors"][0]["field"] == "user.profile.email"
        assert "Invalid email format" in result["errors"][0]["message"]

    def test_nested_object_whitelist(self):
        schema = {
            "user": {
                "type": "object",
                "schema": {
                    "name": {"type": "string"}
                }
            }
        }
        data = {"user": {"name": "Alice", "age": 30}}
        result = validate_schema(data, schema)
        assert result["valid"] is False
        assert result["errors"][0]["field"] == "user.age"
        assert "Unknown field \"age\" is not allowed" in result["errors"][0]["message"]

    def test_nested_array_element_success_camelcase(self):
        schema = {
            "items": {
                "type": "array",
                "elementSchema": {
                    "type": "object",
                    "schema": {
                        "id": {"type": "number", "required": True}
                    }
                }
            }
        }
        data = {"items": [{"id": 1}, {"id": 2}]}
        result = validate_schema(data, schema)
        assert result["valid"] is True
        assert result["sanitized_data"] == data

    def test_nested_array_element_success_snakecase(self):
        schema = {
            "items": {
                "type": "array",
                "element_schema": {
                    "type": "object",
                    "schema": {
                        "id": {"type": "number", "required": True}
                    }
                }
            }
        }
        data = {"items": [{"id": 1}, {"id": 2}]}
        result = validate_schema(data, schema)
        assert result["valid"] is True
        assert result["sanitized_data"] == data

    def test_nested_array_element_error_path(self):
        schema = {
            "items": {
                "type": "array",
                "elementSchema": {
                    "type": "object",
                    "schema": {
                        "id": {"type": "number", "required": True}
                    }
                }
            }
        }
        data = {"items": [{"id": 1}, {"id": "invalid"}]}
        result = validate_schema(data, schema)
        assert result["valid"] is False
        assert result["errors"][0]["field"] == "items[1].id"
        assert "Expected type number" in result["errors"][0]["message"]


# ==========================================
# 7. MIDDLEWARE / DECORATOR TESTS
# ==========================================

class TestRequestValidatorMiddleware:
    @pytest.fixture(autouse=True)
    def clean_sys_modules(self):
        # Backup sys.modules
        old_modules = dict(sys.modules)
        yield
        # Restore sys.modules
        sys.modules.clear()
        sys.modules.update(old_modules)

    def test_flask_middleware_success(self):
        # 1. Mock Flask
        mock_request = MagicMock()
        mock_request.method = "POST"
        mock_request.is_json = True
        mock_request.get_json.return_value = {"username": "alice"}
        mock_request.args.to_dict.return_value = {}
        mock_request.view_args = {}

        mock_flask = MagicMock()
        mock_flask.request = mock_request
        sys.modules['flask'] = mock_flask

        schema = {"username": {"type": "string", "required": True}}

        @validate_request(schema)
        def my_view():
            return "success"

        result = my_view()
        assert result == "success"
        assert mock_request.sanitized_data == {"username": "alice"}

    def test_flask_middleware_validation_failure(self):
        # 1. Mock Flask
        mock_request = MagicMock()
        mock_request.method = "POST"
        mock_request.is_json = True
        mock_request.get_json.return_value = {"username": 123} # invalid type
        mock_request.args.to_dict.return_value = {}
        mock_request.view_args = {}

        mock_flask = MagicMock()
        mock_flask.request = mock_request
        mock_flask.jsonify = lambda d: d
        sys.modules['flask'] = mock_flask

        schema = {"username": {"type": "string", "required": True}}

        @validate_request(schema)
        def my_view():
            return "success"

        result, status_code = my_view()
        assert status_code == 400
        assert result["error"] == "Bad Request"
        assert "Schema validation failed" in result["message"]
        assert len(result["errors"]) > 0

    @pytest.mark.asyncio
    async def test_fastapi_async_middleware_success(self):
        # Mock FastAPI Request
        mock_request = MagicMock()
        # Mock scope and receive so it is identified as FastAPI Request
        mock_request.scope = {}
        mock_request.receive = {}
        mock_request.json = AsyncMock(return_value={"email": "user@example.com"})
        mock_request.query_params = {}
        mock_request.path_params = {}
        mock_request.state = MagicMock()

        schema = {"email": {"type": "string", "format": "email", "required": True}}

        @validate_request(schema)
        async def my_endpoint(request):
            return "success"

        result = await my_endpoint(mock_request)
        assert result == "success"
        assert mock_request.state.sanitized_data == {"email": "user@example.com"}

    @pytest.mark.asyncio
    async def test_fastapi_async_middleware_failure(self):
        # Mock FastAPI Request
        mock_request = MagicMock()
        mock_request.scope = {}
        mock_request.receive = {}
        mock_request.json = AsyncMock(return_value={"email": "invalid-email"})
        mock_request.query_params = {}
        mock_request.path_params = {}

        # Mock fastapi response module
        mock_responses = MagicMock()
        sys.modules['fastapi.responses'] = mock_responses
        # Let JSONResponse return a dict for verification
        mock_responses.JSONResponse = lambda status_code, content: (content, status_code)

        schema = {"email": {"type": "string", "format": "email", "required": True}}

        @validate_request(schema)
        async def my_endpoint(request):
            return "success"

        content, status_code = await my_endpoint(mock_request)
        assert status_code == 400
        assert content["error"] == "Bad Request"
        assert "Schema validation failed" in content["message"]

    def test_fastapi_sync_middleware_success(self):
        # Mock FastAPI Request
        mock_request = MagicMock()
        mock_request.scope = {}
        mock_request.receive = {}
        # Simulate synchronous body reading
        mock_request._json = {"age": 25}
        mock_request.query_params = {}
        mock_request.path_params = {}
        mock_request.state = MagicMock()

        schema = {"age": {"type": "number"}}

        @validate_request(schema)
        def my_endpoint(request):
            return "success"

        result = my_endpoint(mock_request)
        assert result == "success"
        assert mock_request.state.sanitized_data == {"age": 25}

    def test_fastapi_sync_middleware_failure(self):
        # Mock FastAPI Request
        mock_request = MagicMock()
        mock_request.scope = {}
        mock_request.receive = {}
        mock_request._json = {"age": "twenty-five"}
        mock_request.query_params = {}
        mock_request.path_params = {}

        # Mock fastapi response module
        mock_responses = MagicMock()
        sys.modules['fastapi.responses'] = mock_responses
        mock_responses.JSONResponse = lambda status_code, content: (content, status_code)

        schema = {"age": {"type": "number"}}

        @validate_request(schema)
        def my_endpoint(request):
            return "success"

        content, status_code = my_endpoint(mock_request)
        assert status_code == 400
        assert content["error"] == "Bad Request"
