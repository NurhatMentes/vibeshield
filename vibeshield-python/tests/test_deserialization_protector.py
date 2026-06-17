import pytest
from src.deserialization_protector import (
    safe_json_parse,
    detect_unsafe_deserialization,
    VibeShieldDeserializationError
)
from src.middleware.safe_parser import enforce_safe_json

class TestDeserializationProtector:
    # ── safe_json_parse Depth Tests ──────────────────────────────────────────

    def test_safe_json_parse_valid_simple(self):
        """Should successfully parse a simple JSON object."""
        result = safe_json_parse('{"a": 1, "b": 2}')
        assert result == {"a": 1, "b": 2}

    def test_safe_json_parse_valid_list(self):
        """Should successfully parse a simple JSON list."""
        result = safe_json_parse('[1, 2, 3]')
        assert result == [1, 2, 3]

    def test_safe_json_parse_valid_nested(self):
        """Should successfully parse a nested JSON object within the depth limit."""
        # Depth 3: object -> object -> array
        payload = '{"a": {"b": [1, 2]}}'
        result = safe_json_parse(payload, max_depth=5)
        assert result == {"a": {"b": [1, 2]}}

    def test_safe_json_parse_max_depth_reached(self):
        """Should successfully parse when the depth matches max_depth exactly."""
        # Depth 2: object -> object
        payload = '{"a": {"b": 1}}'
        result = safe_json_parse(payload, max_depth=2)
        assert result == {"a": {"b": 1}}

    def test_safe_json_parse_depth_exceeded_dict(self):
        """Should raise VibeShieldDeserializationError when dict depth exceeds max_depth."""
        # Depth 3: object -> object -> object
        payload = '{"a": {"b": {"c": 1}}}'
        with pytest.raises(VibeShieldDeserializationError) as exc_info:
            safe_json_parse(payload, max_depth=2)
        assert "Maximum JSON depth of 2 exceeded." in str(exc_info.value)

    def test_safe_json_parse_depth_exceeded_array(self):
        """Should raise VibeShieldDeserializationError when array depth exceeds max_depth."""
        # Depth 3: array -> array -> array
        payload = '[[[1]]]'
        with pytest.raises(VibeShieldDeserializationError) as exc_info:
            safe_json_parse(payload, max_depth=2)
        assert "Maximum JSON depth of 2 exceeded." in str(exc_info.value)

    def test_safe_json_parse_depth_exceeded_mixed(self):
        """Should raise VibeShieldDeserializationError when mixed depth exceeds max_depth."""
        # Depth 4: object -> array -> object -> array
        payload = '{"a": [{"b": [1]}]}'
        with pytest.raises(VibeShieldDeserializationError) as exc_info:
            safe_json_parse(payload, max_depth=3)
        assert "Maximum JSON depth of 3 exceeded." in str(exc_info.value)

    def test_safe_json_parse_string_with_brackets(self):
        """Should not count brackets inside string literals towards JSON depth."""
        payload = '{"a": "[[[[[[[not_nested]]]]]]]"}'
        result = safe_json_parse(payload, max_depth=2)
        assert result == {"a": "[[[[[[[not_nested]]]]]]]"}

    def test_safe_json_parse_string_with_escaped_quotes(self):
        """Should correctly skip escaped quotes inside string literals."""
        payload = '{"a": "some \\"escaped\\" text", "b": {"c": 1}}'
        result = safe_json_parse(payload, max_depth=3)
        assert result == {"a": 'some "escaped" text', "b": {"c": 1}}

    # ── safe_json_parse Key Sanitisation Tests ───────────────────────────────

    def test_safe_json_parse_proto_sanitized(self):
        """Should remove the __proto__ key from JSON objects."""
        payload = '{"a": 1, "__proto__": {"polluted": true}}'
        result = safe_json_parse(payload)
        assert result == {"a": 1}

    def test_safe_json_parse_constructor_sanitized(self):
        """Should remove the constructor key from JSON objects."""
        payload = '{"a": 1, "constructor": {"polluted": true}}'
        result = safe_json_parse(payload)
        assert result == {"a": 1}

    def test_safe_json_parse_prototype_sanitized(self):
        """Should remove the prototype key from JSON objects."""
        payload = '{"a": 1, "prototype": {"polluted": true}}'
        result = safe_json_parse(payload)
        assert result == {"a": 1}

    def test_safe_json_parse_nested_key_sanitized(self):
        """Should recursively remove forbidden keys from nested JSON objects."""
        payload = '{"nested": {"__proto__": "danger", "safe": 123}}'
        result = safe_json_parse(payload)
        assert result == {"nested": {"safe": 123}}

    def test_safe_json_parse_list_key_sanitized(self):
        """Should recursively remove forbidden keys from JSON objects nested inside lists."""
        payload = '[{"__proto__": "danger", "safe": 1}, {"prototype": "danger", "safe": 2}]'
        result = safe_json_parse(payload)
        assert result == [{"safe": 1}, {"safe": 2}]

    def test_safe_json_parse_primitive_values(self):
        """Should parse primitive values correctly."""
        assert safe_json_parse('123') == 123
        assert safe_json_parse('"hello"') == 'hello'
        assert safe_json_parse('null') is None

    def test_safe_json_parse_malformed(self):
        """Should raise VibeShieldDeserializationError for malformed JSON payloads."""
        with pytest.raises(VibeShieldDeserializationError) as exc_info:
            safe_json_parse('{"invalid": json}')
        assert "Malformed JSON payload:" in str(exc_info.value)

    # ── enforce_safe_json Middleware Tests ────────────────────────────────────

    def test_enforce_safe_json_empty_string(self):
        """Should return empty dict when request body is empty string."""
        assert enforce_safe_json("") == {}

    def test_enforce_safe_json_whitespace_string(self):
        """Should return empty dict when request body is whitespace string."""
        assert enforce_safe_json("   ") == {}

    def test_enforce_safe_json_none(self):
        """Should return empty dict when request body is None."""
        assert enforce_safe_json(None) == {}

    def test_enforce_safe_json_valid_body(self):
        """Should successfully parse a valid request body using middleware."""
        assert enforce_safe_json('{"key": "value"}') == {"key": "value"}

    def test_enforce_safe_json_depth_limit_middleware(self):
        """Should enforce maximum depth check within the middleware wrapper."""
        with pytest.raises(VibeShieldDeserializationError):
            enforce_safe_json('{"a": {"b": {"c": 1}}}', max_depth=2)

    # ── detect_unsafe_deserialization Static Analysis Tests ──────────────────

    def test_detect_unsafe_deserialization_empty(self):
        """Should return safe for empty input."""
        res = detect_unsafe_deserialization("")
        assert res["safe"] is True
        assert res["findings"] == []

    def test_detect_unsafe_deserialization_safe_code(self):
        """Should return safe for code with no dangerous deserialization libraries."""
        code = "x = 1\ny = json.loads('{}')"
        res = detect_unsafe_deserialization(code)
        assert res["safe"] is True
        assert res["findings"] == []

    def test_detect_unsafe_deserialization_pickle_loads(self):
        """Should detect pickle.loads as unsafe."""
        code = "import pickle\npickle.loads(payload)"
        res = detect_unsafe_deserialization(code)
        assert res["safe"] is False
        assert len(res["findings"]) == 1
        assert res["findings"][0]["line"] == 2
        assert res["findings"][0]["pattern"] == "pickle"
        assert res["findings"][0]["severity"] == "critical"

    def test_detect_unsafe_deserialization_pickle_load(self):
        """Should detect pickle.load as unsafe."""
        code = "import pickle\npickle.load(file_handle)"
        res = detect_unsafe_deserialization(code)
        assert res["safe"] is False
        assert len(res["findings"]) == 1
        assert res["findings"][0]["line"] == 2
        assert res["findings"][0]["pattern"] == "pickle"

    def test_detect_unsafe_deserialization_marshal(self):
        """Should detect marshal.loads/load as unsafe."""
        code = "import marshal\nmarshal.loads(bytes_data)"
        res = detect_unsafe_deserialization(code)
        assert res["safe"] is False
        assert len(res["findings"]) == 1
        assert res["findings"][0]["line"] == 2
        assert res["findings"][0]["pattern"] == "marshal"

    def test_detect_unsafe_deserialization_shelve(self):
        """Should detect shelve.open as unsafe."""
        code = "import shelve\nshelve.open('database')"
        res = detect_unsafe_deserialization(code)
        assert res["safe"] is False
        assert len(res["findings"]) == 1
        assert res["findings"][0]["line"] == 2
        assert res["findings"][0]["pattern"] == "shelve"

    def test_detect_unsafe_deserialization_dill(self):
        """Should detect dill.loads/load as unsafe."""
        code = "import dill\ndill.loads(payload)"
        res = detect_unsafe_deserialization(code)
        assert res["safe"] is False
        assert len(res["findings"]) == 1
        assert res["findings"][0]["line"] == 2
        assert res["findings"][0]["pattern"] == "dill"

    def test_detect_unsafe_deserialization_jsonpickle(self):
        """Should detect jsonpickle.decode as unsafe."""
        code = "import jsonpickle\njsonpickle.decode(payload)"
        res = detect_unsafe_deserialization(code)
        assert res["safe"] is False
        assert len(res["findings"]) == 1
        assert res["findings"][0]["line"] == 2
        assert res["findings"][0]["pattern"] == "jsonpickle"

    def test_detect_unsafe_deserialization_yaml_load_unsafe(self):
        """Should detect yaml.load without SafeLoader as unsafe."""
        code = "import yaml\nyaml.load(data)"
        res = detect_unsafe_deserialization(code)
        assert res["safe"] is False
        assert len(res["findings"]) == 1
        assert res["findings"][0]["line"] == 2
        assert res["findings"][0]["pattern"] == "yaml.load without SafeLoader"

    def test_detect_unsafe_deserialization_yaml_load_safe_loader(self):
        """Should consider yaml.load safe when SafeLoader is explicitly used."""
        code = "import yaml\nyaml.load(data, Loader=yaml.SafeLoader)"
        res = detect_unsafe_deserialization(code)
        assert res["safe"] is True
        assert res["findings"] == []

    def test_detect_unsafe_deserialization_yaml_load_safe_load(self):
        """Should consider yaml.load safe when safe_load is in the context."""
        code = "import yaml\nyaml.load(data, Loader=yaml.safe_load)"
        res = detect_unsafe_deserialization(code)
        assert res["safe"] is True
        assert res["findings"] == []

    def test_detect_unsafe_deserialization_multiple_findings(self):
        """Should report multiple unsafe findings, sorted by line number."""
        code = "pickle.loads(a)\nshelve.open(b)\nyaml.load(c)"
        res = detect_unsafe_deserialization(code)
        assert res["safe"] is False
        assert len(res["findings"]) == 3
        # Sorted by line
        assert res["findings"][0]["line"] == 1
        assert res["findings"][0]["pattern"] == "pickle"
        assert res["findings"][1]["line"] == 2
        assert res["findings"][1]["pattern"] == "shelve"
        assert res["findings"][2]["line"] == 3
        assert res["findings"][2]["pattern"] == "yaml.load without SafeLoader"
