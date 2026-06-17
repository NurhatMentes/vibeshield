import math
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

def is_valid_date(val: str) -> bool:
    if not isinstance(val, str):
        return False
    # Validate date structure: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS...
    if not re.match(r"^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)?$", val):
        return False
    for fmt in ('%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ'):
        try:
            datetime.strptime(val, fmt)
            return True
        except ValueError:
            pass
    # Support fromisoformat for tz-aware strings
    try:
        datetime.fromisoformat(val.replace('Z', '+00:00'))
        return True
    except ValueError:
        pass
    return False

def validate_schema(data: Any, schema: Dict[str, Any]) -> Dict[str, Any]:
    errors = []
    if data is None or not isinstance(data, dict):
        return {
            "valid": False,
            "errors": [{"field": "", "message": "Root data must be a dictionary"}],
            "sanitized_data": None
        }

    sanitized_data = {}

    # Strict whitelist check at root level
    for key in data.keys():
        if key not in schema:
            errors.append({
                "field": key,
                "message": f'Unknown field "{key}" is not allowed',
                "value": data[key]
            })

    # Validate defined fields
    for key, field_schema in schema.items():
        value = data.get(key)
        # Check if key is actually in data (differentiating between None and missing)
        value_exists = key in data
        validate_field(
            value if value_exists else None,
            value_exists,
            field_schema,
            key,
            errors,
            sanitized_data,
            key
        )

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "sanitized_data": sanitized_data if len(errors) == 0 else None
    }

def validate_field(
    value: Any,
    exists: bool,
    field_schema: Dict[str, Any],
    path: str,
    errors: List[Dict[str, Any]],
    parent_sanitized: Dict[str, Any],
    key: str
) -> None:
    # Get configuration keys supporting both camelCase and snake_case
    required = field_schema.get("required", False)
    allow_null = field_schema.get("allowNull", field_schema.get("allow_null", False))
    trim = field_schema.get("trim", False)
    field_type = field_schema.get("type")
    field_min = field_schema.get("min")
    field_max = field_schema.get("max")
    format_rule = field_schema.get("format")
    pattern = field_schema.get("pattern")
    enum_values = field_schema.get("enum")
    sub_schema = field_schema.get("schema")
    element_schema = field_schema.get("elementSchema", field_schema.get("element_schema"))

    # 1. Required & Nullability checks
    if not exists:
        if required:
            errors.append({"field": path, "message": "Field is required", "expected": field_type})
        return

    if value is None:
        if allow_null:
            parent_sanitized[key] = None
        else:
            errors.append({"field": path, "message": "Value cannot be null", "value": value, "expected": field_type})
        return

    # 2. Strict Type Checking
    if field_type == "string":
        if not isinstance(value, str):
            errors.append({"field": path, "message": f"Expected type string, got {type(value).__name__}", "value": value, "expected": "string"})
            return
        if trim:
            value = value.strip()
    elif field_type == "number":
        # Reject bool (bool is subclass of int in python)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or (isinstance(value, float) and math.isnan(value)):
            errors.append({"field": path, "message": f"Expected type number, got {type(value).__name__}", "value": value, "expected": "number"})
            return
    elif field_type == "boolean":
        if not isinstance(value, bool):
            errors.append({"field": path, "message": f"Expected type boolean, got {type(value).__name__}", "value": value, "expected": "boolean"})
            return
    elif field_type == "object":
        if not isinstance(value, dict):
            errors.append({"field": path, "message": f"Expected type object, got {type(value).__name__}", "value": value, "expected": "object"})
            return
    elif field_type == "array":
        if not isinstance(value, (list, tuple)):
            errors.append({"field": path, "message": f"Expected type array, got {type(value).__name__}", "value": value, "expected": "array"})
            return
        # Normalize to list
        value = list(value)

    # 3. Min/Max Checks
    if field_type == "string":
        if field_min is not None and len(value) < field_min:
            errors.append({"field": path, "message": f"Length must be at least {field_min}", "value": value})
        if field_max is not None and len(value) > field_max:
            errors.append({"field": path, "message": f"Length must be at most {field_max}", "value": value})
    elif field_type == "number":
        if field_min is not None and value < field_min:
            errors.append({"field": path, "message": f"Value must be at least {field_min}", "value": value})
        if field_max is not None and value > field_max:
            errors.append({"field": path, "message": f"Value must be at most {field_max}", "value": value})
    elif field_type == "array":
        if field_min is not None and len(value) < field_min:
            errors.append({"field": path, "message": f"Array must contain at least {field_min} items", "value": value})
        if field_max is not None and len(value) > field_max:
            errors.append({"field": path, "message": f"Array must contain at most {field_max} items", "value": value})

    # 4. Format Checks
    if field_type == "string" and format_rule:
        valid = True
        if format_rule == "email":
            valid = bool(re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value))
        elif format_rule == "uuid":
            valid = bool(re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", value, re.IGNORECASE))
        elif format_rule == "url":
            valid = bool(re.match(r"^https?://[^\s/$.?#].[^\s]*$", value, re.IGNORECASE))
        elif format_rule == "ipv4":
            valid = bool(re.match(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", value))
        elif format_rule == "ipv6":
            valid = bool(re.match(r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$", value))
        elif format_rule == "phone":
            valid = bool(re.match(r"^\+?[1-9]\d{1,14}$", value))
        elif format_rule == "date":
            valid = is_valid_date(value)
        if not valid:
            errors.append({"field": path, "message": f"Invalid {format_rule} format", "value": value})

    # 5. Pattern Check
    if field_type == "string" and pattern:
        # pattern can be string or regex pattern object
        compiled = re.compile(pattern) if isinstance(pattern, str) else pattern
        if not compiled.search(value):
            # Try full match or search
            if not compiled.match(value):
                errors.append({"field": path, "message": f"Value does not match pattern: {pattern}", "value": value})

    # 6. Enum Check
    if enum_values is not None:
        if value not in enum_values:
            errors.append({"field": path, "message": f"Value must be one of: {enum_values}", "value": value})

    # 7. Recursive Object Validation
    if field_type == "object":
        if sub_schema:
            sub_sanitized = {}
            for sub_key in value.keys():
                if sub_key not in sub_schema:
                    errors.append({
                        "field": f"{path}.{sub_key}",
                        "message": f'Unknown field "{sub_key}" is not allowed',
                        "value": value[sub_key]
                    })
            for sub_key, sub_field_schema in sub_schema.items():
                sub_value_exists = sub_key in value
                validate_field(
                    value.get(sub_key) if sub_value_exists else None,
                    sub_value_exists,
                    sub_field_schema,
                    f"{path}.{sub_key}",
                    errors,
                    sub_sanitized,
                    sub_key
                )
            parent_sanitized[key] = sub_sanitized
        else:
            parent_sanitized[key] = dict(value)
        return

    # 8. Recursive Array Element Validation
    if field_type == "array":
        if element_schema:
            sub_sanitized = []
            for i, element_value in enumerate(value):
                element_path = f"{path}[{i}]"
                temp_parent = {}
                validate_field(element_value, True, element_schema, element_path, errors, temp_parent, "element")
                if "element" in temp_parent:
                    sub_sanitized.append(temp_parent["element"])
            parent_sanitized[key] = sub_sanitized
        else:
            parent_sanitized[key] = list(value)
        return

    parent_sanitized[key] = value
