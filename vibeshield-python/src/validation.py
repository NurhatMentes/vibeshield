import re
from typing import Dict, Any, Tuple, Optional

EMAIL_REGEX = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')

def validate_payload(payload: Any, schema: Dict[str, Dict[str, Any]]) -> Tuple[bool, Optional[Dict[str, str]]]:
    if not isinstance(payload, dict):
        return False, {"_root": "Payload must be a JSON object"}
        
    errors = {}
    has_errors = False

    for key, rule in schema.items():
        value = payload.get(key)
        is_missing = value is None

        if is_missing:
            if rule.get('required'):
                errors[key] = f"Field '{key}' is required"
                has_errors = True
            continue

        # Type Validation
        actual_type = None
        if isinstance(value, str):
            actual_type = 'string'
        elif isinstance(value, bool):
            actual_type = 'boolean'
        elif isinstance(value, (int, float)):
            actual_type = 'number'
        elif isinstance(value, list):
            actual_type = 'array'
        elif isinstance(value, dict):
            actual_type = 'object'
            
        expected_type = rule.get('type')
        if actual_type != expected_type:
            errors[key] = f"Expected type '{expected_type}', but received '{actual_type}'"
            has_errors = True
            continue

        # Constraints Validation
        if expected_type == 'string':
            min_len = rule.get('min')
            if min_len is not None and len(value) < min_len:
                errors[key] = f"String length must be at least {min_len} characters"
                has_errors = True
                
            max_len = rule.get('max')
            if max_len is not None and len(value) > max_len:
                errors[key] = f"String length must not exceed {max_len} characters"
                has_errors = True
                
            if rule.get('format') == 'email' and not EMAIL_REGEX.match(value):
                errors[key] = "Invalid email format"
                has_errors = True
                
        elif expected_type == 'number':
            min_val = rule.get('min')
            if min_val is not None and value < min_val:
                errors[key] = f"Value must be greater than or equal to {min_val}"
                has_errors = True
                
            max_val = rule.get('max')
            if max_val is not None and value > max_val:
                errors[key] = f"Value must be less than or equal to {max_val}"
                has_errors = True
                
        elif expected_type == 'array':
            min_len = rule.get('min')
            if min_len is not None and len(value) < min_len:
                errors[key] = f"Array must contain at least {min_len} items"
                has_errors = True
                
            max_len = rule.get('max')
            if max_len is not None and len(value) > max_len:
                errors[key] = f"Array must not contain more than {max_len} items"
                has_errors = True

    if has_errors:
        return False, errors
    return True, None
