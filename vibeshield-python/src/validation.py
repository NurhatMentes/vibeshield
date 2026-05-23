import re
from typing import Dict, Any, Tuple, Optional

EMAIL_REGEX = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')

def validate_payload(payload: Any, schema: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, str]]]:
    if not isinstance(payload, dict):
        return False, {"_root": "Payload must be a JSON object"}
        
    errors = {}

    def traverse(value: Any, rule: Dict[str, Any], path: str):
        is_missing = value is None

        if is_missing:
            if rule.get('required'):
                errors[path] = f"Field '{path}' is required"
            return

        # Determine actual type
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
            errors[path] = f"Expected type '{expected_type}', but received '{actual_type}'"
            return

        # Constraints Validation
        if expected_type == 'string':
            min_len = rule.get('min')
            if min_len is not None and len(value) < min_len:
                errors[path] = f"String length must be at least {min_len} characters"
                
            max_len = rule.get('max')
            if max_len is not None and len(value) > max_len:
                errors[path] = f"String length must not exceed {max_len} characters"
                
            if rule.get('format') == 'email' and not EMAIL_REGEX.match(value):
                errors[path] = "Invalid email format"
                
        elif expected_type == 'number':
            min_val = rule.get('min')
            if min_val is not None and value < min_val:
                errors[path] = f"Value must be greater than or equal to {min_val}"
                
            max_val = rule.get('max')
            if max_val is not None and value > max_val:
                errors[path] = f"Value must be less than or equal to {max_val}"
                
        elif expected_type == 'array':
            min_len = rule.get('min')
            if min_len is not None and len(value) < min_len:
                errors[path] = f"Array must contain at least {min_len} items"
                
            max_len = rule.get('max')
            if max_len is not None and len(value) > max_len:
                errors[path] = f"Array must not contain more than {max_len} items"
                
            element_schema = rule.get('elementSchema')
            if element_schema:
                for i, item in enumerate(value):
                    traverse(item, element_schema, f"{path}[{i}]")
                    
        elif expected_type == 'object':
            child_schema = rule.get('schema')
            if child_schema:
                for child_key, child_rule in child_schema.items():
                    traverse(value.get(child_key), child_rule, f"{path}.{child_key}")

    # Root traversal
    for key, rule in schema.items():
        traverse(payload.get(key), rule, key)

    if len(errors) > 0:
        return False, errors
    return True, None
