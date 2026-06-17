import json
import logging
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("VibeShield")

class VibeShieldDeserializationError(ValueError):
    """Exception raised when a deserialization security issue is detected."""
    def __init__(self, message: str):
        super().__init__(f"[VibeShield] Deserialization Protection: {message}")
        self.message = message

def _check_json_depth(text: str, max_depth: int) -> None:
    """
    Iteratively checks the nesting depth of a JSON string without parsing it completely.

    Args:
        text: The raw JSON string.
        max_depth: The maximum nesting depth allowed.

    Raises:
        VibeShieldDeserializationError: If the maximum depth is exceeded.
    """
    depth = 0
    max_reached = 0
    in_string = False
    escape = False
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_string:
            if escape:
                escape = False
            elif c == '\\':
                escape = True
            elif c == '"':
                in_string = False
        else:
            if c == '"':
                in_string = True
            elif c in ('{', '['):
                depth += 1
                if depth > max_reached:
                    max_reached = depth
                if max_reached > max_depth:
                    raise VibeShieldDeserializationError(f"Maximum JSON depth of {max_depth} exceeded.")
            elif c in ('}', ']'):
                depth -= 1
        i += 1

def safe_json_parse(text: str, max_depth: int = 64) -> Any:
    """
    Safely parses JSON string with depth validation and key sanitisation.

    Args:
        text: The JSON string to parse.
        max_depth: The maximum nesting depth allowed.

    Returns:
        The deserialized and sanitized JSON payload.

    Raises:
        VibeShieldDeserializationError: If depth limit is exceeded or parsing fails.
    """
    _check_json_depth(text, max_depth)
    try:
        parsed = json.loads(text)
        
        # Parity guard: clean up key words
        def clean_object(obj: Any) -> Any:
            if obj is None or not isinstance(obj, (dict, list)):
                return obj
            if isinstance(obj, list):
                return [clean_object(item) for item in obj]
            
            clean = {}
            for k, v in obj.items():
                if str(k) in ('__proto__', 'constructor', 'prototype'):
                    continue
                clean[k] = clean_object(v)
            return clean

        return clean_object(parsed)
    except Exception as e:
        if isinstance(e, VibeShieldDeserializationError):
            raise e
        raise VibeShieldDeserializationError(f"Malformed JSON payload: {str(e)}")

def detect_unsafe_deserialization(code: str) -> Dict[str, Any]:
    """
    Statically analyzes source code to detect dangerous deserialization patterns.

    Args:
        code: The Python source code string to analyze.

    Returns:
        A dict containing:
            - safe: A boolean indicating if no unsafe patterns were found.
            - findings: A list of dicts detailing each unsafe finding.
    """
    findings = []
    if not code:
        return {"safe": True, "findings": findings}

    lines = code.split('\n')
    def get_line_num(index: int) -> int:
        return len(code[:index].split('\n'))

    # Rules mapping regex to description
    unsafe_libs = [
        (r'\bpickle\.(loads|load)\b', 'pickle', 'critical', 'Avoid using pickle.load/loads as it allows remote code execution.'),
        (r'\bmarshal\.(loads|load)\b', 'marshal', 'critical', 'Avoid using marshal.load/loads for untrusted payloads.'),
        (r'\bshelve\.open\b', 'shelve', 'critical', 'Avoid using shelve for untrusted persistent storage.'),
        (r'\bdill\.(loads|load)\b', 'dill', 'critical', 'dill deserialization allows remote code execution.'),
        (r'\bjsonpickle\.decode\b', 'jsonpickle', 'critical', 'jsonpickle.decode is vulnerable to arbitrary code execution.'),
    ]

    for regex, name, severity, sug in unsafe_libs:
        pattern = re.compile(regex)
        for match in pattern.finditer(code):
            line_num = get_line_num(match.start())
            findings.append({
                "line": line_num,
                "pattern": name,
                "severity": severity,
                "suggestion": sug,
                "original_code": lines[line_num - 1].strip()
            })

    # Rule: yaml.load without SafeLoader
    yaml_pattern = re.compile(r'\byaml\.load\s*\(')
    for match in yaml_pattern.finditer(code):
        line_num = get_line_num(match.start())
        # check if SafeLoader is passed
        # Safe loaders in PyYAML: SafeLoader or safe_load
        # If Loader=yaml.Loader or Loader=Loader is passed, it is unsafe.
        # We check the rest of the line or surrounding context
        context = lines[line_num - 1]
        is_safe = 'SafeLoader' in context or 'safe_load' in context
        if not is_safe:
            findings.append({
                "line": line_num,
                "pattern": "yaml.load without SafeLoader",
                "severity": "critical",
                "suggestion": "Use yaml.safe_load() or specify Loader=yaml.SafeLoader to prevent RCE.",
                "original_code": context.strip()
            })

    findings.sort(key=lambda x: x['line'])
    return {"safe": len(findings) == 0, "findings": findings}
