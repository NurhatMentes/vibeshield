"""
VibeShield Deserialization Protection — Usage Example

Demonstrates how to safely parse JSON payloads, enforce depth checks,
sanitize dangerous keys, and statically analyze code for unsafe deserialization.

Run with: python examples/deserialization_usage.py
"""

import os
import sys

# Allow importing from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src import (
    safe_json_parse,
    detect_unsafe_deserialization,
    enforce_safe_json,
    VibeShieldDeserializationError
)

print("=============================================================")
print("[SECURE] VIBESHIELD DESERIALIZATION PROTECTION DEMO")
print("=============================================================\n")

# 1. Safe JSON parsing with depth validation and sanitisation
print("--- 1. Using safe_json_parse() ---")
payloads = [
    ('{"a": 1, "b": 2}', 5),
    ('{"a": {"b": {"c": {"d": 4}}}}', 3), # Exceeds depth 3
    ('{"__proto__": {"polluted": true}, "safe_key": "hello"}', 5), # Prototype pollution
    ('{"nested": {"constructor": "danger", "prototype": "danger"}}', 5), # Other keyword sanitisation
    ('{"malformed":', 5) # Malformed JSON
]

for payload, depth in payloads:
    print(f"Parsing: {payload} (Max Depth: {depth})")
    try:
        parsed = safe_json_parse(payload, max_depth=depth)
        print(f"  [SUCCESS] Result: {parsed}")
    except VibeShieldDeserializationError as e:
        print(f"  [BLOCKED] Error: {e}")
print()

# 2. Middleware safe parser
print("--- 2. Using enforce_safe_json() Middleware ---")
body_texts = [
    "",
    "   ",
    '{"username": "vibe_user"}',
    '{"nested": {"nested": {"nested": 1}}}'
]

for body in body_texts:
    print(f"Enforcing safe body: {repr(body)}")
    try:
        parsed = enforce_safe_json(body, max_depth=2)
        print(f"  [SUCCESS] Result: {parsed}")
    except VibeShieldDeserializationError as e:
        print(f"  [BLOCKED] Error: {e}")
print()

# 3. Static Analysis Detector
print("--- 3. Using detect_unsafe_deserialization() Detector ---")
sample_codes = [
    # Safe code
    """
import json
import yaml

def parse(data):
    obj = json.loads(data)
    cfg = yaml.safe_load(data)
    return obj, cfg
""",
    # Unsafe code
    """
import pickle
import yaml
import marshal
import shelve
import dill
import jsonpickle

def do_unsafe(data):
    # Unsafe pickle
    p = pickle.loads(data)
    # Unsafe yaml
    y = yaml.load(data)
    # Unsafe marshal
    m = marshal.loads(data)
    # Unsafe shelve
    s = shelve.open("db.db")
    # Unsafe dill
    d = dill.loads(data)
    # Unsafe jsonpickle
    jp = jsonpickle.decode(data)
""",
    # Safe YAML Loader usage
    """
import yaml
def load_yaml(data):
    return yaml.load(data, Loader=yaml.SafeLoader)
"""
]

for i, code in enumerate(sample_codes, 1):
    print(f"Analyzing Code Block {i}:")
    res = detect_unsafe_deserialization(code)
    if res["safe"]:
        print("  [SAFE] No unsafe deserialization patterns detected.")
    else:
        print(f"  [UNSAFE] Detected {len(res['findings'])} findings:")
        for finding in res["findings"]:
            print(f"    - Line {finding['line']}: pattern '{finding['pattern']}' ({finding['severity']})")
            print(f"      Code: {finding['original_code']}")
            print(f"      Suggestion: {finding['suggestion']}")
print()
