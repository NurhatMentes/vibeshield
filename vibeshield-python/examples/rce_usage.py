"""
VibeShield RCE Pattern Detector — Usage Example

Demonstrates how to detect Remote Code Execution (RCE) vulnerabilities,
sandbox escapes, and dangerous system command calls in Python source code.

Run with: python examples/rce_usage.py
"""

import os
import sys

# Allow importing from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.rce_detector import detect_rce_patterns

print("=============================================================")
print("[SECURE] VIBESHIELD RCE SECURITY VALIDATION DEMO")
print("=============================================================\n")

# A set of code payloads to analyze
payloads = {
    "Safe Function": """
def get_user_profile(user_id):
    # Simple dictionary lookup is perfectly safe
    return db.query("SELECT * FROM profiles WHERE id = ?", user_id)
""",
    "Critical: eval() with Dynamic Input": """
def run_calculator(expr):
    # CRITICAL: executing dynamic untrusted mathematical expressions
    return eval("2 + " + expr)
""",
    "High: eval() with Static Literal": """
def test_static():
    # HIGH: eval used with static string
    return eval("1 + 1")
""",
    "Critical: Subprocess shell=True with Dynamic Input": """
def ping_host(host):
    # CRITICAL: shell=True with concatenated variable
    subprocess.run("ping -c 1 " + host, shell=True)
""",
    "High: Subprocess shell=True with Static Input": """
def list_files():
    # HIGH: shell=True with static string
    subprocess.run("ls -la", shell=True)
""",
    "Warning: Subprocess with Dynamic Input (No Shell)": """
def run_command(arg):
    # WARNING: passing dynamic argument list
    subprocess.run(["ls", arg])
""",
    "High: Dynamic getattr() on Variables": """
def invoke_method(obj, method_name):
    # HIGH: dynamic getattr lookup on variable
    func = getattr(obj, method_name)
    return func()
""",
    "Warning: Sandbox Escape (globals/locals)": """
def inspect_context():
    # WARNING: exposing global symbol table
    return globals()
"""
}

for title, code in payloads.items():
    print(f"--- Scenario: {title} ---")
    result = detect_rce_patterns(code)
    print(f"Safe: {result['safe']}")
    if result["findings"]:
        print(f"Findings ({len(result['findings'])}):")
        for finding in result["findings"]:
            print(f"  Line {finding['line']}: [{finding['severity'].upper()}] - {finding['pattern']}")
            print(f"    Original code (masked): {finding['original_code']}")
            print(f"    Suggestion: {finding['suggestion']}")
    else:
        print("  No issues found.")
    print()
