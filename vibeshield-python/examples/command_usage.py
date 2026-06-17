"""
VibeShield Command Injection Protection and safe-exec — Usage Example

Demonstrates how to sanitize command arguments, validate commands, and execute commands safely.

Run with: python examples/command_usage.py
"""

import os
import sys
import platform

# Allow importing from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src import (
    sanitize_shell_input,
    validate_safe_command,
    safe_exec,
    VibeShieldCommandInjectionError
)

print("=============================================================")
print("[SECURE] VIBESHIELD COMMAND INJECTION PROTECTION DEMO")
print("=============================================================\n")

# 1. Sanitizing inputs
print("--- 1. Using sanitize_shell_input() ---")
test_inputs = [
    "safe-arg123",
    "user@domain.com",
    "malicious_arg; rm -rf /",
    "some_arg\x00_inject",
    "another_arg|ls",
    "backtick`inject`",
]

for inp in test_inputs:
    try:
        sanitized = sanitize_shell_input(inp)
        print(f"[SAFE] Input: '{inp}' -> Sanitized: '{sanitized}'")
    except VibeShieldCommandInjectionError as e:
        print(f"[BLOCKED] Input: '{inp}' -> Error: {e}")
print()

# 2. Validating commands
print("--- 2. Using validate_safe_command() ---")
test_commands = [
    ("ping", ["127.0.0.1"]),
    ("bash", ["-c", "ls"]),
    ("../ping", ["127.0.0.1"]),
    ("ping", ["../etc/passwd"]),
    ("ping", ["C:\\some\\path"]),
]

for cmd, args in test_commands:
    try:
        validate_safe_command(cmd, args)
        print(f"[SAFE] Command: {cmd} with args {args}")
    except VibeShieldCommandInjectionError as e:
        print(f"[BLOCKED] Command: {cmd} with args {args} -> Error: {e}")
print()

# 3. Executing commands safely
print("--- 3. Using safe_exec() ---")
try:
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    print("Running a safe ping...")
    result = safe_exec("ping", [count_flag, "1", "127.0.0.1"])
    print(f"Success! Exit Code: {result['code']}")
    # print first 5 lines of stdout
    lines = result['stdout'].splitlines()[:5]
    print("Output preview:")
    for line in lines:
        print(f"  {line}")
except Exception as e:
    print(f"Execution failed: {e}")

print("\nAttempting to execute an unauthorized command...")
try:
    safe_exec("rm", ["-rf", "tmp"])
except VibeShieldCommandInjectionError as e:
    print(f"[BLOCKED] Correctly intercepted: {e}")
