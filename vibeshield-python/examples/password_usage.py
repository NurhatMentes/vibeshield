"""
VibeShield Weak Password Policy Protector — Usage Example

Demonstrates how to validate passwords, calculate Shannon entropy,
generate reports, and use the middleware decorator.

Run with: python examples/password_usage.py
"""

import os
import sys

# Reconfigure stdout to support UTF-8 characters (like emojis) on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Allow importing from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src import (
    validate_password,
    calculate_shannon_entropy,
    generate_password_policy_report,
    validate_password_policy,
)

print("=============================================================")
print("[SECURE] VIBESHIELD WEAK PASSWORD POLICY PROTECTOR DEMO")
print("=============================================================\n")

# 1. Shannon Entropy Calculations
print("--- 1. Shannon Entropy ---")
passwords_to_measure = [
    "",
    "aaaaa",
    "abcdef",
    "password123",
    "Tr0ub4dor&3Secure!",
]

for pwd in passwords_to_measure:
    entropy = calculate_shannon_entropy(pwd)
    print(f"Password: {pwd:<25} Entropy: {entropy:.4f} bits")
print()

# 2. Validation & Assessment Reports
print("--- 2. Validation & Assessment Reports ---")
user_context = {
    "username": "john_doe",
    "firstName": "John",
    "lastName": "Doe",
    "email": "john.doe@company.com",
    "birthDate": "1990-12-31"
}

passwords_to_assess = [
    "123456",                   # Too short, common, no complexity
    "john_doe_pass123",         # Context leak (username)
    "Abc12345!!!",              # Too short (minimum 12)
    "abcdefghijklmnop",         # No complexity (only lowercase)
    "aaabbbccc123!!!",          # Repetitive characters
    "abcdef123xyz!!!",          # Sequential characters
    "Tr0ub4dor&3Secure!",       # Valid, strong
]

for pwd in passwords_to_assess:
    report = generate_password_policy_report(pwd, context=user_context)
    print(report)
    print()

# 3. Middleware Decorator Demonstrations
print("--- 3. Middleware Decorator Demonstrations ---")

# Mock request class mimicking FastAPI request
class MockRequest:
    def __init__(self, body):
        self.scope = {"receive": True}
        self.receive = lambda: None
        self._json = body

# Apply decorator to a mock FastAPI endpoint
@validate_password_policy(min_length=12)
def handle_signup_endpoint(request):
    return {"status": "success", "message": "User registered successfully"}

print("FastAPI Sync Endpoint - Valid Request:")
valid_req = MockRequest({"password": "Tr0ub4dor&3Secure!"})
response = handle_signup_endpoint(valid_req)
print("Response:", response)
print()

print("FastAPI Sync Endpoint - Invalid Request:")
invalid_req = MockRequest({"password": "short"})
response = handle_signup_endpoint(invalid_req)
print("Response Status Code:", response.status_code)
import json
print("Response Content:", json.loads(response.body.decode('utf-8')))
print()
