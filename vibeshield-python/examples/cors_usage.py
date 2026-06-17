"""
VibeShield CORS Security — Usage Example

Demonstrates how to validate CORS configurations before applying them.

Run with: python examples/cors_usage.py
"""

import os
import sys

# Allow importing from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.cors_validator import validate_cors_config
from src.cors_security import enforce_cors_policy


print("=============================================================")
print("🔒 VIBESHIELD CORS SECURITY VALIDATION DEMO")
print("=============================================================\n")

# === CASE 1: Wildcard origin (insecure) ===
print("--- CASE 1: Wildcard Origin ---")
wildcard_result = validate_cors_config({
    "allowed_origins": ["*"],
    "allow_credentials": True,
})
print(f"Valid: {wildcard_result['valid']}")
print(f"Errors: {wildcard_result['errors']}")
print()

# === CASE 2: Sensitive headers exposed ===
print("--- CASE 2: Sensitive Headers Exposed ---")
headers_result = validate_cors_config({
    "allowed_origins": ["https://example.com"],
    "exposed_headers": ["Authorization", "Set-Cookie"],
})
print(f"Valid: {headers_result['valid']}")
print(f"Errors: {headers_result['errors']}")
print()

# === CASE 3: Dangerous methods ===
print("--- CASE 3: Dangerous Methods ---")
methods_result = validate_cors_config({
    "allowed_origins": ["https://example.com"],
    "allowed_methods": ["GET", "POST", "TRACE"],
})
print(f"Valid: {methods_result['valid']}")
print(f"Errors: {methods_result['errors']}")
print()

# === CASE 4: Secure production config ===
print("--- CASE 4: Secure Production Config ---")
secure_result = validate_cors_config({
    "allowed_origins": ["https://myapp.com", "https://admin.myapp.com"],
    "allowed_methods": ["GET", "POST", "PUT"],
    "allowed_headers": ["Content-Type", "Authorization"],
    "exposed_headers": ["X-Request-Id"],
    "allow_credentials": True,
    "max_age": 3600,
})
print(f"Valid: {secure_result['valid']}")
print(f"Warnings: {secure_result['warnings']}")
print()

# === CASE 5: Middleware Enforcement ===
print("--- CASE 5: Middleware Enforcement ---")
enforcement = enforce_cors_policy({
    "allowed_origins": ["*"],
    "allow_credentials": True,
})
print(f"Allowed: {enforcement['allowed']}")
print(f"Tracking ID: {enforcement['tracking_id']}")
print()

# === CASE 6: Secure enforcement ===
print("--- CASE 6: Secure Enforcement ---")
secure_enforcement = enforce_cors_policy({
    "allowed_origins": ["https://myapp.com"],
    "allowed_methods": ["GET", "POST"],
    "allow_credentials": True,
    "max_age": 3600,
})
print(f"Allowed: {secure_enforcement['allowed']}")
print(f"Tracking ID: {secure_enforcement['tracking_id']}")

print("\n=============================================================")
print("💡 TIP: Always validate CORS configs at startup and use")
print("   environment variables for allowed origins.")
print("=============================================================")
