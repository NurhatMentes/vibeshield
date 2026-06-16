"""
VibeShield JWT Security — Usage Example

This file demonstrates how to integrate VibeShield's JWT secret
validator into your application's startup routine.

Run with: python examples/jwt_usage.py
"""

import os
import sys

# Allow importing from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.jwt_validator import validate_jwt_secret
from src.jwt_security import enforce_jwt_security


print("=============================================================")
print("🔐 VIBESHIELD JWT SECRET VALIDATION DEMO")
print("=============================================================\n")

# ── Example 1: Weak AI-generated secret ─────────────────────────────
print("--- CASE 1: AI-Generated Weak Secret ---")
weak = validate_jwt_secret("mysecret")
print('Input:  "mysecret"')
print(f"Valid: {weak['valid']}")
print(f"Errors: {weak['errors']}")
print()

# ── Example 2: Too-short secret ─────────────────────────────────────
print("--- CASE 2: Short Secret ---")
short = validate_jwt_secret("Ab3$z")
print('Input:  "Ab3$z" (5 chars)')
print(f"Valid: {short['valid']}")
print(f"Errors: {short['errors']}")
print()

# ── Example 3: All-digit secret ─────────────────────────────────────
print("--- CASE 3: All-Digit Secret ---")
digits = validate_jwt_secret("98765432101234")
print('Input:  "98765432101234"')
print(f"Valid: {digits['valid']}")
print(f"Errors: {digits['errors']}")
print()

# ── Example 4: Repeating pattern ────────────────────────────────────
print("--- CASE 4: Repeating Pattern ---")
repeating = validate_jwt_secret("abcabcabcabc")
print('Input:  "abcabcabcabc"')
print(f"Valid: {repeating['valid']}")
print(f"Errors: {repeating['errors']}")
print()

# ── Example 5: Valid strong secret ──────────────────────────────────
print("--- CASE 5: Strong Secret (PASS) ---")
strong = validate_jwt_secret("aB3$xYz!qW8#mL2@pQ7&nK4*jR9^tF1%")
print('Input:  "aB3$xYz!qW8#mL2@pQ7&nK4*jR9^tF1%"')
print(f"Valid: {strong['valid']}")
print(f"Errors: {strong['errors']}")
print(f"Warnings: {strong['warnings']}")
print()

# ── Example 6: Full middleware enforcement ──────────────────────────
print("--- CASE 6: Middleware Enforcement ---")
secret = os.environ.get("JWT_SECRET", "changeme")
result = enforce_jwt_security(secret)
print(f"Allowed: {result['allowed']}")
print(f"Tracking ID: {result['tracking_id']}")
print()

print("=============================================================")
print("💡 TIP: Set a strong secret via env var:")
print("   export JWT_SECRET=$(openssl rand -base64 48)")
print("=============================================================")
