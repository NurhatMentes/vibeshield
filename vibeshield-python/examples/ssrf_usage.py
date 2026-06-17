"""
VibeShield SSRF URL Validator — Usage Example

Demonstrates how to validate URLs against Server-Side Request Forgery (SSRF)
vulnerabilities and use the exception middleware.

Run with: python examples/ssrf_usage.py
"""

import os
import sys

# Allow importing from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src import validate_url, enforce_safe_url, VibeShieldSSRFError

print("=============================================================")
print("[SECURE] VIBESHIELD SSRF URL VALIDATION DEMO")
print("=============================================================\n")

# A set of URLs to analyze
test_urls = [
    # Safe URLs
    "https://example.com",
    "http://api.github.com/users/octocat",
    
    # Forbidden protocol
    "file:///etc/passwd",
    "gopher://localhost:70/11",
    
    # Loopback IP and literals
    "http://localhost/admin",
    "http://127.0.0.1:8080/dashboard",
    "http://[::1]",
    
    # Private Subnets
    "http://192.168.1.1/setup",
    "http://10.0.0.1/metadata",
    
    # Bypasses / Obfuscated IPs
    "http://2130706433/",        # Decimal equivalent of 127.0.0.1
    "http://0x7f.0.0.1/",        # Hex representation
    "http://0177.0.0.1/",        # Octal representation
    "http://127.1/",             # Shortened representation (fewer parts)
    
    # Carrier-grade NAT
    "http://100.64.0.1/",
    
    # IDN Homograph attack (Latin mixed with Cyrillic/Greek)
    "http://googl\u0435.com",     # Cyrillic 'е'
]

def safe_print(label: str, text: str):
    # Encode with backslashreplace for safe printing in terminal environments
    safe_text = text.encode("ascii", errors="backslashreplace").decode("ascii")
    print(f"{label:<10} {safe_text}")

print("--- 1. Using validate_url() ---")
for url in test_urls:
    result = validate_url(url)
    if result["safe"]:
        safe_print("[SAFE]", url)
    else:
        safe_print("[BLOCKED]", url)
        safe_print("  Reason:", result.get("reason", ""))
    print()

print("\n--- 2. Using enforce_safe_url() Middleware ---")
for url in test_urls:
    try:
        enforce_safe_url(url)
        safe_print("[SAFE]", url)
    except VibeShieldSSRFError as e:
        safe_print("[BLOCKED]", f"Caught Exception: {e}")
    print()
