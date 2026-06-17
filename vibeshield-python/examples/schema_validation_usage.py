import os
import sys
import json

# Allow importing from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src import validate_schema

# Define a comprehensive validation schema
user_schema = {
    "username": {
        "type": "string",
        "required": True,
        "min": 3,
        "max": 20,
        "trim": True
    },
    "email": {
        "type": "string",
        "required": True,
        "format": "email"
    },
    "age": {
        "type": "number",
        "required": False,
        "min": 18,
        "allowNull": True
    },
    "role": {
        "type": "string",
        "required": True,
        "enum": ["admin", "user", "moderator"]
    },
    "ip_address": {
        "type": "string",
        "required": False,
        "format": "ipv4"
    },
    "profile": {
        "type": "object",
        "required": False,
        "schema": {
            "bio": {"type": "string", "max": 160},
            "website": {"type": "string", "format": "url"}
        }
    },
    "preferences": {
        "type": "array",
        "required": False,
        "elementSchema": {
            "type": "string",
            "enum": ["notifications", "dark_mode", "newsletter"]
        }
    }
}

def run_demo():
    print("=" * 60)
    print(" VIBESHIELD STRICT SCHEMA VALIDATOR DEMO ")
    print("=" * 60)
    
    # 1. Valid Data Case
    print("\n--- CASE 1: Valid Data (With Trimming and Nested Objects/Arrays) ---")
    valid_data = {
        "username": "   JohnDoe   ",  # Will be trimmed to "JohnDoe"
        "email": "johndoe@example.com",
        "age": 25,
        "role": "user",
        "ip_address": "192.168.1.1",
        "profile": {
            "bio": "Software Developer & Security Enthusiast",
            "website": "https://johndoe.dev"
        },
        "preferences": ["dark_mode", "notifications"]
    }
    
    result = validate_schema(valid_data, user_schema)
    print(f"Validation Valid: {result['valid']}")
    print(f"Errors Found: {len(result['errors'])}")
    if result['valid']:
        print("Sanitized Data:")
        print(json.dumps(result['sanitized_data'], indent=2))
    
    # 2. Invalid Data Case
    print("\n--- CASE 2: Invalid Data (Violating Type, Whitelist, Formats, and Enums) ---")
    invalid_data = {
        "username": "Jo",                        # Too short (min is 3)
        "email": "invalid-email",                # Invalid email format
        "age": 16,                               # Too young (min is 18)
        "role": "superadmin",                    # Not in enum
        "ip_address": "256.0.0.1",                # Invalid IPv4 format
        "profile": {
            "bio": "An enthusiastic user",
            "website": "http://invalid-url-site", # Valid url but let's test a bad URL format
            "extra_field": "not allowed"         # Whitelist violation (unknown nested field)
        },
        "preferences": [
            "dark_mode",
            "super_secret_option"               # Not in elementSchema enum list
        ],
        "unknown_root_field": "hack"             # Whitelist violation (unknown root field)
    }
    
    # Let's adjust website to trigger format error (url match is regex ^https?://[^\s/$.?#].[^\s]*$)
    invalid_data["profile"]["website"] = "invalid_uri"
    
    result_invalid = validate_schema(invalid_data, user_schema)
    print(f"Validation Valid: {result_invalid['valid']}")
    print("Errors Found:")
    for error in result_invalid['errors']:
        print(f" - Field: '{error['field']}' -> {error['message']} (value: {repr(error.get('value'))})")

if __name__ == "__main__":
    run_demo()
