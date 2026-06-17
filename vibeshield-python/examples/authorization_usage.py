"""
VibeShield Authorization & Access Control Protector — Usage Example

Demonstrates role verification, ownership checks, and static code scanning.

Run with: python examples/authorization_usage.py
"""

import os
import sys
import asyncio

# Allow importing from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src import (
    check_permission,
    validate_resource_ownership,
    detect_missing_auth_middleware,
    VibeShieldAuthorizationError,
    require_role,
    require_permission,
    require_ownership,
    require_auth,
)

print("=============================================================")
print("[SECURE] VIBESHIELD AUTHORIZATION PROTECTOR DEMO")
print("=============================================================\n")

# --- 1. Basic Permission and Ownership Checks ---
print("--- 1. Using check_permission() and validate_resource_ownership() ---")

users = {
    "admin_user": {"role": "admin", "id": 1},
    "regular_user": {"role": "user", "id": 100, "permissions": ["users:read"]},
    "guest_user": {"role": "guest", "id": 999}
}

# Check permissions
print("Permission Matrix Checks:")
for name, user in users.items():
    can_write_post = check_permission(user, "posts", "write")
    can_delete_user = check_permission(user, "users", "delete")
    print(f"  [{name}] Role: {user['role']}")
    print(f"    - Can write post? {can_write_post}")
    print(f"    - Can delete user? {can_delete_user}")

# Check ownership (IDOR protection)
print("\nOwnership Checks:")
resource_owner_id = 100  # owned by regular_user
for name, user in users.items():
    is_owner = validate_resource_ownership(
        user_id=user["id"],
        resource_id=5000,
        resource_owner_id=resource_owner_id,
        user_role=user["role"]
    )
    print(f"  [{name}] user_id: {user['id']} (role: {user['role']}) owns resource owned by 100? {is_owner}")


# --- 2. Middleware / Decorators Demonstration ---
print("\n--- 2. Route Protection Decorators ---")

# Define protected endpoints
@require_role("admin")
def delete_system_logs(user):
    return "SUCCESS: System logs deleted."

@require_permission("posts", "write")
def create_blog_post(user):
    return "SUCCESS: Blog post created."

@require_ownership("post_id")
def edit_blog_post(post_id: int, user: dict, owner_id: int):
    return f"SUCCESS: Post {post_id} edited."

@require_auth(roles=["user"], permissions=["posts:write"])
def publish_post(user):
    return "SUCCESS: Post published."

# Invoking sync decorators
print("\nExecuting sync decorated functions:")

# Test role decorator
try:
    print("  Calling delete_system_logs as regular_user...")
    delete_system_logs(user=users["regular_user"])
except VibeShieldAuthorizationError as e:
    print(f"  [BLOCKED] {e}")

try:
    print("  Calling delete_system_logs as admin_user...")
    res = delete_system_logs(user=users["admin_user"])
    print(f"  [ALLOWED] {res}")
except VibeShieldAuthorizationError as e:
    print(f"  [BLOCKED] {e}")

# Test permission decorator
try:
    print("  Calling create_blog_post as guest_user...")
    create_blog_post(user=users["guest_user"])
except VibeShieldAuthorizationError as e:
    print(f"  [BLOCKED] {e}")

try:
    print("  Calling create_blog_post as regular_user...")
    res = create_blog_post(user=users["regular_user"])
    print(f"  [ALLOWED] {res}")
except VibeShieldAuthorizationError as e:
    print(f"  [BLOCKED] {e}")

# Test ownership decorator
try:
    print("  Editing post owned by 100 as guest_user (id 999)...")
    edit_blog_post(post_id=456, user=users["guest_user"], owner_id=100)
except VibeShieldAuthorizationError as e:
    print(f"  [BLOCKED] {e}")

try:
    print("  Editing post owned by 100 as regular_user (id 100)...")
    res = edit_blog_post(post_id=456, user=users["regular_user"], owner_id=100)
    print(f"  [ALLOWED] {res}")
except VibeShieldAuthorizationError as e:
    print(f"  [BLOCKED] {e}")

# Test combined decorator
try:
    print("  Publishing post as regular_user...")
    res = publish_post(user={"role": "user", "permissions": ["posts:write"]})
    print(f"  [ALLOWED] {res}")
except VibeShieldAuthorizationError as e:
    print(f"  [BLOCKED] {e}")


# --- 3. Static Scanner Demonstration ---
print("\n--- 3. Static Authorization Scanner ---")

unsafe_code = """
@app.route("/admin/delete-database")
def delete_db():
    # Dangerous admin endpoint without auth guard!
    db.drop_all()

@app.get("/api/users/{user_id}")
def get_user_profile(user_id: int):
    # IDOR Vulnerable! Missing ownership check
    return db.query_user(user_id)
"""

safe_code = """
@require_role("admin")
@app.route("/admin/delete-database")
def delete_db():
    db.drop_all()

@require_ownership("user_id")
@app.get("/api/users/{user_id}")
def get_user_profile(user_id: int):
    return db.query_user(user_id)
"""

print("Scanning Unsafe Code Block:")
scan_result = detect_missing_auth_middleware(unsafe_code)
print(f"  Safe: {scan_result['safe']}")
for finding in scan_result["findings"]:
    print(f"  - [{finding['severity'].upper()}] Line {finding['line']}: {finding['pattern']}")
    print(f"    Code: {finding['original_code']}")
    print(f"    Suggestion: {finding['suggestion']}")

print("\nScanning Safe Code Block:")
scan_result_safe = detect_missing_auth_middleware(safe_code)
print(f"  Safe: {scan_result_safe['safe']}")
print(f"  Findings Count: {len(scan_result_safe['findings'])}")
