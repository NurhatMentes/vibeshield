import re
from typing import Any, Dict, List, Optional, Union

class VibeShieldAuthorizationError(ValueError):
    """Exception raised when an authorization verification check fails."""
    def __init__(self, message: str):
        super().__init__(f"[VibeShield] Authorization Protection: {message}")
        self.message = message

PERMISSION_MATRIX = {
    "admin": {
        "users": ["read", "write", "delete", "admin"],
        "posts": ["read", "write", "delete", "admin"],
        "settings": ["read", "write", "admin"]
    },
    "user": {
        "users": ["read"],
        "posts": ["read", "write"],
        "settings": ["read"]
    },
    "guest": {
        "users": [],
        "posts": ["read"],
        "settings": []
    }
}

def check_permission(user: Dict[str, Any], resource: str, action: str) -> bool:
    role = user.get("role")
    if role == "admin":
        return True

    user_permissions = user.get("permissions", [])
    direct_perm = f"{resource}:{action}"
    direct_wildcard = f"{resource}:*"
    if direct_perm in user_permissions or direct_wildcard in user_permissions or "*:*" in user_permissions:
        return True

    role_matrix = PERMISSION_MATRIX.get(role)
    if role_matrix and resource in role_matrix:
        allowed_actions = role_matrix[resource]
        if action in allowed_actions:
            return True

    return False

def validate_resource_ownership(
    user_id: Union[str, int],
    resource_id: Union[str, int],
    resource_owner_id: Union[str, int],
    user_role: Optional[str] = None
) -> bool:
    if user_role == "admin":
        return True
    return str(user_id) == str(resource_owner_id)

def detect_missing_auth_middleware(code: str) -> Dict[str, Any]:
    findings = []
    if not code:
        return {"safe": True, "findings": findings}

    lines = code.split("\n")

    for i, line in enumerate(lines):
        line_num = i + 1

        # Rule 1: Admin route missing auth check
        is_admin_route = bool(re.search(r"\.(get|post|put|delete|use|route)\s*\(\s*['\"]/admin", line, re.IGNORECASE)) or \
                         bool(re.search(r"@app\.(route|get|post|put|delete)\s*\(\s*['\"]/admin", line, re.IGNORECASE))
        if is_admin_route:
            has_auth = bool(re.search(r"requireAuth|requireRole|require_auth|require_role|Depends", line, re.IGNORECASE)) or \
                       (i > 0 and bool(re.search(r"requireAuth|requireRole|require_auth|require_role", lines[i - 1], re.IGNORECASE)))
            if not has_auth:
                findings.append({
                    "line": line_num,
                    "pattern": "Missing Auth in Admin Route",
                    "severity": "critical",
                    "suggestion": "Ensure an authorization middleware or role guard (e.g. require_role(['admin'])) is applied to admin endpoints.",
                    "original_code": line.strip()
                })

        # Rule 2: User/IDOR sensitive endpoints missing ownership check
        is_sensitive_user_route = bool(re.search(r"/api/users/(:\w+|<\w+>|\{\w+\})", line, re.IGNORECASE)) or \
                                  bool(re.search(r"/posts/(:\w+|<\w+>|\{\w+\})", line, re.IGNORECASE))
        if is_sensitive_user_route:
            has_ownership = bool(re.search(r"requireOwnership|require_ownership", line, re.IGNORECASE)) or \
                            (i > 0 and bool(re.search(r"requireOwnership|require_ownership", lines[i - 1], re.IGNORECASE)))
            if not has_ownership:
                findings.append({
                    "line": line_num,
                    "pattern": "Missing Ownership Check",
                    "severity": "warning",
                    "suggestion": "Ensure resource ownership validation (e.g. require_ownership) is applied to prevent IDOR vulnerabilities.",
                    "original_code": line.strip()
                })

        # Rule 3: Flask/FastAPI route handler missing auth checks
        is_route_handler = bool(re.search(r"@app\.(route|get|post|put|delete)", line, re.IGNORECASE))
        if is_route_handler:
            file_has_auth = bool(re.search(r"requireAuth|requireRole|requirePermission|requireOwnership|require_auth|require_role|require_permission|require_ownership|check_permission|validate_resource_ownership", code))
            if not file_has_auth:
                findings.append({
                    "line": line_num,
                    "pattern": "Route Handler Missing Auth",
                    "severity": "high",
                    "suggestion": "Route handlers should enforce authentication/authorization checks.",
                    "original_code": line.strip()
                })

    findings.sort(key=lambda x: x["line"])
    return {
        "safe": len(findings) == 0,
        "findings": findings
    }
