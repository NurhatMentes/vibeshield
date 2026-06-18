import asyncio
import pytest
from unittest.mock import MagicMock, patch
from typing import Any, Dict

from src.authorization_protector import (
    VibeShieldAuthorizationError,
    PERMISSION_MATRIX,
    check_permission,
    validate_resource_ownership,
    detect_missing_auth_middleware,
)
from src.middleware.authorization import (
    require_role,
    require_permission,
    require_ownership,
    require_auth,
)

# Helper Mocks for FastAPI/Starlette-like request
class MockRequest:
    def __init__(self, user=None, path_params=None):
        self.scope = {"receive": True}
        self.state = MockState(user)
        self.path_params = path_params or {}

class MockState:
    def __init__(self, user):
        self.user = user

# --- Exception Tests ---

def test_authorization_error_message():
    err = VibeShieldAuthorizationError("Access Denied")
    assert err.message == "Access Denied"
    assert str(err) == "[VibeShield] Authorization Protection: Access Denied"
    assert isinstance(err, ValueError)


# --- Permission Matrix Checks ---

def test_check_permission_admin():
    # Admin should always be allowed
    user = {"role": "admin"}
    assert check_permission(user, "any_resource", "any_action") is True


def test_check_permission_matrix_user_allowed():
    user = {"role": "user"}
    assert check_permission(user, "posts", "read") is True
    assert check_permission(user, "posts", "write") is True


def test_check_permission_matrix_user_denied():
    user = {"role": "user"}
    assert check_permission(user, "posts", "delete") is False
    assert check_permission(user, "settings", "admin") is False


def test_check_permission_matrix_guest_allowed():
    user = {"role": "guest"}
    assert check_permission(user, "posts", "read") is True


def test_check_permission_matrix_guest_denied():
    user = {"role": "guest"}
    assert check_permission(user, "users", "read") is False
    assert check_permission(user, "settings", "read") is False


def test_check_permission_direct_permission_exact():
    user = {"role": "guest", "permissions": ["users:read"]}
    assert check_permission(user, "users", "read") is True


def test_check_permission_direct_permission_wildcard():
    user = {"role": "guest", "permissions": ["users:*"]}
    assert check_permission(user, "users", "read") is True
    assert check_permission(user, "users", "delete") is True
    assert check_permission(user, "posts", "read") is True  # Allowed by role guest


def test_check_permission_direct_permission_global_wildcard():
    user = {"role": "guest", "permissions": ["*:*"]}
    assert check_permission(user, "settings", "write") is True


def test_check_permission_direct_permission_not_matched():
    user = {"role": "guest", "permissions": ["users:write"]}
    assert check_permission(user, "users", "read") is False


def test_check_permission_invalid_role():
    user = {"role": "hacker"}
    assert check_permission(user, "users", "read") is False


def test_check_permission_no_role():
    user = {}
    assert check_permission(user, "posts", "read") is False


# --- Resource Ownership Validation Tests ---

def test_ownership_admin():
    assert validate_resource_ownership(user_id=1, resource_id=10, resource_owner_id=2, user_role="admin") is True


def test_ownership_match_int():
    assert validate_resource_ownership(user_id=42, resource_id=100, resource_owner_id=42) is True


def test_ownership_match_str():
    assert validate_resource_ownership(user_id="42", resource_id="100", resource_owner_id="42") is True


def test_ownership_match_mixed():
    assert validate_resource_ownership(user_id=42, resource_id=100, resource_owner_id="42") is True
    assert validate_resource_ownership(user_id="42", resource_id=100, resource_owner_id=42) is True


def test_ownership_mismatch():
    assert validate_resource_ownership(user_id=42, resource_id=100, resource_owner_id=43) is False


def test_ownership_missing_user_role():
    assert validate_resource_ownership(user_id=42, resource_id=100, resource_owner_id=42, user_role=None) is True


# --- Static Scanner Tests ---

def test_scanner_empty_code():
    res = detect_missing_auth_middleware("")
    assert res["safe"] is True
    assert len(res["findings"]) == 0


def test_scanner_admin_route_missing_auth():
    code = """
    @app.route('/admin/dashboard')
    def admin_dashboard():
        return "Welcome"
    """
    res = detect_missing_auth_middleware(code)
    assert res["safe"] is False
    assert any(f["pattern"] == "Missing Auth in Admin Route" for f in res["findings"])


def test_scanner_admin_route_with_auth():
    code_decorator = """
    @require_role('admin')
    @app.route('/admin/dashboard')
    def admin_dashboard():
        return "Welcome"
    """
    res = detect_missing_auth_middleware(code_decorator)
    rule_1_findings = [f for f in res["findings"] if f["pattern"] == "Missing Auth in Admin Route"]
    assert len(rule_1_findings) == 0


def test_scanner_sensitive_user_route_missing_ownership():
    code = """
    @app.get("/api/users/{user_id}")
    def get_user(user_id: int):
        return {}
    """
    res = detect_missing_auth_middleware(code)
    assert any(f["pattern"] == "Missing Ownership Check" for f in res["findings"])


def test_scanner_sensitive_user_route_with_ownership():
    code = """
    @require_ownership('user_id')
    @app.get("/api/users/{user_id}")
    def get_user(user_id: int):
        return {}
    """
    res = detect_missing_auth_middleware(code)
    rule_2_findings = [f for f in res["findings"] if f["pattern"] == "Missing Ownership Check"]
    assert len(rule_2_findings) == 0


def test_scanner_route_handler_missing_auth():
    code = """
    @app.get("/posts")
    def get_posts():
        return []
    """
    res = detect_missing_auth_middleware(code)
    assert any(f["pattern"] == "Route Handler Missing Auth" for f in res["findings"])


def test_scanner_route_handler_with_auth():
    code = """
    @app.get("/posts")
    @require_auth(roles=['user'])
    def get_posts():
        return []
    """
    res = detect_missing_auth_middleware(code)
    rule_3_findings = [f for f in res["findings"] if f["pattern"] == "Route Handler Missing Auth"]
    assert len(rule_3_findings) == 0


# --- Decorator Tests ---

def test_decorator_require_role_success():
    @require_role("user")
    def my_view(user: Dict[str, Any]):
        return "success"

    assert my_view(user={"role": "user"}) == "success"


def test_decorator_require_role_admin_bypass():
    @require_role("user")
    def my_view(user: Dict[str, Any]):
        return "success"

    assert my_view(user={"role": "admin"}) == "success"


def test_decorator_require_role_fail():
    @require_role("admin")
    def my_view(user: Dict[str, Any]):
        return "success"

    with pytest.raises(VibeShieldAuthorizationError) as exc_info:
        my_view(user={"role": "user"})
    assert "not authorized" in str(exc_info.value)


@pytest.mark.asyncio
async def test_decorator_require_role_async():
    @require_role("user")
    async def my_async_view(user: Dict[str, Any]):
        return "success"

    res = await my_async_view(user={"role": "user"})
    assert res == "success"

    with pytest.raises(VibeShieldAuthorizationError):
        await my_async_view(user={"role": "guest"})


def test_decorator_require_permission_success():
    @require_permission("posts", "write")
    def edit_post(user: Dict[str, Any]):
        return "edited"

    assert edit_post(user={"role": "user"}) == "edited"


def test_decorator_require_permission_fail():
    @require_permission("users", "delete")
    def delete_user(user: Dict[str, Any]):
        return "deleted"

    with pytest.raises(VibeShieldAuthorizationError):
        delete_user(user={"role": "user"})


@pytest.mark.asyncio
async def test_decorator_require_permission_async():
    @require_permission("settings", "write")
    async def save_settings(user: Dict[str, Any]):
        return "saved"

    assert await save_settings(user={"role": "admin"}) == "saved"

    with pytest.raises(VibeShieldAuthorizationError):
        await save_settings(user={"role": "user"})


def test_decorator_require_ownership_success_kwargs():
    @require_ownership("post_id")
    def get_post(post_id: int, user: Dict[str, Any], owner_id: int):
        return "post-content"

    assert get_post(post_id=123, user={"id": 42}, owner_id=42) == "post-content"


def test_decorator_require_ownership_success_extractor():
    def dummy_db_extractor(resource_id):
        return 99

    @require_ownership("post_id", owner_id_extractor=dummy_db_extractor)
    def get_post(post_id: int, user: Dict[str, Any]):
        return "post-content"

    assert get_post(post_id=123, user={"id": 99}) == "post-content"


def test_decorator_require_ownership_fail():
    @require_ownership("post_id")
    def get_post(post_id: int, user: Dict[str, Any], owner_id: int):
        return "post-content"

    with pytest.raises(VibeShieldAuthorizationError):
        get_post(post_id=123, user={"id": 42}, owner_id=43)


@pytest.mark.asyncio
async def test_decorator_require_ownership_async():
    @require_ownership("resource_id")
    async def delete_item(resource_id: str, user: Dict[str, Any], owner_id: str):
        return "deleted"

    assert await delete_item(resource_id="item55", user={"id": "u1"}, owner_id="u1") == "deleted"

    with pytest.raises(VibeShieldAuthorizationError):
        await delete_item(resource_id="item55", user={"id": "u1"}, owner_id="u2")


def test_decorator_require_auth_combined_success():
    @require_auth(roles=["user"], permissions=["posts:write"])
    def update_post(user: Dict[str, Any]):
        return "updated"

    assert update_post(user={"role": "user", "permissions": ["posts:write"]}) == "updated"


def test_decorator_require_auth_combined_fail():
    @require_auth(roles=["user"], permissions=["users:delete"])
    def update_post(user: Dict[str, Any]):
        return "updated"

    # Fails due to role not matched
    with pytest.raises(VibeShieldAuthorizationError):
        update_post(user={"role": "guest", "permissions": ["users:delete"]})

    # Fails due to missing permission (user role 'user' does not have users:delete)
    with pytest.raises(VibeShieldAuthorizationError):
        update_post(user={"role": "user", "permissions": []})


@pytest.mark.asyncio
async def test_decorator_require_auth_combined_async():
    @require_auth(roles=["user"], ownership={"resource_id_key": "pid"})
    async def edit_post_async(pid: int, user: Dict[str, Any], owner_id: int):
        return "async-success"

    assert await edit_post_async(pid=10, user={"role": "user", "id": 5}, owner_id=5) == "async-success"


def test_decorator_missing_user_context():
    @require_role("user")
    def test_view():
        return "ok"

    with pytest.raises(VibeShieldAuthorizationError) as exc_info:
        test_view()
    assert "User context not found" in str(exc_info.value)


# --- Context Extraction Tests (FastAPI request object, Flask mock) ---

def test_fastapi_request_user_extraction():
    @require_role("user")
    def my_view(request):
        return "ok"

    req = MockRequest(user={"role": "user"})
    assert my_view(request=req) == "ok"


def test_fastapi_request_ownership_extraction():
    @require_ownership("post_id")
    def my_view(request, owner_id=None):
        return "ok"

    req = MockRequest(user={"id": 10}, path_params={"post_id": 50})
    assert my_view(request=req, owner_id=10) == "ok"


def test_flask_request_g_extraction():
    flask_mock = MagicMock()
    flask_mock.g.user = {"role": "user"}
    flask_mock.request = MagicMock()
    flask_mock.request.user = None
    flask_mock.request.environ = {}

    with patch.dict("sys.modules", {"flask": flask_mock}):
        @require_role("user")
        def my_view():
            return "ok"

        assert my_view() == "ok"


def test_flask_request_environ_extraction():
    flask_mock = MagicMock()
    flask_mock.g = MagicMock(spec=[])  # no user attribute
    flask_mock.request.user = None
    flask_mock.request.environ = {"user": {"role": "guest"}}

    with patch.dict("sys.modules", {"flask": flask_mock}):
        @require_role("guest")
        def my_view():
            return "ok"

        assert my_view() == "ok"


# --- Extra edge cases for permissions ---

def test_require_auth_various_permission_formats():
    @require_auth(permissions="posts:read")
    def check_str(user):
        return "str_ok"

    @require_auth(permissions=("posts", "read"))
    def check_tuple(user):
        return "tuple_ok"

    @require_auth(permissions={"resource": "posts", "action": "read"})
    def check_dict(user):
        return "dict_ok"

    @require_auth(permissions=["posts:read", ("posts", "read")])
    def check_list(user):
        return "list_ok"

    user = {"role": "guest"}
    assert check_str(user=user) == "str_ok"
    assert check_tuple(user=user) == "tuple_ok"
    assert check_dict(user=user) == "dict_ok"
    assert check_list(user=user) == "list_ok"


def test_require_auth_invalid_permission_format():
    @require_auth(permissions="posts_without_colon")
    def test_view(user):
        return "ok"

    with pytest.raises(VibeShieldAuthorizationError) as exc_info:
        test_view(user={"role": "user"})
    assert "Invalid permission format" in str(exc_info.value)

def test_create_permission_matrix():
    from src.authorization_protector import create_permission_matrix
    custom = create_permission_matrix({
        "moderator": {
            "posts": ["read", "write", "delete"]
        }
    })
    assert "moderator" in custom
    assert custom["moderator"]["posts"] == ["read", "write", "delete"]
    assert "delete" in custom["admin"]["users"]

def test_check_permission_custom_matrix():
    from src.authorization_protector import create_permission_matrix, check_permission
    custom = create_permission_matrix({
        "moderator": {
            "posts": ["read", "write", "delete"]
        }
    })
    assert check_permission("moderator", "posts", "delete", custom) is True
    assert check_permission("moderator", "users", "read", custom) is False
    assert check_permission("user", "posts", "write", custom) is True
