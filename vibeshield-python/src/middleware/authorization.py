import functools
import inspect
import logging
from typing import Any, Callable, Dict, List, Optional, Union
from ..authorization_protector import (
    VibeShieldAuthorizationError,
    check_permission,
    validate_resource_ownership,
)

logger = logging.getLogger("VibeShield")

def _get_user_and_request(*args, **kwargs):
    # 1. Look in kwargs
    user = kwargs.get("user") or kwargs.get("current_user")
    request = kwargs.get("request")

    # 2. Look in args for a request-like object (typically with starlette/fastapi signature)
    if not request:
        for arg in args:
            if hasattr(arg, "scope") and hasattr(arg, "receive"):
                request = arg
                break

    # 3. Resolve user from request if found
    if request:
        if not user:
            if hasattr(request, "state") and hasattr(request.state, "user"):
                user = request.state.user
            elif isinstance(request, dict) and "user" in request:
                user = request["user"]
            elif hasattr(request, "scope") and isinstance(request.scope, dict) and "user" in request.scope:
                user = request.scope["user"]
            elif hasattr(request, "user"):
                user = request.user

    # 4. Resolve from Flask g or request
    if not user:
        try:
            from flask import g as flask_g, request as flask_req
            if flask_g and hasattr(flask_g, "user") and flask_g.user is not None:
                user = flask_g.user
            elif flask_g and hasattr(flask_g, "current_user") and flask_g.current_user is not None:
                user = flask_g.current_user
            elif flask_req:
                if hasattr(flask_req, "user") and flask_req.user is not None:
                    user = flask_req.user
                elif hasattr(flask_req, "environ") and "user" in flask_req.environ:
                    user = flask_req.environ["user"]
        except ImportError:
            pass

    return user, request

def _normalize_user(user: Any) -> Dict[str, Any]:
    if not user:
        return {}
    if isinstance(user, dict):
        return user
    
    user_dict = {}
    if hasattr(user, "get") and callable(getattr(user, "get")):
        user_dict["role"] = user.get("role")
        user_dict["permissions"] = user.get("permissions", [])
        user_dict["id"] = user.get("id") or user.get("user_id")
    else:
        user_dict["role"] = getattr(user, "role", None)
        user_dict["permissions"] = getattr(user, "permissions", [])
        user_dict["id"] = getattr(user, "id", None) or getattr(user, "user_id", None)
        
    return user_dict

def _verify_role(user: Any, role_name: Union[str, List[str]]) -> None:
    user_dict = _normalize_user(user)
    user_role = user_dict.get("role")
    
    if isinstance(role_name, str):
        allowed_roles = [role_name]
    else:
        allowed_roles = list(role_name)

    if user_role == "admin":
        return

    if not user_role or user_role not in allowed_roles:
        logger.warning("[VibeShield] Role check failed: User role '%s' not in %s", user_role, allowed_roles)
        raise VibeShieldAuthorizationError(
            f"User role '{user_role}' is not authorized. Allowed: {allowed_roles}"
        )

def _verify_permission(user: Any, resource: str, action: str) -> None:
    user_dict = _normalize_user(user)
    if not check_permission(user_dict, resource, action):
        logger.warning("[VibeShield] Permission check failed: missing %s:%s for role %s", resource, action, user_dict.get("role"))
        raise VibeShieldAuthorizationError(
            f"User is missing required permission: {resource}:{action}"
        )

def _verify_ownership(user: Any, args: tuple, kwargs: dict, request: Any, resource_id_key: str, owner_id_extractor: Optional[Callable]) -> None:
    resource_id = kwargs.get(resource_id_key)
    if resource_id is None:
        if request and hasattr(request, "path_params") and isinstance(request.path_params, dict):
            resource_id = request.path_params.get(resource_id_key)
        if resource_id is None:
            try:
                from flask import request as flask_req
                if flask_req and flask_req.view_args:
                    resource_id = flask_req.view_args.get(resource_id_key)
            except ImportError:
                pass

    if owner_id_extractor:
        try:
            resource_owner_id = owner_id_extractor(resource_id)
        except Exception as e:
            logger.error("[VibeShield] Failed to extract owner ID: %s", str(e))
            raise VibeShieldAuthorizationError(f"Failed to extract owner ID: {str(e)}")
    else:
        resource_owner_id = kwargs.get("owner_id") or kwargs.get("resource_owner_id") or resource_id

    user_dict = _normalize_user(user)
    user_id = user_dict.get("id")
    user_role = user_dict.get("role")

    if not validate_resource_ownership(user_id, resource_id, resource_owner_id, user_role):
        logger.warning("[VibeShield] Ownership validation failed: User %s, Resource %s, Owner %s", user_id, resource_id, resource_owner_id)
        raise VibeShieldAuthorizationError(
            f"User '{user_id}' does not own resource '{resource_id}' (owner: '{resource_owner_id}')"
        )

def _check_permissions_list(user: Any, permissions: Any) -> None:
    if not permissions:
        return
    
    if isinstance(permissions, (str, tuple, dict)):
        perm_list = [permissions]
    else:
        perm_list = list(permissions)

    for perm in perm_list:
        if isinstance(perm, str):
            if ":" not in perm:
                raise VibeShieldAuthorizationError(f"Invalid permission format: {perm}")
            resource, action = perm.split(":", 1)
        elif isinstance(perm, (tuple, list)):
            if len(perm) != 2:
                raise VibeShieldAuthorizationError(f"Invalid permission tuple/list: {perm}")
            resource, action = perm[0], perm[1]
        elif isinstance(perm, dict):
            resource = perm.get("resource")
            action = perm.get("action")
            if not resource or not action:
                raise VibeShieldAuthorizationError(f"Invalid permission dictionary: {perm}")
        else:
            raise VibeShieldAuthorizationError(f"Unsupported permission type: {type(perm)}")

        _verify_permission(user, resource, action)

def require_role(role_name: Union[str, List[str]]) -> Callable:
    """Decorator to require a user role."""
    def decorator(func: Callable) -> Callable:
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                user, request = _get_user_and_request(*args, **kwargs)
                if not user:
                    raise VibeShieldAuthorizationError("User context not found.")
                _verify_role(user, role_name)
                return await func(*args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                user, request = _get_user_and_request(*args, **kwargs)
                if not user:
                    raise VibeShieldAuthorizationError("User context not found.")
                _verify_role(user, role_name)
                return func(*args, **kwargs)
            return sync_wrapper
    return decorator

def require_permission(resource: str, action: str) -> Callable:
    """Decorator to require a resource action permission."""
    def decorator(func: Callable) -> Callable:
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                user, request = _get_user_and_request(*args, **kwargs)
                if not user:
                    raise VibeShieldAuthorizationError("User context not found.")
                _verify_permission(user, resource, action)
                return await func(*args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                user, request = _get_user_and_request(*args, **kwargs)
                if not user:
                    raise VibeShieldAuthorizationError("User context not found.")
                _verify_permission(user, resource, action)
                return func(*args, **kwargs)
            return sync_wrapper
    return decorator

def require_ownership(resource_id_key: str = "resource_id", owner_id_extractor: Optional[Callable] = None) -> Callable:
    """Decorator to enforce resource ownership validation to prevent IDOR."""
    def decorator(func: Callable) -> Callable:
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                user, request = _get_user_and_request(*args, **kwargs)
                if not user:
                    raise VibeShieldAuthorizationError("User context not found.")
                _verify_ownership(user, args, kwargs, request, resource_id_key, owner_id_extractor)
                return await func(*args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                user, request = _get_user_and_request(*args, **kwargs)
                if not user:
                    raise VibeShieldAuthorizationError("User context not found.")
                _verify_ownership(user, args, kwargs, request, resource_id_key, owner_id_extractor)
                return func(*args, **kwargs)
            return sync_wrapper
    return decorator

def require_auth(
    roles: Optional[Union[str, List[str]]] = None,
    permissions: Optional[Any] = None,
    ownership: Optional[Dict[str, Any]] = None
) -> Callable:
    """Combined decorator to enforce roles, permissions, and ownership validation."""
    def decorator(func: Callable) -> Callable:
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                user, request = _get_user_and_request(*args, **kwargs)
                if not user:
                    raise VibeShieldAuthorizationError("User context not found.")
                
                if roles:
                    _verify_role(user, roles)
                if permissions:
                    _check_permissions_list(user, permissions)
                if ownership is not None:
                    resource_id_key = ownership.get("resource_id_key", "resource_id")
                    owner_id_extractor = ownership.get("owner_id_extractor")
                    _verify_ownership(user, args, kwargs, request, resource_id_key, owner_id_extractor)
                    
                return await func(*args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                user, request = _get_user_and_request(*args, **kwargs)
                if not user:
                    raise VibeShieldAuthorizationError("User context not found.")
                
                if roles:
                    _verify_role(user, roles)
                if permissions:
                    _check_permissions_list(user, permissions)
                if ownership is not None:
                    resource_id_key = ownership.get("resource_id_key", "resource_id")
                    owner_id_extractor = ownership.get("owner_id_extractor")
                    _verify_ownership(user, args, kwargs, request, resource_id_key, owner_id_extractor)
                    
                return func(*args, **kwargs)
            return sync_wrapper
    return decorator
