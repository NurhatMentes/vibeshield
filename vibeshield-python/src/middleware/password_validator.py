import functools
import inspect
from typing import Any, Callable, Dict, Optional
from ..password_protector import validate_password

def validate_password_policy(
    min_length: int = 12,
    max_length: int = 128,
    require_complexity: bool = True
) -> Callable:
    def decorator(func: Callable) -> Callable:
        if inspect.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                fastapi_request = None
                for arg in args:
                    if hasattr(arg, 'scope') and hasattr(arg, 'receive'):
                        fastapi_request = arg
                        break
                if not fastapi_request:
                    for val in kwargs.values():
                        if hasattr(val, 'scope') and hasattr(val, 'receive'):
                            fastapi_request = val
                            break

                if fastapi_request:
                    body = {}
                    try:
                        if hasattr(fastapi_request, '_json'):
                            body = fastapi_request._json
                        else:
                            import json
                            body = json.loads(fastapi_request._body.decode('utf-8'))
                    except Exception:
                        body = {}

                    password = body.get("password")
                    context = body.get("context") or {
                        "username": body.get("username"),
                        "email": body.get("email"),
                        "firstName": body.get("firstName"),
                        "lastName": body.get("lastName"),
                        "birthDate": body.get("birthDate")
                    }

                    result = validate_password(password, context, min_length, max_length, require_complexity)
                    if not result["valid"]:
                        try:
                            from fastapi.responses import JSONResponse
                        except ImportError:
                            from starlette.responses import JSONResponse
                        return JSONResponse(
                            status_code=400,
                            content={
                                "error": "Bad Request",
                                "message": "Password does not meet security requirements",
                                "details": result
                            }
                        )

                return await func(*args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                is_flask = False
                try:
                    from flask import request as flask_request
                    if flask_request and hasattr(flask_request, 'method') and flask_request.method:
                        is_flask = True
                except ImportError:
                    pass

                if is_flask:
                    from flask import jsonify, request as flask_request
                    body = {}
                    if flask_request.is_json:
                        body = flask_request.get_json() or {}

                    password = body.get("password")
                    context = body.get("context") or {
                        "username": body.get("username"),
                        "email": body.get("email"),
                        "firstName": body.get("firstName"),
                        "lastName": body.get("lastName"),
                        "birthDate": body.get("birthDate")
                    }

                    result = validate_password(password, context, min_length, max_length, require_complexity)
                    if not result["valid"]:
                        return jsonify({
                            "error": "Bad Request",
                            "message": "Password does not meet security requirements",
                            "details": result
                        }), 400
                    return func(*args, **kwargs)

                fastapi_request = None
                for arg in args:
                    if hasattr(arg, 'scope') and hasattr(arg, 'receive'):
                        fastapi_request = arg
                        break
                if not fastapi_request:
                    for val in kwargs.values():
                        if hasattr(val, 'scope') and hasattr(val, 'receive'):
                            fastapi_request = val
                            break

                if fastapi_request:
                    body = {}
                    try:
                        if hasattr(fastapi_request, '_json'):
                            body = fastapi_request._json
                        else:
                            import json
                            body = json.loads(fastapi_request._body.decode('utf-8'))
                    except Exception:
                        body = {}

                    password = body.get("password")
                    context = body.get("context") or {
                        "username": body.get("username"),
                        "email": body.get("email"),
                        "firstName": body.get("firstName"),
                        "lastName": body.get("lastName"),
                        "birthDate": body.get("birthDate")
                    }

                    result = validate_password(password, context, min_length, max_length, require_complexity)
                    if not result["valid"]:
                        try:
                            from fastapi.responses import JSONResponse
                        except ImportError:
                            from starlette.responses import JSONResponse
                        return JSONResponse(
                            status_code=400,
                            content={
                                "error": "Bad Request",
                                "message": "Password does not meet security requirements",
                                "details": result
                            }
                        )

                return func(*args, **kwargs)
            return sync_wrapper
    return decorator
