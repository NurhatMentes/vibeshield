import functools
import inspect
from typing import Any, Callable, Dict
from ..schema_validator import validate_schema

def validate_request(schema: Dict[str, Any]) -> Callable:
    def decorator(func: Callable) -> Callable:
        # Check if the decorated function is a coroutine
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
                        body = await fastapi_request.json()
                    except Exception:
                        body = {}

                    query = dict(fastapi_request.query_params)
                    path = dict(fastapi_request.path_params)
                    data_to_validate = {**query, **path, **body}
                    result = validate_schema(data_to_validate, schema)
                    if not result["valid"]:
                        try:
                            from fastapi.responses import JSONResponse
                        except ImportError:
                            from starlette.responses import JSONResponse
                        return JSONResponse(
                            status_code=400,
                            content={
                                "error": "Bad Request",
                                "message": "Schema validation failed",
                                "errors": result["errors"]
                            }
                        )
                    fastapi_request.state.sanitized_data = result["sanitized_data"]

                return await func(*args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                # Check Flask request
                is_flask = False
                try:
                    from flask import request as flask_request
                    if flask_request and hasattr(flask_request, 'method') and flask_request.method:
                        is_flask = True
                except ImportError:
                    pass

                if is_flask:
                    from flask import request as flask_request, jsonify
                    body = {}
                    if flask_request.is_json:
                        body = flask_request.get_json() or {}
                    query = flask_request.args.to_dict() if hasattr(flask_request, 'args') else {}
                    path_params = flask_request.view_args or {}
                    data_to_validate = {**query, **path_params, **body}
                    result = validate_schema(data_to_validate, schema)
                    if not result["valid"]:
                        return jsonify({
                            "error": "Bad Request",
                            "message": "Schema validation failed",
                            "errors": result["errors"]
                        }), 400
                    flask_request.sanitized_data = result["sanitized_data"]
                    return func(*args, **kwargs)

                # Check FastAPI sync request
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
                        pass

                    query = dict(fastapi_request.query_params)
                    path = dict(fastapi_request.path_params)
                    data_to_validate = {**query, **path, **body}
                    result = validate_schema(data_to_validate, schema)
                    if not result["valid"]:
                        try:
                            from fastapi.responses import JSONResponse
                        except ImportError:
                            from starlette.responses import JSONResponse
                        return JSONResponse(
                            status_code=400,
                            content={
                                "error": "Bad Request",
                                "message": "Schema validation failed",
                                "errors": result["errors"]
                            }
                        )
                    fastapi_request.state.sanitized_data = result["sanitized_data"]
                return func(*args, **kwargs)
            return sync_wrapper
    return decorator
