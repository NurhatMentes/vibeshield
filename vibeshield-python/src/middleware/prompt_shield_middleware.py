import functools
import inspect
from typing import Any, Callable, Dict, List, Optional
from ..prompt_shield import detect_prompt_injection

def prompt_shield(
    fields: Optional[List[str]] = None,
    threshold: int = 100,
    block_on_detection: bool = True,
    on_detection: Optional[Callable[[Dict[str, Any], Any], None]] = None,
    options: Optional[Dict[str, Any]] = None
) -> Callable:
    scan_fields = fields or ['prompt', 'message', 'query', 'input', 'text', 'content']
    shield_options = options or {}

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

                worst_result = {
                    'safe': True,
                    'score': 0,
                    'risk_level': 'none',
                    'threats': [],
                    'summary': 'Input is safe'
                }

                if fastapi_request:
                    body = {}
                    try:
                        # Attempt to read body
                        if hasattr(fastapi_request, '_json'):
                            body = fastapi_request._json
                        else:
                            import json
                            # Avoid reading body asynchronously if already read, or use clone/fallback
                            body_bytes = await fastapi_request.body()
                            body = json.loads(body_bytes.decode('utf-8'))
                    except Exception:
                        body = {}

                    max_score = 0
                    for field in scan_fields:
                        val = body.get(field)
                        if isinstance(val, str) and val:
                            result = detect_prompt_injection(val, shield_options)
                            if result['score'] > max_score:
                                max_score = result['score']
                                worst_result = result

                    if max_score >= threshold:
                        if on_detection:
                            on_detection(worst_result, fastapi_request)
                        if block_on_detection:
                            try:
                                from fastapi.responses import JSONResponse
                            except ImportError:
                                from starlette.responses import JSONResponse
                            return JSONResponse(
                                status_code=403,
                                content={
                                    "error": "Forbidden",
                                    "message": "Potential prompt injection or jailbreak detected",
                                    "details": worst_result
                                }
                            )

                    # Attach result to request state
                    if hasattr(fastapi_request, 'state'):
                        fastapi_request.state.prompt_shield_result = worst_result
                    else:
                        fastapi_request.prompt_shield_result = worst_result

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

                worst_result = {
                    'safe': True,
                    'score': 0,
                    'risk_level': 'none',
                    'threats': [],
                    'summary': 'Input is safe'
                }

                if is_flask:
                    from flask import jsonify, request as flask_request
                    body = {}
                    if flask_request.is_json:
                        body = flask_request.get_json() or {}

                    max_score = 0
                    for field in scan_fields:
                        val = body.get(field)
                        if isinstance(val, str) and val:
                            result = detect_prompt_injection(val, shield_options)
                            if result['score'] > max_score:
                                max_score = result['score']
                                worst_result = result

                    if max_score >= threshold:
                        if on_detection:
                            on_detection(worst_result, flask_request)
                        if block_on_detection:
                            return jsonify({
                                "error": "Forbidden",
                                "message": "Potential prompt injection or jailbreak detected",
                                "details": worst_result
                            }), 403

                    flask_request.prompt_shield_result = worst_result
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

                    max_score = 0
                    for field in scan_fields:
                        val = body.get(field)
                        if isinstance(val, str) and val:
                            result = detect_prompt_injection(val, shield_options)
                            if result['score'] > max_score:
                                max_score = result['score']
                                worst_result = result

                    if max_score >= threshold:
                        if on_detection:
                            on_detection(worst_result, fastapi_request)
                        if block_on_detection:
                            try:
                                from fastapi.responses import JSONResponse
                            except ImportError:
                                from starlette.responses import JSONResponse
                            return JSONResponse(
                                status_code=403,
                                content={
                                    "error": "Forbidden",
                                    "message": "Potential prompt injection or jailbreak detected",
                                    "details": worst_result
                                }
                            )

                    if hasattr(fastapi_request, 'state'):
                        fastapi_request.state.prompt_shield_result = worst_result
                    else:
                        fastapi_request.prompt_shield_result = worst_result

                return func(*args, **kwargs)
            return sync_wrapper
    return decorator
