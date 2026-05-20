import json
import urllib.parse
from urllib.parse import parse_qsl, urlencode
import io

from .sanitizer import sanitize
from .cache import VibeShieldCache, CachedResponse
from .errors import handle_exception

# Global cache instance
global_cache = VibeShieldCache()

class VibeShieldASGIMiddleware:
    """
    ASGI Middleware for FastAPI / Starlette.
    Provides plug-and-play sanitization, error masking, and caching.
    """
    def __init__(self, app, cache_enabled: bool = False, cache_ttl: float = 60.0, key_generator = None):
        self.app = app
        self.cache_enabled = cache_enabled
        self.cache_ttl = cache_ttl
        self.key_generator = key_generator

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 1. Sanitize Query Parameters on-the-fly
        query_string = scope.get("query_string", b"").decode("utf-8")
        if query_string:
            pairs = parse_qsl(query_string, keep_blank_values=True)
            sanitized_pairs = [(k, sanitize(v)) for k, v in pairs]
            scope["query_string"] = urlencode(sanitized_pairs).encode("utf-8")

        # 2. Sanitize Path Parameters if present
        if "path_params" in scope:
            scope["path_params"] = sanitize(scope["path_params"])

        # 3. Check Cache for GET requests
        method = scope.get("method", "GET")
        path = scope.get("path", "")
        
        cache_key = None
        if self.cache_enabled and method == "GET":
            if self.key_generator:
                try:
                    # In python, we pass a simplified dict-based request proxy to match JS signature
                    req_proxy = {"method": method, "path": path, "query_string": query_string}
                    cache_key = self.key_generator(req_proxy)
                except Exception:
                    cache_key = f"{method}:{path}?{query_string}"
            else:
                cache_key = f"{method}:{path}?{query_string}"

            cached = global_cache.get(cache_key)
            if cached:
                # Cache hit - send response directly
                await send({
                    "type": "http.response.start",
                    "status": cached.status,
                    "headers": cached.headers
                })
                await send({
                    "type": "http.response.body",
                    "body": cached.body,
                    "more_body": False
                })
                return

        # 4. Intercept Request Body
        # We need to buffer and sanitize the body for POST/PUT/PATCH
        sanitized_receive = receive
        if method in ("POST", "PUT", "PATCH"):
            body = b""
            more_body = True
            while more_body:
                message = await receive()
                if message["type"] == "http.request":
                    body += message.get("body", b"")
                    more_body = message.get("more_body", False)
            
            # Sanitize the body depending on content-type
            headers_dict = {k.decode("utf-8").lower(): v.decode("utf-8") for k, v in scope.get("headers", [])}
            content_type = headers_dict.get("content-type", "")
            
            sanitized_body = body
            if body:
                if "application/json" in content_type:
                    try:
                        data = json.loads(body.decode("utf-8"))
                        sanitized_data = sanitize(data)
                        sanitized_body = json.dumps(sanitized_data).encode("utf-8")
                    except Exception:
                        sanitized_body = sanitize(body.decode("utf-8", errors="ignore")).encode("utf-8")
                elif "application/x-www-form-urlencoded" in content_type:
                    try:
                        body_str = body.decode("utf-8")
                        pairs = parse_qsl(body_str, keep_blank_values=True)
                        sanitized_pairs = [(k, sanitize(v)) for k, v in pairs]
                        sanitized_body = urlencode(sanitized_pairs).encode("utf-8")
                    except Exception:
                        sanitized_body = sanitize(body.decode("utf-8", errors="ignore")).encode("utf-8")
                else:
                    sanitized_body = sanitize(body.decode("utf-8", errors="ignore")).encode("utf-8")

            # Create helper to feed the sanitized body back to the app
            class SanitizedReceive:
                def __init__(self, b: bytes):
                    self.b = b
                    self.read = False
                async def __call__(self):
                    if not self.read:
                        self.read = True
                        return {
                            "type": "http.request",
                            "body": self.b,
                            "more_body": False
                        }
                    return {"type": "http.disconnect"}
            
            sanitized_receive = SanitizedReceive(sanitized_body)

        # 5. Capture Response Chunks & Exceptions
        status_code = [200]
        response_headers = [[]]
        body_chunks = []

        async def custom_send(message):
            if message["type"] == "http.response.start":
                status_code[0] = message.get("status", 200)
                response_headers[0] = message.get("headers", [])
            elif message["type"] == "http.response.body":
                body_chunks.append(message.get("body", b""))
            await send(message)

        try:
            await self.app(scope, sanitized_receive, custom_send)
            
            # Cache the response on successful GET
            if self.cache_enabled and method == "GET" and status_code[0] == 200 and cache_key:
                full_body = b"".join(body_chunks)
                global_cache.set(cache_key, CachedResponse(status_code[0], response_headers[0], full_body), self.cache_ttl)
                
        except Exception as e:
            masked_payload, tracking_id = handle_exception(e)
            error_body = json.dumps(masked_payload).encode("utf-8")
            
            await send({
                "type": "http.response.start",
                "status": 500,
                "headers": [(b"content-type", b"application/json")]
            })
            await send({
                "type": "http.response.body",
                "body": error_body,
                "more_body": False
            })


class VibeShieldWSGIMiddleware:
    """
    WSGI Middleware for Flask.
    Provides plug-and-play sanitization, error masking, and caching.
    """
    def __init__(self, app, cache_enabled: bool = False, cache_ttl: float = 60.0, key_generator = None):
        self.app = app
        self.cache_enabled = cache_enabled
        self.cache_ttl = cache_ttl
        self.key_generator = key_generator

    def __call__(self, environ, start_response):
        # 1. Sanitize Query Parameters on-the-fly
        query_string = environ.get("QUERY_STRING", "")
        if query_string:
            pairs = parse_qsl(query_string, keep_blank_values=True)
            sanitized_pairs = [(k, sanitize(v)) for k, v in pairs]
            environ["QUERY_STRING"] = urlencode(sanitized_pairs)

        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "")

        # 2. Check Cache for GET requests
        cache_key = None
        if self.cache_enabled and method == "GET":
            if self.key_generator:
                try:
                    req_proxy = {"method": method, "path": path, "query_string": query_string}
                    cache_key = self.key_generator(req_proxy)
                except Exception:
                    cache_key = f"{method}:{path}?{query_string}"
            else:
                cache_key = f"{method}:{path}?{query_string}"

            cached = global_cache.get(cache_key)
            if cached:
                # Cache hit - start response and return cached body
                start_response(f"{cached.status} OK", cached.headers)
                return [cached.body]

        # 3. Sanitize Request Body for POST/PUT/PATCH
        content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)
        if content_length > 0 and method in ("POST", "PUT", "PATCH"):
            body = environ["wsgi.input"].read(content_length)
            content_type = environ.get("CONTENT_TYPE", "")
            
            sanitized_body = body
            if "application/json" in content_type:
                try:
                    data = json.loads(body.decode("utf-8"))
                    sanitized_data = sanitize(data)
                    sanitized_body = json.dumps(sanitized_data).encode("utf-8")
                except Exception:
                    sanitized_body = sanitize(body.decode("utf-8", errors="ignore")).encode("utf-8")
            elif "application/x-www-form-urlencoded" in content_type:
                try:
                    body_str = body.decode("utf-8")
                    pairs = parse_qsl(body_str, keep_blank_values=True)
                    sanitized_pairs = [(k, sanitize(v)) for k, v in pairs]
                    sanitized_body = urlencode(sanitized_pairs).encode("utf-8")
                except Exception:
                    sanitized_body = sanitize(body.decode("utf-8", errors="ignore")).encode("utf-8")
            else:
                sanitized_body = sanitize(body.decode("utf-8", errors="ignore")).encode("utf-8")

            environ["wsgi.input"] = io.BytesIO(sanitized_body)
            environ["CONTENT_LENGTH"] = str(len(sanitized_body))

        # 4. Capture Response Chunks & Exceptions
        captured_status = [None]
        captured_headers = [None]

        def custom_start_response(status, response_headers, exc_info=None):
            captured_status[0] = status
            captured_headers[0] = response_headers
            return start_response(status, response_headers, exc_info)

        try:
            response_iterable = self.app(environ, custom_start_response)
            body_chunks = []
            for chunk in response_iterable:
                body_chunks.append(chunk)
            
            full_body = b"".join(body_chunks)

            # Cache the response on successful GET
            if self.cache_enabled and method == "GET" and captured_status[0] and captured_status[0].startswith("200") and cache_key:
                try:
                    status_code = int(captured_status[0].split()[0])
                except Exception:
                    status_code = 200
                global_cache.set(cache_key, CachedResponse(status_code, captured_headers[0], full_body), self.cache_ttl)

            return [full_body]

        except Exception as e:
            masked_payload, tracking_id = handle_exception(e)
            error_body = json.dumps(masked_payload).encode("utf-8")
            start_response("500 Internal Server Error", [("Content-Type", "application/json")])
            return [error_body]
