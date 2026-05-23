import json
import urllib.parse
from urllib.parse import parse_qsl, urlencode
import io

from .sanitizer import sanitize
from .cache import VibeShieldCache, CachedResponse
from .errors import handle_exception
from .security.crypto import process_crypto_fields
from .validation import validate_payload
from .logging import start_audit_timer, end_audit_timer, log_audit, log_performance_warning

# Global cache instance
global_cache = VibeShieldCache()

class VibeShieldASGIMiddleware:
    """
    ASGI Middleware for FastAPI / Starlette.
    Provides plug-and-play sanitization, error masking, caching, and transparent field encryption.
    """
    def __init__(self, app, cache_enabled: bool = False, cache_ttl: float = 60.0, key_generator = None, crypto_secret: str = None, crypto_fields: list = None, validation_schema: dict = None, logging: dict = None):
        self.app = app
        self.cache_enabled = cache_enabled
        self.cache_ttl = cache_ttl
        self.key_generator = key_generator
        self.crypto_secret = crypto_secret
        self.crypto_fields = crypto_fields or []
        self.validation_schema = validation_schema
        self.logging = logging

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        audit_start_time = start_audit_timer() if self.logging else None
        is_crypto_active = bool(self.crypto_secret and self.crypto_fields)

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
                    req_proxy = {"method": method, "path": path, "query_string": query_string}
                    cache_key = self.key_generator(req_proxy)
                except Exception:
                    cache_key = f"{method}:{path}?{query_string}"
            else:
                cache_key = f"{method}:{path}?{query_string}"

            cached = global_cache.get(cache_key)
            if cached:
                if self.logging and audit_start_time is not None:
                    duration_ms = end_audit_timer(audit_start_time)
                    if self.logging.get("audit"): log_audit(method, path, cached.status, duration_ms)
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
        sanitized_receive = receive
        if method in ("POST", "PUT", "PATCH"):
            body = b""
            more_body = True
            while more_body:
                message = await receive()
                if message["type"] == "http.request":
                    body += message.get("body", b"")
                    more_body = message.get("more_body", False)
            
            headers_dict = {k.decode("utf-8").lower(): v.decode("utf-8") for k, v in scope.get("headers", [])}
            content_type = headers_dict.get("content-type", "")
            
            sanitized_body = body
            if body:
                if "application/json" in content_type:
                    try:
                        data = json.loads(body.decode("utf-8"))
                        if self.validation_schema:
                            is_valid, errors = validate_payload(data, self.validation_schema)
                            if not is_valid:
                                error_body = json.dumps({"status": "error", "errors": errors}).encode("utf-8")
                                if self.logging and audit_start_time is not None:
                                    duration_ms = end_audit_timer(audit_start_time)
                                    if self.logging.get("audit"): log_audit(method, path, 400, duration_ms)
                                await send({
                                    "type": "http.response.start",
                                    "status": 400,
                                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(error_body)).encode("utf-8"))]
                                })
                                await send({
                                    "type": "http.response.body",
                                    "body": error_body,
                                    "more_body": False
                                })
                                return
                        sanitized_data = sanitize(data)
                        if is_crypto_active:
                            sanitized_data = process_crypto_fields(sanitized_data, self.crypto_fields, True, self.crypto_secret)
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
                if not is_crypto_active:
                    await send(message)
            elif message["type"] == "http.response.body":
                body_chunks.append(message.get("body", b""))
                if not is_crypto_active:
                    await send(message)

        try:
            await self.app(scope, sanitized_receive, custom_send)
            
            full_body = b"".join(body_chunks)

            # 6. Response Decryption
            if is_crypto_active:
                content_type = next((v.decode("utf-8") for k, v in response_headers[0] if k.decode("utf-8").lower() == "content-type"), "")
                if "application/json" in content_type:
                    try:
                        res_data = json.loads(full_body.decode("utf-8"))
                        decrypted_data = process_crypto_fields(res_data, self.crypto_fields, False, self.crypto_secret)
                        full_body = json.dumps(decrypted_data).encode("utf-8")
                        new_headers = []
                        for k, v in response_headers[0]:
                            if k.decode("utf-8").lower() == "content-length":
                                new_headers.append((k, str(len(full_body)).encode("utf-8")))
                            else:
                                new_headers.append((k, v))
                        response_headers[0] = new_headers
                    except Exception:
                        pass
                
                # Send the buffered and decrypted response
                await send({
                    "type": "http.response.start",
                    "status": status_code[0],
                    "headers": response_headers[0]
                })
                await send({
                    "type": "http.response.body",
                    "body": full_body,
                    "more_body": False
                })

            # Cache the response on successful GET
            if self.cache_enabled and method == "GET" and status_code[0] == 200 and cache_key:
                global_cache.set(cache_key, CachedResponse(status_code[0], response_headers[0], full_body), self.cache_ttl)

            if self.logging and audit_start_time is not None:
                duration_ms = end_audit_timer(audit_start_time)
                if self.logging.get("audit"): log_audit(method, path, status_code[0], duration_ms)
                threshold = self.logging.get("performance_threshold_ms")
                if threshold and duration_ms > threshold:
                    log_performance_warning(method, path, duration_ms, threshold)
                
        except Exception as e:
            masked_payload, tracking_id = handle_exception(e)
            error_body = json.dumps(masked_payload).encode("utf-8")
            
            if self.logging and audit_start_time is not None:
                duration_ms = end_audit_timer(audit_start_time)
                if self.logging.get("audit"): log_audit(method, path, 500, duration_ms)
                threshold = self.logging.get("performance_threshold_ms")
                if threshold and duration_ms > threshold:
                    log_performance_warning(method, path, duration_ms, threshold)
            
            if not is_crypto_active or not response_headers[0]: # Ensure start hasn't been sent if active
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
    Provides plug-and-play sanitization, error masking, caching, and transparent field encryption.
    """
    def __init__(self, app, cache_enabled: bool = False, cache_ttl: float = 60.0, key_generator = None, crypto_secret: str = None, crypto_fields: list = None, validation_schema: dict = None, logging: dict = None):
        self.app = app
        self.cache_enabled = cache_enabled
        self.cache_ttl = cache_ttl
        self.key_generator = key_generator
        self.crypto_secret = crypto_secret
        self.crypto_fields = crypto_fields or []
        self.validation_schema = validation_schema
        self.logging = logging

    def __call__(self, environ, start_response):
        audit_start_time = start_audit_timer() if self.logging else None
        is_crypto_active = bool(self.crypto_secret and self.crypto_fields)

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
                if self.logging and audit_start_time is not None:
                    duration_ms = end_audit_timer(audit_start_time)
                    if self.logging.get("audit"): log_audit(method, path, cached.status, duration_ms)
                start_response(f"{cached.status} OK", cached.headers)
                return [cached.body]

        # 3. Sanitize and Encrypt Request Body
        content_length = int(environ.get("CONTENT_LENGTH", 0) or 0)
        if content_length > 0 and method in ("POST", "PUT", "PATCH"):
            body = environ["wsgi.input"].read(content_length)
            content_type = environ.get("CONTENT_TYPE", "")
            
            sanitized_body = body
            if "application/json" in content_type:
                try:
                    data = json.loads(body.decode("utf-8"))
                    if self.validation_schema:
                        is_valid, errors = validate_payload(data, self.validation_schema)
                        if not is_valid:
                            error_body = json.dumps({"status": "error", "errors": errors}).encode("utf-8")
                            if self.logging and audit_start_time is not None:
                                duration_ms = end_audit_timer(audit_start_time)
                                if self.logging.get("audit"): log_audit(method, path, 400, duration_ms)
                            start_response("400 Bad Request", [("Content-Type", "application/json"), ("Content-Length", str(len(error_body)))])
                            return [error_body]
                    sanitized_data = sanitize(data)
                    if is_crypto_active:
                        sanitized_data = process_crypto_fields(sanitized_data, self.crypto_fields, True, self.crypto_secret)
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
            if not is_crypto_active:
                return start_response(status, response_headers, exc_info)
            return lambda body: None

        try:
            response_iterable = self.app(environ, custom_start_response)
            body_chunks = []
            for chunk in response_iterable:
                body_chunks.append(chunk)
            
            full_body = b"".join(body_chunks)

            # 5. Response Decryption
            if is_crypto_active:
                content_type = next((v for k, v in captured_headers[0] if k.lower() == "content-type"), "")
                if "application/json" in content_type:
                    try:
                        res_data = json.loads(full_body.decode("utf-8"))
                        decrypted_data = process_crypto_fields(res_data, self.crypto_fields, False, self.crypto_secret)
                        full_body = json.dumps(decrypted_data).encode("utf-8")
                        new_headers = []
                        for k, v in captured_headers[0]:
                            if k.lower() == "content-length":
                                new_headers.append((k, str(len(full_body))))
                            else:
                                new_headers.append((k, v))
                        captured_headers[0] = new_headers
                    except Exception:
                        pass
                
                # Forward delayed headers
                start_response(captured_status[0], captured_headers[0])

            # Cache the response on successful GET
            if self.cache_enabled and method == "GET" and captured_status[0] and captured_status[0].startswith("200") and cache_key:
                try:
                    status_code = int(captured_status[0].split()[0])
                except Exception:
                    status_code = 200
                global_cache.set(cache_key, CachedResponse(status_code, captured_headers[0], full_body), self.cache_ttl)

            if self.logging and audit_start_time is not None:
                duration_ms = end_audit_timer(audit_start_time)
                try:
                    final_status = int(captured_status[0].split()[0])
                except Exception:
                    final_status = 200
                if self.logging.get("audit"): log_audit(method, path, final_status, duration_ms)
                threshold = self.logging.get("performance_threshold_ms")
                if threshold and duration_ms > threshold:
                    log_performance_warning(method, path, duration_ms, threshold)

            return [full_body]

        except Exception as e:
            masked_payload, tracking_id = handle_exception(e)
            error_body = json.dumps(masked_payload).encode("utf-8")
            
            if self.logging and audit_start_time is not None:
                duration_ms = end_audit_timer(audit_start_time)
                if self.logging.get("audit"): log_audit(method, path, 500, duration_ms)
                threshold = self.logging.get("performance_threshold_ms")
                if threshold and duration_ms > threshold:
                    log_performance_warning(method, path, duration_ms, threshold)
                    
            start_response("500 Internal Server Error", [("Content-Type", "application/json")])
            return [error_body]
