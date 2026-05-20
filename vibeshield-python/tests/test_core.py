import pytest
import json
import httpx
from fastapi import FastAPI, Request
from flask import Flask, request as flask_request, jsonify
from httpx import AsyncClient

from src.core import VibeShieldASGIMiddleware, VibeShieldWSGIMiddleware, global_cache

# ==========================================
# 1. FASTAPI (ASGI) INTEGRATION TESTS
# ==========================================

@pytest.mark.asyncio
async def test_fastapi_sanitization():
    app = FastAPI()
    app.add_middleware(VibeShieldASGIMiddleware)

    @app.post("/login")
    async def login(request: Request):
        data = await request.json()
        return {"data": data}

    @app.get("/search")
    async def search(request: Request):
        params = dict(request.query_params)
        return {"params": params}

    # In modern HTTPX, we use ASGITransport to wrap ASGI apps
    async with AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        # Check Body Sanitization (SQLi + NoSQLi)
        payload = {"username": "admin' OR '1'='1", "password": {"$ne": "pwd"}}
        res = await ac.post("/login", json=payload)
        assert res.status_code == 200
        assert res.json()["data"]["username"] == "admin'' OR ''1''=''1"
        assert res.json()["data"]["password"] == {}

        # Check Query String Sanitization (XSS)
        res = await ac.get("/search", params={"q": "<script>alert(1)</script>SafeText"})
        assert res.status_code == 200
        assert res.json()["params"]["q"] == "SafeText"


@pytest.mark.asyncio
async def test_fastapi_error_masking():
    app = FastAPI()
    app.add_middleware(VibeShieldASGIMiddleware)

    @app.get("/error")
    async def error_route():
        raise RuntimeError("Secret DB Key Leaked: 12345!")

    async with AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/error")
        assert res.status_code == 500
        data = res.json()
        assert data["success"] is False
        assert data["message"] == "Internal Server Error"
        assert "Secret DB Key" not in data["message"]
        assert "tracking_id" in data


@pytest.mark.asyncio
async def test_fastapi_caching():
    global_cache.clear()
    app = FastAPI()
    # Enable cache with 5s TTL
    app.add_middleware(VibeShieldASGIMiddleware, cache_enabled=True, cache_ttl=5.0)

    call_count = 0

    @app.get("/data")
    async def get_data():
        nonlocal call_count
        call_count += 1
        return {"count": call_count}

    async with AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        # First request - Cache miss
        res1 = await ac.get("/data")
        assert res1.json()["count"] == 1

        # Second request - Cache hit
        res2 = await ac.get("/data")
        assert res2.json()["count"] == 1
        assert call_count == 1


# ==========================================
# 2. FLASK (WSGI) INTEGRATION TESTS
# ==========================================

def test_flask_sanitization():
    app = Flask(__name__)
    app.wsgi_app = VibeShieldWSGIMiddleware(app.wsgi_app)

    @app.route("/login", methods=["POST"])
    def login():
        return jsonify({"data": flask_request.json})

    @app.route("/search", methods=["GET"])
    def search():
        return jsonify({"params": dict(flask_request.args)})

    client = app.test_client()

    # Check Body Sanitization (SQLi + NoSQLi)
    payload = {"username": "admin' OR '1'='1", "password": {"$ne": "pwd"}}
    res = client.post("/login", json=payload)
    assert res.status_code == 200
    assert res.json["data"]["username"] == "admin'' OR ''1''=''1"
    assert res.json["data"]["password"] == {}

    # Check Query String Sanitization (XSS)
    res = client.get("/search?q=<script>alert(1)</script>SafeText")
    assert res.status_code == 200
    assert res.json["params"]["q"] == "SafeText"


def test_flask_error_masking():
    app = Flask(__name__)
    # Allow exceptions to propagate out of Flask WSGI internals so our middleware can catch them
    app.config["PROPAGATE_EXCEPTIONS"] = True
    app.wsgi_app = VibeShieldWSGIMiddleware(app.wsgi_app)

    @app.route("/error")
    def error_route():
        raise RuntimeError("Secret Flask Session Leaked: key_abc!")

    client = app.test_client()
    res = client.get("/error")
    assert res.status_code == 500
    data = res.json
    assert data["success"] is False
    assert data["message"] == "Internal Server Error"
    assert "Secret Flask Session" not in data["message"]
    assert "tracking_id" in data


def test_flask_caching():
    global_cache.clear()
    app = Flask(__name__)
    app.wsgi_app = VibeShieldWSGIMiddleware(app.wsgi_app, cache_enabled=True, cache_ttl=5.0)

    call_count = 0

    @app.route("/data")
    def get_data():
        nonlocal call_count
        call_count += 1
        return jsonify({"count": call_count})

    client = app.test_client()

    # First request - Cache miss
    res1 = client.get("/data")
    assert res1.json["count"] == 1

    # Second request - Cache hit
    res2 = client.get("/data")
    assert res2.json["count"] == 1
    assert call_count == 1
