import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { vibeShield } from '../src/core/wrapper.js';
import { globalCache } from '../src/core/cache.js';

describe('VibeShield Core Wrapper (Module A)', () => {
  beforeEach(() => {
    globalCache.clear();
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should pass through responses from a valid handler', async () => {
    const handler = () => new Response('ok', { status: 200 });
    const wrapped = vibeShield(handler);

    const req = new Request('http://localhost:3000/api/users');
    const response = await wrapped(req);

    expect(response.status).toBe(200);
    expect(await response.text()).toBe('ok');
  });

  it('should intercept and sanitize request JSON body', async () => {
    const handler = async (req: Request) => {
      const body = await req.json();
      return Response.json(body);
    };

    const wrapped = vibeShield(handler);

    // SQLi and XSS payloads in body
    const bodyPayload = {
      username: "<script>alert(1)</script>admin",
      query: "1' OR 1=1 --",
      $where: "malicious code" // NoSQL operator key
    };

    const req = new Request('http://localhost:3000/api/login', {
      method: 'POST',
      body: JSON.stringify(bodyPayload),
      headers: { 'Content-Type': 'application/json' }
    });

    const response = await wrapped(req);
    const result = await response.json();

    expect(result.username).toBe('admin'); // tag stripped
    expect(result.query).toBe("1'' OR 1=1 __"); // single quote escaped, comment stripped
    expect(result.$where).toBeUndefined(); // MongoDB dollar-operator key removed
  });

  it('should intercept and sanitize request URL searchParams', async () => {
    const handler = (req: Request) => {
      const url = new URL(req.url);
      return Response.json({
        user: url.searchParams.get('user'),
        id: url.searchParams.get('id')
      });
    };

    const wrapped = vibeShield(handler);

    const req = new Request('http://localhost:3000/api/users?user=<script>alert(1)</script>john&id=1\' or 1=1');
    const response = await wrapped(req);
    const result = await response.json();

    expect(result.user).toBe('john'); // tag stripped
    expect(result.id).toBe("1'' or 1=1"); // SQLi quotes escaped
  });

  it('should sanitize Next.js 13/14 dynamic context parameters (plain object)', async () => {
    const handler = (req: Request, ctx: any) => {
      return Response.json(ctx.params);
    };

    const wrapped = vibeShield(handler);

    const req = new Request('http://localhost:3000/api/users');
    const context = {
      params: {
        userId: "<img src=x onerror=alert(1)>123",
        role: "admin"
      }
    };

    const response = await wrapped(req, context);
    const params = await response.json();

    expect(params.userId).toBe('123'); // XSS tag stripped
    expect(params.role).toBe('admin');
  });

  it('should sanitize Next.js 15 dynamic context parameters (Promise)', async () => {
    const handler = async (req: Request, ctx: any) => {
      const params = await ctx.params;
      return Response.json(params);
    };

    const wrapped = vibeShield(handler);

    const req = new Request('http://localhost:3000/api/users');
    const context = {
      params: Promise.resolve({
        userId: "5' OR '1'='1",
        $operator: "should be stripped"
      })
    };

    const response = await wrapped(req, context);
    const params = await response.json();

    expect(params.userId).toBe("5'' OR ''1''=''1"); // SQLi escaped
    expect(params.$operator).toBeUndefined(); // Mongo operator stripped
  });

  it('should cache GET requests and serve them on cache hit', async () => {
    let callCount = 0;
    const handler = () => {
      callCount++;
      return new Response(`count: ${callCount}`, { status: 200 });
    };

    // Enable cache
    const wrapped = vibeShield(handler, { cache: { enabled: true, ttl: 10 } });

    const req1 = new Request('http://localhost:3000/api/users', { method: 'GET' });
    const response1 = await wrapped(req1);
    expect(await response1.text()).toBe('count: 1');

    // Yield control to let the non-blocking background cache serialization finish
    await new Promise(resolve => setTimeout(resolve, 10));

    // Second call should return cached response, handler is not called again
    const req2 = new Request('http://localhost:3000/api/users', { method: 'GET' });
    const response2 = await wrapped(req2);
    expect(await response2.text()).toBe('count: 1');
    expect(callCount).toBe(1);
  });

  it('should sort query parameters for consistent cache keys and prevent cache poisoning', async () => {
    let callCount = 0;
    const handler = () => {
      callCount++;
      return new Response(`count: ${callCount}`, { status: 200 });
    };

    const wrapped = vibeShield(handler, { cache: { enabled: true, ttl: 10 } });

    const req1 = new Request('http://localhost:3000/api/users?b=2&a=1', { method: 'GET' });
    const response1 = await wrapped(req1);
    expect(await response1.text()).toBe('count: 1');

    await new Promise(resolve => setTimeout(resolve, 10));

    const req2 = new Request('http://localhost:3000/api/users?a=1&b=2', { method: 'GET' });
    const response2 = await wrapped(req2);
    expect(await response2.text()).toBe('count: 1');
    expect(callCount).toBe(1);
  });

  it('should not cache POST requests', async () => {
    let callCount = 0;
    const handler = () => {
      callCount++;
      return new Response(`count: ${callCount}`, { status: 200 });
    };

    const wrapped = vibeShield(handler, { cache: { enabled: true, ttl: 10 } });

    const req1 = new Request('http://localhost:3000/api/users', { method: 'POST' });
    const response1 = await wrapped(req1);
    expect(await response1.text()).toBe('count: 1');

    const req2 = new Request('http://localhost:3000/api/users', { method: 'POST' });
    const response2 = await wrapped(req2);
    expect(await response2.text()).toBe('count: 2');
    expect(callCount).toBe(2);
  });

  it('should intercept unhandled errors and return a masked error response', async () => {
    const handler = () => {
      throw new Error('Fatal DB crash!');
    };

    const wrapped = vibeShield(handler);

    const req = new Request('http://localhost:3000/api/users');
    const response = await wrapped(req);

    expect(response.status).toBe(500);
    const body = await response.json();
    expect(body.error).toBe('Internal Server Error');
    expect(body.message).toContain('VS-');
    expect(body.message).not.toContain('Fatal DB crash!');
  });
});
