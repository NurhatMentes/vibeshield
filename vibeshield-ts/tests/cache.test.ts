import { describe, it, expect, beforeEach, vi } from 'vitest';
import { VibeShieldCache } from '../src/core/cache.js';

describe('In-Memory Cache Module', () => {
  let cache: VibeShieldCache;

  beforeEach(() => {
    // Limit cache to 3 elements and default TTL of 1 second for testing
    cache = new VibeShieldCache(3, 1);
    vi.useFakeTimers();
  });

  it('should store and retrieve cached response', async () => {
    const res = new Response('hello world', {
      status: 200,
      headers: { 'Content-Type': 'text/plain', 'X-Custom': 'test' },
    });

    await cache.set('key-1', res);

    const hit = cache.get('key-1');
    expect(hit).not.toBeNull();
    expect(await hit!.text()).toBe('hello world');
    expect(hit!.status).toBe(200);
    expect(hit!.headers.get('Content-Type')).toBe('text/plain');
    expect(hit!.headers.get('X-Custom')).toBe('test');
  });

  it('should expire entries after TTL', async () => {
    const res = new Response('data');
    await cache.set('key-1', res, 1); // 1s TTL

    // Immediately available
    expect(cache.get('key-1')).not.toBeNull();

    // Fast-forward time by 1.1 seconds
    vi.advanceTimersByTime(1100);

    expect(cache.get('key-1')).toBeNull();
  });

  it('should evict Least Recently Used (LRU) item when exceeding capacity', async () => {
    // Limit is 3
    const res1 = new Response('val1');
    const res2 = new Response('val2');
    const res3 = new Response('val3');
    const res4 = new Response('val4');

    await cache.set('key-1', res1);
    await cache.set('key-2', res2);
    await cache.set('key-3', res3);

    expect(cache.size()).toBe(3);

    // Access key-1 to make it recently used
    cache.get('key-1');

    // Add key-4, which should trigger eviction of key-2 (since key-1 was refreshed, and key-2 is now the oldest)
    await cache.set('key-4', res4);

    expect(cache.size()).toBe(3);
    expect(cache.get('key-2')).toBeNull(); // Evicted!
    expect(cache.get('key-1')).not.toBeNull(); // Preserved!
    expect(cache.get('key-3')).not.toBeNull(); // Preserved!
    expect(cache.get('key-4')).not.toBeNull(); // Preserved!
  });

  it('should reconstruct independent response objects', async () => {
    const res = new Response('data');
    await cache.set('key-1', res);

    const hit1 = cache.get('key-1')!;
    const hit2 = cache.get('key-1')!;

    // Can read body of multiple hits (standard response body cannot be read twice)
    expect(await hit1.text()).toBe('data');
    expect(await hit2.text()).toBe('data');
    expect(hit1).not.toBe(hit2); // different instances
  });

  it('should warn when TTL exceeds 60 seconds', async () => {
    const consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const res = new Response('data');
    await cache.set('key-1', res, 70);
    
    expect(consoleWarnSpy).toHaveBeenCalledWith(
      expect.stringContaining('[VibeShield Cache] TTL 70s exceeds maximum 60s.')
    );
    consoleWarnSpy.mockRestore();
  });
});
