interface CachedResponse {
  body: Uint8Array;
  status: number;
  statusText: string;
  headers: [string, string][];
  expiresAt: number;
}

export class VibeShieldCache {
  private cache = new Map<string, CachedResponse>();
  private limit: number;
  private defaultTtl: number;

  constructor(limit = 500, defaultTtl = 60) {
    // Ensure limits are strictly within MVP scope (max 500 records, max 60s TTL)
    this.limit = Math.min(limit, 500);
    this.defaultTtl = Math.min(defaultTtl, 60);
  }

  /**
   * Retrieves a reconstructed Response from the cache if hit and valid.
   */
  public get(key: string): Response | null {
    const cached = this.cache.get(key);
    if (!cached) {
      return null;
    }

    // Expiry check
    if (Date.now() > cached.expiresAt) {
      this.cache.delete(key);
      return null;
    }

    // Move to the end of the Map (LRU update)
    this.cache.delete(key);
    this.cache.set(key, cached);

    // Reconstruct the Response object using a Blob wrapping the cached body.
    // This allows the response to be read multiple times on different cache hits
    // without detaching the underlying cached ArrayBuffer.
    return new Response(new Blob([cached.body as any]), {
      status: cached.status,
      statusText: cached.statusText,
      headers: new Headers(cached.headers),
    });
  }

  /**
   * Stores a response in the cache. Clones the response to extract its body without blocking.
   */
  public async set(key: string, response: Response, ttlSeconds = this.defaultTtl): Promise<void> {
    const finalTtl = Math.min(ttlSeconds, 60);

    // Prune any expired entries before checking capacity
    this.pruneExpired();

    // LRU Eviction: Evict the oldest key if limit is reached
    if (this.cache.size >= this.limit && !this.cache.has(key)) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }

    try {
      const responseClone = response.clone();
      const bodyBuffer = await responseClone.arrayBuffer();
      const body = new Uint8Array(bodyBuffer);
      const headersList: [string, string][] = [];
      responseClone.headers.forEach((val, name) => {
        headersList.push([name, val]);
      });

      this.cache.set(key, {
        body,
        status: responseClone.status,
        statusText: responseClone.statusText,
        headers: headersList,
        expiresAt: Date.now() + finalTtl * 1000,
      });
    } catch (e) {
      // Fail silently if response body reading or cloning errors (e.g. body already locked)
    }
  }

  /**
   * Prunes all expired keys from the cache.
   */
  private pruneExpired(): void {
    const now = Date.now();
    for (const [key, cached] of this.cache.entries()) {
      if (now > cached.expiresAt) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Clears all cache entries.
   */
  public clear(): void {
    this.cache.clear();
  }

  /**
   * Returns current cache size.
   */
  public size(): number {
    return this.cache.size;
  }
}

// Global default cache instance
export const globalCache = new VibeShieldCache();
