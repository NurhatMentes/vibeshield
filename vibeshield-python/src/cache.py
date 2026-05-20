import time
from collections import OrderedDict
from threading import Lock

class CachedResponse:
    """
    Representation of a cached HTTP response, storing status, headers, and binary body.
    """
    def __init__(self, status_code: int, headers: list, body: bytes):
        self.status = status_code
        self.headers = headers
        self.body = body

class VibeShieldCache:
    """
    Thread-safe In-Memory LRU Cache with TTL expiration.
    """
    def __init__(self, max_size: int = 500, default_ttl: float = 60.0):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache = OrderedDict()
        self.lock = Lock()

    def get(self, key: str):
        with self.lock:
            if key not in self.cache:
                return None
            val, expiry = self.cache[key]
            if time.time() > expiry:
                del self.cache[key]
                return None
            # Move to end (Most Recently Used)
            self.cache.move_to_end(key)
            return val

    def set(self, key: str, val, ttl: float = None):
        with self.lock:
            if ttl is None:
                ttl = self.default_ttl
            expiry = time.time() + ttl
            
            if key in self.cache:
                del self.cache[key]
            elif len(self.cache) >= self.max_size:
                # Evict oldest (Least Recently Used)
                self.cache.popitem(last=False)
            
            self.cache[key] = (val, expiry)

    def size(self) -> int:
        with self.lock:
            now = time.time()
            # Clean expired items during size check
            expired_keys = [k for k, (_, exp) in self.cache.items() if now > exp]
            for k in expired_keys:
                del self.cache[k]
            return len(self.cache)

    def clear(self):
        with self.lock:
            self.cache.clear()
