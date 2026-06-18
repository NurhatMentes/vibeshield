import time
import pytest
from src.cache import VibeShieldCache

def test_cache_set_and_get():
    cache = VibeShieldCache(max_size=3, default_ttl=5.0)
    cache.set("key1", "val1")
    
    assert cache.get("key1") == "val1"
    assert cache.size() == 1

def test_cache_expiration():
    cache = VibeShieldCache(max_size=3, default_ttl=0.1) # 100ms TTL
    cache.set("key1", "val1")
    
    assert cache.get("key1") == "val1"
    time.sleep(0.15)
    
    assert cache.get("key1") is None
    assert cache.size() == 0

def test_cache_lru_eviction():
    # Capacity = 3
    cache = VibeShieldCache(max_size=3, default_ttl=5.0)
    cache.set("key1", "val1")
    cache.set("key2", "val2")
    cache.set("key3", "val3")
    
    assert cache.size() == 3
    
    # Access key1 to make it most recently used
    cache.get("key1")
    
    # Add key4, which should evict key2 (oldest active element since key1 was accessed)
    cache.set("key4", "val4")
    
    assert cache.size() == 3
    assert cache.get("key2") is None # Evicted
    assert cache.get("key1") == "val1"
    assert cache.get("key3") == "val3"
    assert cache.get("key4") == "val4"

def test_cache_clear():
    cache = VibeShieldCache(max_size=3, default_ttl=5.0)
    cache.set("key1", "val1")
    cache.set("key2", "val2")
    
    assert cache.size() == 2
    cache.clear()
    assert cache.size() == 0

def test_cache_ttl_warning(capsys):
    cache = VibeShieldCache(max_size=3, default_ttl=5.0)
    cache.set("key1", "val1", ttl=70.0)
    
    captured = capsys.readouterr()
    assert "[VibeShield Cache] TTL 70.0s exceeds maximum 60s." in captured.err
