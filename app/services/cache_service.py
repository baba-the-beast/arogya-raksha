import json
import logging
import os
import threading
import time
from typing import Any

logger = logging.getLogger("security.cache")

_redis_client = None
_in_memory_cache: dict[str, Any] = {}
_memory_lock = threading.Lock()


class CacheUnavailableError(RuntimeError):
    """Raised by strict (fail-closed) operations when the distributed cache cannot be reached."""

def get_redis_client():
    """Returns the Redis client singleton if configured."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    redis_url = os.getenv("REDIS_URL") or os.getenv("SESSION_REDIS_URL")
    if redis_url:
        import redis
        try:
            _redis_client = redis.from_url(redis_url, decode_responses=True)
            return _redis_client
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            _redis_client = False # Set to false to avoid repeated connection attempts
            return None
    return None

class CacheService:
    """
    Abstracts distributed caching. Uses Redis if available (production multi-worker),
    otherwise falls back to an in-memory dictionary for local development/testing.
    """

    @classmethod
    def set(cls, key: str, value: Any, ttl_seconds: int = 3600) -> None:
        client = get_redis_client()
        if client:
            try:
                client.set(key, json.dumps(value), ex=ttl_seconds)
                return
            except Exception as e:
                logger.error(f"Redis set failed for {key}: {e}")

        # Fallback
        _in_memory_cache[key] = {
            "value": value,
            "expires_at": time.time() + ttl_seconds
        }

    @classmethod
    def get(cls, key: str) -> Any | None:
        client = get_redis_client()
        if client:
            try:
                val = client.get(key)
                return json.loads(val) if val else None
            except Exception as e:
                logger.error(f"Redis get failed for {key}: {e}")
                return None

        # Fallback
        cached = _in_memory_cache.get(key)
        if cached:
            if time.time() > cached["expires_at"]:
                del _in_memory_cache[key]
                return None
            return cached["value"]
        return None

    @classmethod
    def add_if_absent(cls, key: str, value: Any, ttl_seconds: int) -> bool:
        """
        Atomically stores key only if it does not already exist (Redis SET NX).
        Returns True if stored, False if the key was already present.
        Fails closed: raises CacheUnavailableError if Redis is configured but unreachable.
        """
        client = get_redis_client()
        if client:
            try:
                return bool(client.set(key, json.dumps(value), ex=ttl_seconds, nx=True))
            except Exception as e:
                logger.error(f"Redis SET NX failed for {key}: {e}")
                raise CacheUnavailableError(str(e)) from e

        with _memory_lock:
            cached = _in_memory_cache.get(key)
            if cached and time.time() <= cached["expires_at"]:
                return False
            _in_memory_cache[key] = {"value": value, "expires_at": time.time() + ttl_seconds}
            return True

    @classmethod
    def rpush(cls, key: str, value: Any, ttl_seconds: int = 3600) -> None:
        """Appends to a list (with a TTL on the whole list)."""
        client = get_redis_client()
        if client:
            try:
                pipe = client.pipeline()
                pipe.rpush(key, json.dumps(value))
                pipe.expire(key, ttl_seconds)
                pipe.execute()
                return
            except Exception as e:
                logger.error(f"Redis rpush failed for {key}: {e}")

        # Fallback
        with _memory_lock:
            if key not in _in_memory_cache or time.time() > _in_memory_cache[key].get("expires_at", 0):
                _in_memory_cache[key] = {"value": [], "expires_at": time.time() + ttl_seconds}
            _in_memory_cache[key]["value"].append(value)
            _in_memory_cache[key]["expires_at"] = max(_in_memory_cache[key]["expires_at"], time.time() + ttl_seconds)

    @classmethod
    def lrange(cls, key: str, strict: bool = False) -> list[Any]:
        """Returns the list at key. With strict=True, raises CacheUnavailableError on Redis failure."""
        client = get_redis_client()
        if client:
            try:
                vals = client.lrange(key, 0, -1)
                return [json.loads(v) for v in vals]
            except Exception as e:
                logger.error(f"Redis lrange failed for {key}: {e}")
                if strict:
                    raise CacheUnavailableError(str(e)) from e
                return []

        # Fallback
        cached = _in_memory_cache.get(key)
        if cached and time.time() < cached["expires_at"]:
            return cached["value"]
        return []

    @classmethod
    def delete(cls, key: str) -> None:
        client = get_redis_client()
        if client:
            try:
                client.delete(key)
                return
            except Exception as e:
                logger.error(f"Redis delete failed for {key}: {e}")

        # Fallback
        if key in _in_memory_cache:
            del _in_memory_cache[key]

    @classmethod
    def clear_memory(cls) -> None:
        """Testing utility to clear fallback cache."""
        _in_memory_cache.clear()
