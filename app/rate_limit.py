"""Fixed-window rate limiter backed by Redis, with an in-memory fallback.

Redis is used when REDIS_PORT is configured and reachable, so limits are shared across
API instances. Without Redis the limiter still works, but only per process.
"""

import logging
import threading
import time

import redis
from fastapi import HTTPException, Request, status

log = logging.getLogger("balancevault.ratelimit")


class RateLimiter:
    def __init__(self) -> None:
        self._redis: redis.Redis | None = None
        self._memory: dict[str, tuple[int, float]] = {}
        self._lock = threading.Lock()

    @property
    def backend(self) -> str:
        return "redis" if self._redis is not None else "memory"

    def init(self, host: str | None, port: int = 6379, password: str | None = None, db: int = 0) -> None:
        if not host:
            log.warning("REDIS_PORT not set - using in-memory rate limiting (single instance only)")
            return
        client = redis.Redis(
            host=host,
            port=port,
            password=password or None,
            db=db,
            socket_timeout=1,
            socket_connect_timeout=1,
        )
        try:
            client.ping()
            self._redis = client
            log.info("Rate limiter connected to Redis at %s:%s", host, port)
        except redis.RedisError as exc:
            log.warning("Redis at %s:%s unavailable (%s) - falling back to in-memory rate limiting", host, port, exc)

    def ping(self) -> bool | None:
        """True/False for Redis health, None when Redis is not configured."""
        if self._redis is None:
            return None
        try:
            return bool(self._redis.ping())
        except redis.RedisError:
            return False

    def hit(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        """Register one hit. Returns (allowed, retry_after_seconds)."""
        key = f"bv:rl:{key}"
        if self._redis is not None:
            try:
                pipe = self._redis.pipeline()
                pipe.incr(key)
                pipe.expire(key, window, nx=True)
                pipe.ttl(key)
                count, _, ttl = pipe.execute()
                return count <= limit, max(int(ttl), 1)
            except redis.RedisError as exc:
                log.error("Redis error during rate limiting, using memory: %s", exc)
        return self._hit_memory(key, limit, window)

    def _hit_memory(self, key: str, limit: int, window: int) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            count, reset_at = self._memory.get(key, (0, now + window))
            if now >= reset_at:
                count, reset_at = 0, now + window
            count += 1
            self._memory[key] = (count, reset_at)
            if len(self._memory) > 50_000:  # crude memory bound
                self._memory = {k: v for k, v in self._memory.items() if v[1] > now}
        return count <= limit, max(int(reset_at - now), 1)

    def reset(self) -> None:
        with self._lock:
            self._memory.clear()


limiter = RateLimiter()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def enforce(key: str, limit: int, window: int) -> None:
    allowed, retry_after = limiter.hit(key, limit, window)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
