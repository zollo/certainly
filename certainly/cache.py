"""Result caching backed by Redis.

Host results are cached by ``hostname:port`` so that repeated scans (across
different jobs) reuse recent work. If Redis is unavailable the cache silently
degrades to a no-op, so the app keeps working without a cache.
"""
from __future__ import annotations

from typing import Optional

from .models import HostResult

_KEY_PREFIX = "certainly:cache:"


class ResultCache:
    def __init__(self, redis_client, ttl_seconds: int):
        self._redis = redis_client
        self._ttl = ttl_seconds

    @property
    def enabled(self) -> bool:
        return self._redis is not None and self._ttl > 0

    @staticmethod
    def _key(hostname: str, port: int) -> str:
        return f"{_KEY_PREFIX}{hostname.lower()}:{port}"

    def get(self, hostname: str, port: int) -> Optional[HostResult]:
        if not self.enabled:
            return None
        try:
            raw = self._redis.get(self._key(hostname, port))
        except Exception:
            return None
        if not raw:
            return None
        try:
            result = HostResult.model_validate_json(raw)
            result.from_cache = True
            return result
        except Exception:
            return None

    def set(self, result: HostResult) -> None:
        if not self.enabled:
            return
        try:
            payload = result.model_copy(update={"from_cache": False}).model_dump_json()
            self._redis.set(self._key(result.hostname, result.port), payload, ex=self._ttl)
        except Exception:
            # Caching is best-effort; never fail a scan because of it.
            return
