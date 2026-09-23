"""Per-client token-bucket rate limiter (average rate + burst), concurrency safe.

Model
-----
Each client owns one token bucket:

* ``burst``      -> bucket capacity, i.e. maximum instant concurrency accepted.
* ``rate_per_sec`` -> refill speed, i.e. sustainable average rate (req/s).

Every request atomically takes one token under a single lock, so concurrent
threads can never double-count, skip a count, or drift.  Buckets that have
been idle long enough to refill completely hold no information and are
reaped; if the client table is still full after reaping, the least recently
used bucket is evicted, keeping memory bounded by ``max_clients``.
"""

import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitConfig:
    rate_per_sec: float
    burst: int


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    remaining: int
    retry_after: float          # fractional seconds; 0 when allowed
    limit: int                  # burst size (echoed in RateLimit headers)
    evicted: bool = False       # True when an LRU bucket had to make room

    @property
    def retry_after_seconds(self) -> int:
        """Integer seconds usable for the Retry-After header (>= 1 when denied)."""
        return max(1, math.ceil(self.retry_after))


class TokenBucket:
    """A single refill-on-demand token bucket. All methods are lock-guarded."""

    def __init__(self, rate_per_sec: float, burst: int, clock=time.monotonic):
        if rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be > 0")
        if burst <= 0:
            raise ValueError("burst must be > 0")
        self.rate = float(rate_per_sec)
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.last = clock()
        self._clock = clock

    def _refill(self, now: float) -> None:
        elapsed = now - self.last
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last = now

    def is_full(self, now: float) -> bool:
        self._refill(now)
        return self.tokens >= self.capacity

    def take(self, tokens: float = 1.0) -> tuple[bool, int, float]:
        """Try to take ``tokens``. Returns (allowed, remaining, retry_after)."""
        now = self._clock()
        self._refill(now)
        if self.tokens + 1e-9 >= tokens:
            self.tokens -= tokens
            return True, int(self.tokens), 0.0
        deficit = tokens - self.tokens
        return False, int(self.tokens), deficit / self.rate


class RateLimiter:
    """Maps client ids to token buckets; bounded size, thread safe."""

    def __init__(
        self,
        config: RateLimitConfig,
        max_clients: int = 10_000,
        idle_ttl: float | None = None,
        clock=time.monotonic,
    ):
        if max_clients <= 0:
            raise ValueError("max_clients must be > 0")
        self.config = config
        self.max_clients = max_clients
        # Time to fully refill: after that an idle bucket is safe to drop.
        self.idle_ttl = (
            idle_ttl if idle_ttl is not None else config.burst / config.rate_per_sec
        )
        self._clock = clock
        self._buckets: OrderedDict[str, TokenBucket] = OrderedDict()
        self._lock = threading.Lock()

    def _reap_idle(self, now: float) -> int:
        """Drop buckets that have fully refilled after a long idle period."""
        stale = [
            cid
            for cid, bucket in self.buckets_items()
            if now - bucket.last >= self.idle_ttl and bucket.is_full(now)
        ]
        for cid in stale:
            self._buckets.pop(cid, None)
        return len(stale)

    def buckets_items(self):
        return list(self._buckets.items())

    def check(self, client_id: str) -> RateLimitDecision:
        evicted = False
        with self._lock:
            bucket = self._buckets.get(client_id)
            if bucket is None:
                now = self._clock()
                # Bound the table: first reclaim information-free idle buckets.
                if len(self._buckets) >= self.max_clients:
                    self._reap_idle(now)
                # Still full: evict the least recently used active bucket.
                if len(self._buckets) >= self.max_clients:
                    self._buckets.popitem(last=False)
                    evicted = True
                bucket = TokenBucket(
                    self.config.rate_per_sec, self.config.burst, self._clock
                )
                self._buckets[client_id] = bucket
            else:
                self._buckets.move_to_end(client_id)
            allowed, remaining, retry_after = bucket.take(1.0)
            return RateLimitDecision(
                allowed=allowed,
                remaining=remaining,
                retry_after=retry_after,
                limit=self.config.burst,
                evicted=evicted,
            )

    def cleanup(self) -> int:
        """Explicit periodic reaping (safe to call from a background job)."""
        with self._lock:
            return self._reap_idle(self._clock())

    def clients_count(self) -> int:
        with self._lock:
            return len(self._buckets)
