"""按客户端维度的令牌桶限流。

语义：
  * 每客户端一个令牌桶，容量 = burst（瞬时突发上限），
    以 rate_per_second 持续补充令牌（平均速率上限）。
  * 每次判定在同一把全局锁内完成"补充 -> 扣费/拒绝"，
    因此并发下既不会漏计也不会重复计数，更不会出现计数漂移。
  * 内存有界：桶按最近使用做 LRU 淘汰（max_clients），
    空闲超过 idle_ttl 的桶由惰性扫描 + 周期 sweep 回收。
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass


def _monotonic() -> float:
    return time.monotonic()


@dataclass
class RateLimitResult:
    allowed: bool
    client_id: str
    #: 被拒绝时建议的重试等待秒数（0 表示未拒绝）
    retry_after_seconds: float
    tokens_before: float
    tokens_after: float
    reason: str  # "ok" | "rate_limited"


class TokenBucket:
    """单客户端令牌桶；所有调用方需自行保证串行访问。"""

    __slots__ = ("capacity", "refill_per_second", "tokens", "last_refill", "last_seen")

    def __init__(self, capacity: int, refill_per_second: float, now: float) -> None:
        self.capacity = float(capacity)
        self.refill_per_second = refill_per_second
        self.tokens = float(capacity)  # 全新桶：允许打满一个突发
        self.last_refill = now
        self.last_seen = now

    def refill(self, now: float) -> None:
        elapsed = now - self.last_refill
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
            self.last_refill = now

    def take(self, amount: int, now: float) -> tuple[bool, float, float, float]:
        """返回 (allowed, tokens_before, tokens_after, retry_after_seconds)。"""
        self.refill(now)
        before = self.tokens
        if self.tokens + 1e-9 >= amount:
            self.tokens -= amount
            self.last_seen = now
            return True, before, self.tokens, 0.0
        # 令牌不足：不扣任何令牌（拒绝不消耗额度）
        deficit = amount - self.tokens
        retry_after = deficit / self.refill_per_second
        self.last_seen = now
        return False, before, before, retry_after


class RateLimiter:
    """带 LRU 上限与空闲回收的全局限流器，线程安全。"""

    def __init__(self, rate_per_second: float, burst: int,
                 max_clients: int = 100_000, idle_ttl: float = 300.0,
                 sweep_interval: float = 60.0) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second 必须为正数")
        if burst < 1:
            raise ValueError("burst 必须 >= 1")
        if max_clients < 1:
            raise ValueError("max_clients 必须 >= 1")
        self.rate_per_second = rate_per_second
        self.burst = burst
        self.max_clients = max_clients
        self.idle_ttl = idle_ttl
        self.sweep_interval = sweep_interval
        self._buckets: "OrderedDict[str, TokenBucket]" = OrderedDict()
        self._lock = threading.Lock()
        # 惰性初始化为首个请求的时钟，兼容注入时钟与真实单调时钟
        self._last_sweep: float | None = None

    def _get_or_create(self, client_id: str, now: float) -> TokenBucket:
        bucket = self._buckets.get(client_id)
        if bucket is None:
            bucket = TokenBucket(self.burst, self.rate_per_second, now)
            self._buckets[client_id] = bucket
        else:
            # 标记为最近使用
            self._buckets.move_to_end(client_id)
        return bucket

    def _enforce_bounds(self, now: float) -> None:
        """删除空闲超过 TTL 的桶；桶数超上限时再做 LRU 淘汰。

        空闲扫描受 sweep_interval 节流（避免全表扫描）；
        但 LRU 硬上限无论何时都立即执行，保证桶数永不超 max_clients。
        """
        if self._last_sweep is None:
            self._last_sweep = now
        if now - self._last_sweep >= self.sweep_interval:
            self._last_sweep = now
            dead = [cid for cid, b in self._buckets.items()
                    if now - b.last_seen > self.idle_ttl]
            for cid in dead:
                self._buckets.pop(cid, None)
        # 硬性上限：超限则从最久未使用端淘汰
        while len(self._buckets) > self.max_clients:
            self._buckets.popitem(last=False)

    def check(self, client_id: str, now: float | None = None) -> RateLimitResult:
        current = _monotonic() if now is None else now
        with self._lock:
            bucket = self._get_or_create(client_id, current)
            self._enforce_bounds(current)
            allowed, before, after, retry_after = bucket.take(1, current)
        if allowed:
            return RateLimitResult(True, client_id, 0.0, before, after, "ok")
        return RateLimitResult(False, client_id, max(retry_after, 0.001),
                               before, after, "rate_limited")

    def active_clients(self) -> int:
        with self._lock:
            return len(self._buckets)

    def reset(self) -> None:
        """仅供测试使用。"""
        with self._lock:
            self._buckets.clear()
            self._last_sweep = None
