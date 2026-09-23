"""Tests for the token-bucket limiter: exact counts, concurrency, boundedness."""

import threading

import pytest

from defense.ratelimit import RateLimitConfig, RateLimiter, TokenBucket


class FakeClock:
    def __init__(self):
        self.t = 1000.0
        self.lock = threading.Lock()

    def __call__(self):
        return self.t

    def advance(self, dt):
        with self.lock:
            self.t += dt


def test_burst_then_refill():
    clk = FakeClock()
    rl = RateLimiter(RateLimitConfig(rate_per_sec=5, burst=3), clock=clk)
    for _ in range(3):
        d = rl.check("c1")
        assert d.allowed
    d = rl.check("c1")
    assert not d.allowed
    assert 0.19 <= d.retry_after <= 0.21
    clk.advance(0.2)
    assert rl.check("c1").allowed
    # another client is independent
    assert rl.check("c2").allowed


def test_concurrent_no_lost_or_double_count():
    rl = RateLimiter(RateLimitConfig(rate_per_sec=1.0, burst=100), max_clients=1000)
    results = []
    lock = threading.Lock()

    def worker():
        local = [rl.check("same-client").allowed for _ in range(20)]
        with lock:
            results.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 200
    assert sum(results) == 100          # exactly burst accepted, not one more/less
    assert results.count(False) == 100


def test_idle_buckets_reaped():
    clk = FakeClock()
    rl = RateLimiter(RateLimitConfig(rate_per_sec=1, burst=2), clock=clk)
    rl.check("a")
    clk.advance(10)
    assert rl.cleanup() == 1
    assert rl.clients_count() == 0


def test_lru_eviction_bounds_memory():
    clk = FakeClock()
    rl = RateLimiter(RateLimitConfig(rate_per_sec=1, burst=100), max_clients=3, clock=clk)
    for cid in ("a", "b", "c"):
        rl.check(cid)
    d = rl.check("d")
    assert d.evicted
    assert rl.clients_count() == 3
    # active clients never lose state just because new identities appear
    d_b = rl.check("b")
    assert d_b.allowed and d_b.remaining == 98


def test_invalid_config_rejected():
    with pytest.raises(ValueError):
        TokenBucket(0, 1)
    with pytest.raises(ValueError):
        TokenBucket(1, 0)
    with pytest.raises(ValueError):
        RateLimiter(RateLimitConfig(1, 1), max_clients=0)


def test_memory_bounded_under_massive_identity_churn():
    # No idle reaping possible (all buckets visited within ttl window),
    # so the LRU backstop must keep the table at exactly max_clients.
    clk = FakeClock()
    rl = RateLimiter(RateLimitConfig(rate_per_sec=1000, burst=10), max_clients=500,
                     idle_ttl=10_000, clock=clk)
    for i in range(50_000):
        d = rl.check(f"client-{i}")
        assert d.allowed
    assert rl.clients_count() == 500
