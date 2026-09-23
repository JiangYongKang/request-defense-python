"""令牌桶限流：突发边界、补充、并发严格计数、资源有界。"""
from __future__ import annotations

import threading

import pytest

from request_defense.ratelimit import RateLimiter


def test_exact_burst_boundary():
    rl = RateLimiter(rate_per_second=1000, burst=5)
    allowed = [rl.check("c", now=100.0).allowed for _ in range(5)]
    assert allowed == [True] * 5
    sixth = rl.check("c", now=100.0)
    assert sixth.allowed is False
    assert sixth.reason == "rate_limited"
    assert 0 < sixth.retry_after_seconds <= 0.002  # 1/1000 s 量级，重试提示合理


def test_refill_respects_average_rate():
    rl = RateLimiter(rate_per_second=10, burst=5)
    for _ in range(5):
        assert rl.check("c", now=0.0).allowed
    assert not rl.check("c", now=0.0).allowed
    # 0.5s 补 5 个令牌
    for _ in range(5):
        assert rl.check("c", now=0.5).allowed
    assert not rl.check("c", now=0.5).allowed


def test_rejected_request_does_not_consume_tokens():
    rl = RateLimiter(rate_per_second=1, burst=1)
    assert rl.check("c", now=0.0).allowed
    r1 = rl.check("c", now=0.0)
    r2 = rl.check("c", now=0.0)
    assert not r1.allowed and not r2.allowed
    # 两次拒绝后重试时间不应被放大（拒绝不扣费）
    assert abs(r1.retry_after_seconds - r2.retry_after_seconds) < 1e-9


def test_clients_are_isolated():
    rl = RateLimiter(rate_per_second=1, burst=1)
    assert rl.check("a", now=0.0).allowed
    assert rl.check("b", now=0.0).allowed
    assert not rl.check("a", now=0.0).allowed
    assert not rl.check("b", now=0.0).allowed


@pytest.mark.parametrize("workers,hits", [(8, 200), (32, 500), (64, 1000)])
def test_concurrent_no_dup_no_miss_no_drift(workers, hits):
    """高并发临界：允许数必须恰好等于 burst，总判定数恰好等于请求总数。"""
    burst = 37
    rl = RateLimiter(rate_per_second=10 ** 9, burst=burst)  # 窗口内不补充
    counts: list[tuple[int, int]] = []
    lock = threading.Lock()

    def worker() -> None:
        allowed = denied = 0
        for _ in range(hits):
            if rl.check("hot-client", now=1.0).allowed:
                allowed += 1
            else:
                denied += 1
        with lock:
            counts.append((allowed, denied))

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total_allowed = sum(a for a, _ in counts)
    total_denied = sum(d for _, d in counts)
    assert total_allowed == burst
    assert total_allowed + total_denied == workers * hits


def test_lru_hard_cap_never_exceeded():
    rl = RateLimiter(rate_per_second=1, burst=5, max_clients=10,
                     idle_ttl=10 ** 9, sweep_interval=10 ** 9)
    for i in range(10_000):
        rl.check(f"client-{i}", now=0.0)
        assert rl.active_clients() <= 10
    assert rl.active_clients() == 10


def test_idle_ttl_reclaims():
    rl = RateLimiter(rate_per_second=1, burst=5, idle_ttl=30, sweep_interval=0)
    rl.check("old", now=0.0)
    rl.check("new", now=31.0)
    assert "old" not in rl._buckets
    assert rl.active_clients() == 1


def test_massive_identity_churn_is_bounded():
    rl = RateLimiter(rate_per_second=10, burst=10, max_clients=500,
                     idle_ttl=1, sweep_interval=0)
    for i in range(200_000):
        rl.check(f"id-{i}", now=float(i) / 1000.0)
    assert rl.active_clients() <= 500
