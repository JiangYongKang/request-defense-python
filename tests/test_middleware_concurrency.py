"""ASGI 事件循环 + 线程池混合并发下的限流一致性。"""
from __future__ import annotations

import asyncio

import pytest

from request_defense.config import DefenseConfig
from request_defense.middleware import DefenseMiddleware
from tests.conftest import call_asgi

from fastapi import FastAPI

pytestmark = pytest.mark.anyio


def _app():
    inner = FastAPI()

    @inner.get("/")
    def root():
        return {"ok": True}

    return DefenseMiddleware(inner, config=DefenseConfig(
        # 补充速率取极小值：整个测试窗口（亚秒级）补不回 1 个令牌，
        # 从而在真实时钟下得到确定性的临界判定。
        rate_per_second=1e-6, burst=25,
        max_clients=10, client_idle_ttl_seconds=300.0))


async def test_async_concurrent_exact_burst(decision_logs):
    app = _app()

    async def one(i):
        return await call_asgi(app, "GET", "http://t/",
                               client=("203.0.113.9", 40000 + i))

    results = await asyncio.gather(*(one(i) for i in range(500)))
    codes = [r.status_code for r in results]
    assert codes.count(200) == 25
    assert codes.count(429) == 475
    # 所有拒绝原因可区分且一致
    bodies = [r.json() for r in results if r.status_code == 429]
    assert {b["error"] for b in bodies} == {"rate_limited"}
    assert all(b["retryable"] for b in bodies)


async def test_concurrent_with_spoofed_xff_still_aggregated(decision_logs):
    """500 个并发请求，每个伪造不同 XFF、同一不可信 peer：只允许 burst 个。"""
    inner = FastAPI()

    @inner.get("/")
    def root():
        return {"ok": True}

    app = DefenseMiddleware(inner, config=DefenseConfig(
        rate_per_second=1e-6, burst=10,
        trusted_proxies=("10.0.0.1",)))

    async def one(i):
        return await call_asgi(
            app, "GET", "http://t/",
            headers=[("x-forwarded-for", f"172.{i // 256}.{i % 256}.1")],
            client=("203.0.113.9", 40000 + i))

    results = await asyncio.gather(*(one(i) for i in range(500)))
    codes = [r.status_code for r in results]
    assert codes.count(200) == 10, codes.count(200)
    assert codes.count(429) == 490
