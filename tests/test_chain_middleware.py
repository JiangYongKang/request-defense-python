"""多级链路场景的端到端验证：chain 身份 -> 规则 -> 限流 -> 本地历史。"""
from __future__ import annotations

import asyncio

import pytest

from fastapi import FastAPI, Request

from request_defense.config import DefenseConfig
from request_defense.middleware import DefenseMiddleware
from tests.conftest import call_asgi

pytestmark = pytest.mark.anyio


def _make_app(**kwargs) -> DefenseMiddleware:
    config = DefenseConfig(forward_trust_mode="chain", **kwargs)
    inner = FastAPI()

    @inner.get("/")
    def root():
        return {"Hello": "World"}

    @inner.get("/__defense/decisions")
    def decisions(request: Request, limit: int = 20):
        mw: DefenseMiddleware = request.scope["defense_middleware"]
        return {
            "enabled": mw.config.decision_history_size > 0,
            "capacity": mw.config.decision_history_size,
            "stored": len(mw.history),
            "records": mw.history.recent(limit),
        }

    return DefenseMiddleware(inner, config=config)


async def test_chain_identity_drives_rate_limit(decision_logs):
    """两层可信代理下，真实客户端经边界识别后按同一维度限流。"""
    app = _make_app(rate_per_second=1e-6, burst=2,
                    trusted_proxies=("10.0.0.0/8",), proxy_hop_count=2)
    common_peer = ("10.0.0.1", 80)
    r1 = await call_asgi(
        app, "GET", "http://t/",
        headers=[("x-forwarded-for", "203.0.113.9, 10.0.0.2")],
        client=common_peer)
    r2 = await call_asgi(
        app, "GET", "http://t/",
        headers=[("x-forwarded-for", "203.0.113.9, 10.0.0.2")],
        client=common_peer)
    r3 = await call_asgi(
        app, "GET", "http://t/",
        # 客户端自填不同左段，真实边界地址不变
        headers=[("x-forwarded-for", "8.8.8.8, 203.0.113.9, 10.0.0.2")],
        client=common_peer)
    assert [r.status_code for r in (r1, r2, r3)] == [200, 200, 429]
    assert decision_logs.last["input"]["client_id"] == "203.0.113.9"
    assert (decision_logs.last["input"]["identity_reason"]
            == "chain_client_at_trust_boundary")
    assert decision_logs.last["input"]["trust_boundary_index"] == 2


async def test_untrusted_midhop_fallback_still_rate_limited(decision_logs):
    """中间跳不可信 -> 回退到可信代理地址聚合，攻击者无法借用他人配额。"""
    app = _make_app(rate_per_second=1e-6, burst=1,
                    trusted_proxies=("10.0.0.0/8",), proxy_hop_count=3)
    args = dict(client=("10.0.0.1", 80))
    r1 = await call_asgi(
        app, "GET", "http://t/",
        headers=[("x-forwarded-for", "203.0.113.9, 192.168.5.5, 10.0.0.2")],
        **args)
    r2 = await call_asgi(
        app, "GET", "http://t/",
        headers=[("x-forwarded-for", "7.7.7.7, 192.168.5.5, 10.0.0.2")],
        **args)
    assert r1.status_code == 200 and r2.status_code == 429
    inp = decision_logs.last["input"]
    assert inp["client_id"] == "10.0.0.2"
    assert inp["identity_reason"] == "chain_untrusted_midhop_fallback"


async def test_decision_history_endpoint_local_replay():
    """本地历史端点能看到判定输入与最终结论，且容量有界。"""
    app = _make_app(rate_per_second=1000.0, burst=1000,
                    trusted_proxies=("10.0.0.0/8",), proxy_hop_count=1,
                    decision_history_size=3)
    for ip in ("203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"):
        await call_asgi(
            app, "GET", "http://t/",
            headers=[("x-forwarded-for", ip)], client=("10.0.0.1", 80))
    resp = await call_asgi(app, "GET", "http://t/__defense/decisions",
                           client=("10.0.0.1", 80),
                           headers=[("x-forwarded-for", "203.0.113.9")])
    body = resp.json()
    assert body["enabled"] is True and body["capacity"] == 3
    # 查询请求自身也被记录为最新一条，容量内共 3 条（有界）
    assert body["stored"] == 3
    newest = body["records"][0]
    assert newest["event"] == "defense_decision"
    assert newest["input"]["path"] == "/__defense/decisions"
    assert newest["input"]["client_id"] == "203.0.113.9"
    assert newest["input"]["identity_reason"] == "chain_client_at_trust_boundary"
    assert newest["decision"] == "allow"
    # 有界：只留最近 3 条，最早的 .1/.2 已淘汰
    ids = [r["input"]["client_id"] for r in body["records"]]
    assert "203.0.113.1" not in ids and "203.0.113.2" not in ids
    assert "203.0.113.4" in ids


async def test_decision_history_disabled_by_default_is_zero_cost():
    """默认不保留本地历史：端点显式报告 disabled，stored=0。"""
    app = _make_app(rate_per_second=1000.0, burst=1000,
                    trusted_proxies=("10.0.0.0/8",), proxy_hop_count=1)
    await call_asgi(app, "GET", "http://t/",
                    headers=[("x-forwarded-for", "203.0.113.9")],
                    client=("10.0.0.1", 80))
    resp = await call_asgi(app, "GET", "http://t/__defense/decisions",
                           client=("10.0.0.1", 80),
                           headers=[("x-forwarded-for", "203.0.113.9")])
    body = resp.json()
    assert body["enabled"] is False and body["capacity"] == 0
    assert body["stored"] == 0 and body["records"] == []


async def test_same_identity_concurrent_counting_is_consistent():
    """500 并发：全部来自同一真实客户端（边界地址相同），但左段伪造各不相同。

    chain 模式只采信信任边界地址，所有请求必须聚合到同一 client_id，
    允许数严格等于 burst，不漏计、不重复计数。
    """
    app = _make_app(rate_per_second=1e-6, burst=30,
                    trusted_proxies=("10.0.0.0/8",), proxy_hop_count=2)

    async def one(i):
        # 左段每次都换（攻击者试图骗取独立配额），真实边界 203.0.113.9 恒定
        xff = f"172.{i // 256 % 256}.{i % 256}.1, 203.0.113.9, 10.0.0.2"
        return await call_asgi(
            app, "GET", "http://t/",
            headers=[("x-forwarded-for", xff)], client=("10.0.0.1", 40000 + i))

    results = await asyncio.gather(*(one(i) for i in range(500)))
    codes = [r.status_code for r in results]
    assert codes.count(200) == 30, codes.count(200)
    assert codes.count(429) == 470
    # 只有一个客户端桶
    assert app.limiter.active_clients() == 1


async def test_malicious_oversized_chains_do_not_crash(decision_logs):
    """超长转发链 / 大量重复 XFF 头：明确结论、不崩、不采纳左段。"""
    app = _make_app(rate_per_second=1000.0, burst=1000,
                    trusted_proxies=("10.0.0.0/8",), proxy_hop_count=2,
                    max_forward_hops=8, max_forward_header_bytes=512)
    # 1) 单条 20 万字符
    huge = "1.2.3.4, " + ("z" * 200_000) + ", 10.0.0.2"
    r1 = await call_asgi(app, "GET", "http://t/",
                         headers=[("x-forwarded-for", huge)],
                         client=("10.0.0.1", 80))
    assert r1.status_code == 200
    # 2) 50 个重复 XFF 头
    r2 = await call_asgi(
        app, "GET", "http://t/",
        headers=[("x-forwarded-for", "203.0.113.9, 10.0.0.2")] * 50,
        client=("10.0.0.1", 80))
    assert r2.status_code == 200
    inp = decision_logs.last["input"]
    assert inp["peer_ip"] == "10.0.0.1"
    # 任何情况下最终身份都来自右段可证实来源，绝不是左侧伪造值
    assert inp["client_id"] in ("10.0.0.1", "10.0.0.2", "203.0.113.9")
    assert inp["anomalies"]  # 异常输入必有留痕
    assert decision_logs.last["elapsed_ms"] < 100


async def test_normal_interface_behavior_unchanged_in_chain_mode():
    """chain 模式不改变正常请求的接口行为。"""
    app = _make_app(rate_per_second=1000.0, burst=1000)
    resp = await call_asgi(app, "GET", "http://t/")
    assert resp.status_code == 200
    assert resp.json() == {"Hello": "World"}
    assert resp.headers["x-defense-decision"] == "allow"
