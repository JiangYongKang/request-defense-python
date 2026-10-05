"""ASGI 全链路：多级转发链下的限流/拦截行为与并发计数一致性。"""
from __future__ import annotations

import asyncio

import pytest

from request_defense.config import DefenseConfig
from request_defense.middleware import DefenseMiddleware
from tests.conftest import call_asgi

from fastapi import FastAPI, Request

pytestmark = pytest.mark.anyio

CLIENT = "198.51.100.7"
P1 = "10.0.0.1"
P2 = "10.0.0.2"
PARTNER = "203.0.113.1"


def _make_app(**kwargs) -> DefenseMiddleware:
    config = DefenseConfig(**kwargs)
    inner = FastAPI()

    @inner.get("/")
    def root():
        return {"Hello": "World"}

    @inner.get("/__defense/status")
    def status(request: Request):
        mw: DefenseMiddleware = request.scope["defense_middleware"]
        return {
            "proxy_hop_count": mw.config.proxy_hop_count,
            "trusted_proxies": list(mw.config.trusted_proxies),
            "on_forwarded_from_untrusted": mw.config.on_forwarded_from_untrusted,
            "identity": mw.resolver.status_dict(),
        }

    return DefenseMiddleware(inner, config=config)


async def test_two_level_trusted_chain_rate_limits_real_client(decision_logs):
    """两级自有代理：同一真实客户端经链路上来，按真实身份聚合限流。"""
    app = _make_app(rate_per_second=1e-6, burst=2,
                    trusted_proxies=(P1, P2), proxy_hop_count=2)
    hdr = [("x-forwarded-for", f"{CLIENT}, {P1}")]
    codes = [
        (await call_asgi(app, "GET", "http://t/", headers=hdr,
                         client=(P2, 4000 + i))).status_code
        for i in range(4)
    ]
    assert codes == [200, 200, 429, 429]
    log = decision_logs.last["input"]
    assert log["client_id"] == CLIENT
    assert log["resolution_reason"] == "forwarded_ok"
    assert log["verified_trusted_hops"] == 1
    assert log["trust_boundary"] is None


async def test_boundary_breach_aggregates_on_unforgeable_gateway(decision_logs):
    """合作方不可信网关 + 自有代理，请求方任意伪造左段：
    全部聚合到不可伪造的网关地址，不能用伪造 XFF 拿到多个配额。"""
    app = _make_app(rate_per_second=1e-6, burst=3,
                    trusted_proxies=(P2,), proxy_hop_count=2)
    statuses = []
    for i in range(6):
        # 每请求伪造不同的最左"受害者"地址
        hdr = [("x-forwarded-for", f"172.{i}.0.1, {PARTNER}")]
        statuses.append((await call_asgi(
            app, "GET", "http://t/", headers=hdr, client=(P2, 5000 + i)
        )).status_code)
    assert statuses == [200, 200, 200, 429, 429, 429]
    log = decision_logs.last["input"]
    assert log["client_id"] == PARTNER
    assert log["resolution_reason"] == "trust_boundary_breach_at_untrusted_hop"
    assert log["trust_boundary"]["boundary_addr"] == PARTNER
    assert "untrusted_hop_in_trusted_segment" in log["anomalies"]
    # 正常接口行为不变：没有新增拒绝，只是按网关维度限流
    assert decision_logs.last["decision"] == "deny"
    assert decision_logs.last["deny"]["error"] == "rate_limited"


async def test_same_identity_concurrent_requests_counted_exactly_once(decision_logs):
    """同一真实客户端（多级链识别出的同一 client_id）高并发：
    允许数严格等于 burst，不会因链解析拿到多个配额或漏计。"""
    app = _make_app(rate_per_second=1e-6, burst=20,
                    trusted_proxies=(P1, P2), proxy_hop_count=2)

    async def one(i):
        # 模拟不同最左灌水值 + 不同源端口，但真实客户端与代理链不变
        hdr = [("x-forwarded-for", f"6.6.6.{i % 250}, {CLIENT}, {P1}")]
        # hop_count=2 -> 候选=右数第 2 跳 = CLIENT；右数第 1 跳 P1 可信
        return await call_asgi(app, "GET", "http://t/", headers=hdr,
                               client=(P2, 40000 + i))

    results = await asyncio.gather(*(one(i) for i in range(400)))
    codes = [r.status_code for r in results]
    assert codes.count(200) == 20
    assert codes.count(429) == 380
    assert app.limiter.active_clients() == 1  # 只有一个真实身份
    assert decision_logs.last["input"]["client_id"] == CLIENT


async def test_concurrent_breach_requests_do_not_create_multiple_quotas():
    """边界突破场景：500 并发、每请求不同伪造左段，桶数必须为 1。"""
    app = _make_app(rate_per_second=1e-6, burst=15,
                    trusted_proxies=(P2,), proxy_hop_count=2)

    async def one(i):
        hdr = [("x-forwarded-for", f"10.{i // 256}.{i % 256}.1, {PARTNER}")]
        return await call_asgi(app, "GET", "http://t/", headers=hdr,
                               client=(P2, 40000 + i))

    results = await asyncio.gather(*(one(i) for i in range(500)))
    codes = [r.status_code for r in results]
    assert codes.count(200) == 15
    assert codes.count(429) == 485
    assert app.limiter.active_clients() == 1


async def test_malicious_headers_have_stable_decision_and_app_survives(
        decision_logs):
    """超长链 / 大量重复头 / 非法字符：不崩、结论稳定、正常接口照旧放行。"""
    app = _make_app(rate_per_second=1000.0, burst=1000,
                    trusted_proxies=(P1, P2), proxy_hop_count=2)
    long_chain = ", ".join(f"10.{i // 256}.{i % 256}.{1 + i % 250}"
                           for i in range(600)) + f", {CLIENT}, {P1}"
    cases = [
        [("x-forwarded-for", long_chain)],
        [("x-forwarded-for", "\x00\x01bad, ???, 10.0.0.1")],
        [("x-forwarded-for", "a" * 20000)],
        [("x-forwarded-for", f"{CLIENT}, {P1}")] * 30,
        [],
    ]
    for hdr in cases:
        resp = await call_asgi(app, "GET", "http://t/", headers=hdr,
                               client=(P2, 9000))
        assert resp.status_code == 200
        assert resp.json() == {"Hello": "World"}
        assert resp.headers["x-defense-decision"] in (
            "allow", "deny:rate_limited")
        assert decision_logs.last["input"]["resolution_reason"]


async def test_status_endpoint_reports_trust_topology():
    app = _make_app(rate_per_second=1000.0, burst=1000,
                    trusted_proxies=(P1, "10.1.0.0/16"), proxy_hop_count=3,
                    on_forwarded_from_untrusted="deny")
    resp = await call_asgi(app, "GET", "http://t/__defense/status")
    assert resp.status_code == 200
    body = resp.json()
    # 兼容旧字段
    assert body["proxy_hop_count"] == 3
    assert body["trusted_proxies"] == [P1, "10.1.0.0/16"]
    # 新增：当前生效的信任拓扑
    topo = body["identity"]
    assert topo["model"] == "per_hop_trusted_chain"
    assert topo["declared_hop_count"] == 3
    assert topo["on_forwarded_from_untrusted"] == "deny"
    assert topo["trusted_proxies"] == [P1, "10.1.0.0/16"]
    assert topo["limits"]["max_xff_tokens"] > 0
