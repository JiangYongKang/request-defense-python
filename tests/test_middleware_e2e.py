"""端到端：身份 -> 规则 -> 限流，经 ASGI 全链路验证。"""
from __future__ import annotations

import json

import pytest

from request_defense.config import DefenseConfig
from request_defense.middleware import DefenseMiddleware
from tests.conftest import call_asgi

from fastapi import FastAPI

pytestmark = pytest.mark.anyio


def _make_app(**kwargs) -> DefenseMiddleware:
    config = DefenseConfig(**kwargs)
    inner = FastAPI()

    @inner.get("/")
    def root():
        return {"Hello": "World"}

    return DefenseMiddleware(inner, config=config)


async def test_normal_request_behavior_unchanged(decision_logs):
    app = _make_app(rate_per_second=100.0, burst=100)
    resp = await call_asgi(app, "GET", "http://t/")
    assert resp.status_code == 200
    assert resp.json() == {"Hello": "World"}
    assert resp.headers["x-defense-decision"] == "allow"
    assert decision_logs.last["decision"] == "allow"


async def test_rate_limit_distinguishable_reason_and_retry_after(decision_logs):
    app = _make_app(rate_per_second=1.0, burst=2)
    assert (await call_asgi(app, "GET", "http://t/")).status_code == 200
    assert (await call_asgi(app, "GET", "http://t/")).status_code == 200
    rejected = await call_asgi(app, "GET", "http://t/")
    assert rejected.status_code == 429
    body = rejected.json()
    assert body["error"] == "rate_limited"
    assert body["retryable"] is True
    assert body["retry_after_seconds"] > 0
    assert rejected.headers["retry-after"] == "1"
    assert rejected.headers["x-defense-decision"] == "deny:rate_limited"
    assert decision_logs.last["deny"]["error"] == "rate_limited"


async def test_rate_limit_per_client_dimension(decision_logs):
    app = _make_app(rate_per_second=1.0, burst=1)
    # 两个不同直连 peer：各自独立 1 个突发
    r1 = await call_asgi(app, "GET", "http://t/", client=("203.0.113.1", 1000))
    r2 = await call_asgi(app, "GET", "http://t/", client=("203.0.113.2", 1000))
    assert r1.status_code == r2.status_code == 200
    r1b = await call_asgi(app, "GET", "http://t/", client=("203.0.113.1", 1000))
    assert r1b.status_code == 429


async def test_spoofed_forwarded_header_cannot_bypass_limit(decision_logs):
    """攻击者直连（不可信），每次伪造不同 XFF：必须仍按 peer 聚合限流。"""
    app = _make_app(rate_per_second=1.0, burst=3,
                    trusted_proxies=("10.0.0.1",))
    statuses = []
    for i in range(5):
        resp = await call_asgi(
            app, "GET", "http://t/",
            headers=[("x-forwarded-for", f"10.{i}.{i}.{i}")],
            client=("203.0.113.9", 50000))
        statuses.append(resp.status_code)
    assert statuses == [200, 200, 200, 429, 429], statuses
    log = decision_logs.last
    assert log["input"]["client_id"] == "203.0.113.9"
    assert "forwarded_headers_from_untrusted_peer" in log["input"]["anomalies"]


async def test_deny_policy_blocks_untrusted_forwarding(decision_logs):
    app = _make_app(rate_per_second=100.0, burst=100,
                    trusted_proxies=("10.0.0.1",),
                    on_forwarded_from_untrusted="deny")
    resp = await call_asgi(
        app, "GET", "http://t/",
        headers=[("x-forwarded-for", "1.2.3.4")],
        client=("203.0.113.9", 50000))
    assert resp.status_code == 403
    assert resp.json()["error"] == "forwarded_headers_from_untrusted_source"
    assert resp.json()["retryable"] is False


async def test_trusted_proxy_identity_is_used_and_limited(decision_logs):
    app = _make_app(rate_per_second=1.0, burst=1,
                    trusted_proxies=("10.0.0.1",))
    # 同一真实客户端 198.51.100.7，经同一代理两次：第二次必须被限
    common = {"headers": [("x-forwarded-for", "198.51.100.7")],
              "client": ("10.0.0.1", 80)}
    assert (await call_asgi(app, "GET", "http://t/", **common)).status_code == 200
    second = await call_asgi(app, "GET", "http://t/", **common)
    assert second.status_code == 429
    assert decision_logs.last["input"]["client_id"] == "198.51.100.7"


async def test_client_prepended_spoof_cannot_evade_limit():
    """攻击者自填 XFF 左端，代理追加真实 IP：不同伪造值、同一真实 IP 仍受限。"""
    app = _make_app(rate_per_second=1.0, burst=1,
                    trusted_proxies=("10.0.0.1",))
    r1 = await call_asgi(
        app, "GET", "http://t/",
        headers=[("x-forwarded-for", "9.9.9.9, 198.51.100.7")],
        client=("10.0.0.1", 80))
    r2 = await call_asgi(
        app, "GET", "http://t/",
        headers=[("x-forwarded-for", "8.8.8.8, 198.51.100.7")],
        client=("10.0.0.1", 80))
    assert r1.status_code == 200 and r2.status_code == 429


async def test_rule_blocks_before_rate_limit_and_distinguishable(
        tmp_path, decision_logs):
    rule_file = tmp_path / "rules.json"
    rule_file.write_text(json.dumps({"rules": [
        {"id": "block-admin", "field": "path_prefix",
         "match": "prefix", "value": "/admin"},
    ]}), encoding="utf-8")
    app = _make_app(rate_per_second=100.0, burst=100,
                    rules_file=str(rule_file))
    resp = await call_asgi(app, "GET", "http://t/admin/secret")
    assert resp.status_code == 403
    body = resp.json()
    assert body["error"] == "rule_denied"
    assert body["rule_id"] == "block-admin"
    assert body["retryable"] is False
    assert resp.headers["x-defense-decision"] == "deny:rule:block-admin"
    # 规则命中先于限流：命中后不应有任何令牌被扣
    assert decision_logs.last["rate_limit"] is None


async def test_rule_blocked_request_does_not_consume_burst(tmp_path):
    """恶意请求命中规则，不应耗尽正常请求的令牌。"""
    rule_file = tmp_path / "rules.json"
    rule_file.write_text(json.dumps({"rules": [
        {"id": "block-admin", "field": "path_prefix",
         "match": "prefix", "value": "/admin"},
    ]}), encoding="utf-8")
    app = _make_app(rate_per_second=1.0, burst=1,
                    rules_file=str(rule_file))
    # 同一个 client_id 下，先打 5 次恶意请求，再打正常请求仍应放行
    for _ in range(5):
        r = await call_asgi(app, "GET", "http://t/admin")
        assert r.status_code == 403
    ok = await call_asgi(app, "GET", "http://t/")
    assert ok.status_code == 200


async def test_broken_rule_file_does_not_take_down_service(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    # 整体非法：服务仍启动，规则全部不生效（fail-*open 仅限规则维度），
    # 但状态端点明确暴露失败原因，限流仍然有效。
    app = _make_app(rate_per_second=1000.0, burst=1000, rules_file=str(bad))
    resp = await call_asgi(app, "GET", "http://t/")
    assert resp.status_code == 200
    assert app.rules.loaded is False
    assert app.rules.status == "rules_file_invalid_json"
    assert app.rules.load_error


async def test_partial_invalid_rules_remain_operational(tmp_path):
    rf = tmp_path / "rules.json"
    rf.write_text(json.dumps({"rules": [
        {"id": "good", "field": "path_prefix", "match": "prefix", "value": "/admin"},
        {"id": "bad", "field": "path", "match": "regex", "value": "(["},
    ]}), encoding="utf-8")
    app = _make_app(rate_per_second=1000.0, burst=1000, rules_file=str(rf))
    assert app.rules.status == "loaded_with_invalid_rules"
    assert (await call_asgi(app, "GET", "http://t/admin")).status_code == 403
    assert (await call_asgi(app, "GET", "http://t/")).status_code == 200
    assert len(app.rules.invalid_rules) == 1


async def test_malformed_and_missing_forwarded_do_not_crash(decision_logs):
    app = _make_app(rate_per_second=100.0, burst=100,
                    trusted_proxies=("10.0.0.1",))
    # 非法 XFF：回退 peer，不崩溃
    r = await call_asgi(
        app, "GET", "http://t/",
        headers=[("x-forwarded-for", "???garbage")],
        client=("10.0.0.1", 80))
    assert r.status_code == 200
    assert decision_logs.last["input"]["client_id"] == "10.0.0.1"
    # 缺失 XFF：同样回退
    r2 = await call_asgi(app, "GET", "http://t/", client=("10.0.0.1", 80))
    assert r2.status_code == 200
    assert "missing_forwarded_headers" in decision_logs.last["input"]["anomalies"]
