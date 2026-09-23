"""End-to-end middleware behavior via Starlette TestClient.

Covers: ordering (rules beat rate limit), distinct denial reasons, forged
forwarding, trusted XFF identity, reload failure keeps old ruleset, and
that normal request bodies/responses stay untouched.
"""

import json
import logging
import threading

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from defense.config import DefenseConfig
from defense.factory import (
    add_defense,
    add_defense_safely,
    build_defense,
    get_engine,
    reload_defense,
)
from defense.rules import CompiledRule


def make_app(config: DefenseConfig):
    app = FastAPI()
    build_defense(app, config)

    @app.get("/")
    def root():
        return {"Hello": "World"}

    @app.api_route("/echo", methods=["GET", "POST", "DELETE"])
    async def echo(request: Request):
        raw = (await request.body()) if request.method == "POST" else b""
        return {"method": request.method, "body_len": len(raw),
                "client": request.state.defense_client_id}

    return app


def cfg(**kw):
    base = dict(rate_per_sec=1000, burst=3, rules=())
    base.update(kw)
    return DefenseConfig(**base)


RULE_ADMIN = CompiledRule({
    "id": "block-admin",
    "reason_code": "admin_area",
    "match": {"field": "path", "op": "prefix", "value": "/admin"},
})
RULE_UA = CompiledRule({
    "id": "block-scanner",
    "match": {"field": "header", "name": "user-agent", "op": "regex",
              "value": r"(?i)sqlmap"},
})


def test_normal_traffic_unchanged_with_headers():
    app = make_app(cfg())
    r = TestClient(app).get("/")
    assert r.status_code == 200 and r.json() == {"Hello": "World"}
    assert r.headers["X-RateLimit-Limit"] == "3"
    assert r.headers["X-RateLimit-Remaining"] == "2"


def test_rule_block_reason_distinguishable_and_no_retry_after():
    app = make_app(cfg(rules=(RULE_ADMIN,), rate_per_sec=1000, burst=100))
    r = TestClient(app, client=("1.2.3.4", 5000)).get("/admin/x")
    assert r.status_code == 403
    body = r.json()
    assert body["error"] == "rule_blocked"
    assert body["reason"] == "admin_area"
    assert "Retry-After" not in r.headers
    assert r.headers["X-Defense-Reason"] == "rule:block-admin"


def test_rate_limit_reason_retry_after_and_exact_boundary():
    app = make_app(cfg(rate_per_sec=0.0001, burst=3))  # effectively no refill
    c = TestClient(app, client=("9.9.9.9", 5000))
    codes = [c.get("/").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    r = c.get("/")
    body = r.json()
    assert body["error"] == "rate_limited"
    assert int(r.headers["Retry-After"]) >= 1
    assert r.headers["X-Defense-Reason"] == "rate_limited"


def test_rule_checked_before_rate_limit_does_not_consume_budget():
    app = make_app(cfg(rules=(RULE_ADMIN,), rate_per_sec=0.0001, burst=1))
    c = TestClient(app, client=("9.9.9.9", 5000))
    blocked = c.get("/admin")       # blocked, must not consume the single token
    assert blocked.status_code == 403
    ok = c.get("/")                 # full burst still available
    assert ok.status_code == 200


def test_clients_are_isolated():
    app = make_app(cfg(rate_per_sec=0.0001, burst=1))
    c1 = TestClient(app, client=("1.0.0.1", 5000))
    c2 = TestClient(app, client=("1.0.0.2", 5000))
    assert c1.get("/").status_code == 200
    assert c1.get("/").status_code == 429
    assert c2.get("/").status_code == 200  # different identity, own bucket


def test_forged_xff_from_untrusted_peer_is_ignored():
    # Same attacker identity regardless of which XFF he claims.
    app = make_app(cfg(rate_per_sec=0.0001, burst=1))
    c = TestClient(app, client=("6.6.6.6", 5000))
    assert c.get("/", headers={"X-Forwarded-For": "8.8.8.8"}).status_code == 200
    # Claiming a different IP must not hand over a fresh bucket.
    r2 = c.get("/", headers={"X-Forwarded-For": "7.7.7.7"})
    assert r2.status_code == 429


def test_trusted_proxy_xff_identifies_real_client(tmp_path):
    import ipaddress
    app = make_app(cfg(
        trusted_networks=(ipaddress.ip_network("10.0.0.0/8"),),
        forward_depth=1,
        rate_per_sec=0.0001, burst=1,
    ))
    proxy = TestClient(app, client=("10.0.0.1", 5000))
    assert proxy.get("/", headers={"X-Forwarded-For": "8.8.8.8"}).status_code == 200
    assert proxy.get("/", headers={"X-Forwarded-For": "8.8.8.8"}).status_code == 429
    # Different real client gets its own bucket through the same proxy.
    assert proxy.get("/", headers={"X-Forwarded-For": "9.9.9.9"}).status_code == 200


def test_trusted_proxy_malformed_xff_falls_back_to_peer():
    import ipaddress
    app = make_app(cfg(
        trusted_networks=(ipaddress.ip_network("10.0.0.0/8"),),
        rate_per_sec=0.0001, burst=1,
    ))
    c = TestClient(app, client=("10.0.0.1", 5000))
    # Malformed chain -> identity falls back to the peer bucket.
    assert c.get("/", headers={"X-Forwarded-For": "junk"}).status_code == 200
    assert c.get("/", headers={"X-Forwarded-For": "junk2"}).status_code == 429
    # A well-formed header afterwards resolves a distinct client identity.
    assert c.get("/", headers={"X-Forwarded-For": "8.8.8.8"}).status_code == 200
    # Empty XFF from trusted proxy also keys on the peer bucket (exhausted).
    assert c.get("/").status_code == 429


def test_header_based_rule_matches_case_insensitively():
    app = make_app(cfg(rules=(RULE_UA,), rate_per_sec=1000, burst=100))
    c = TestClient(app, client=("1.2.3.4", 5000))
    assert c.get("/", headers={"User-Agent": "SQLMap/1.2"}).status_code == 403
    assert c.get("/", headers={"User-Agent": "curl"}).status_code == 200


def test_body_rule_does_not_change_forwarded_payload():
    body_rule = CompiledRule({
        "id": "body-bad",
        "match": {"field": "body", "op": "contains", "value": "/etc/passwd"},
    })
    app = make_app(cfg(rules=(body_rule,), rate_per_sec=1000, burst=100))
    c = TestClient(app, client=("1.2.3.4", 5000))
    bad = c.post("/echo", content="cat /etc/passwd")
    assert bad.status_code == 403 and bad.json()["reason"] == "rule:body-bad"
    good = c.post("/echo", content="hello")
    assert good.status_code == 200 and good.json()["body_len"] == 5


def test_verdict_logged_with_inputs_and_conclusion(caplog):
    app = make_app(cfg(rate_per_sec=0.0001, burst=1))
    c = TestClient(app, client=("1.2.3.4", 5000))
    with caplog.at_level(logging.INFO, logger="defense"):
        c.get("/")
        c.get("/", headers={"X-Forwarded-For": "8.8.8.8"})
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "verdict=allow" in text and "verdict=deny:rate_limited" in text
    assert "client_id=1.2.3.4" in text
    assert "id_source=forged-headers-ignored" in text
    assert "trail=" in text


def test_reload_failure_keeps_existing_rules(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({
        "rate_limit": {"rate_per_sec": 1000, "burst": 50},
        "rules": [{"id": "a", "match": {"field": "path", "op": "prefix",
                                        "value": "/admin"}}],
    }))
    app = FastAPI()
    add_defense(app, str(good))

    @app.get("/{p}")
    def catch(p: str):
        return {"ok": True}

    c = TestClient(app, client=("1.2.3.4", 5000))
    assert c.get("/admin").status_code == 403

    bad = tmp_path / "bad.json"
    bad.write_text('{"rules": [{"id": "broken"}]}')  # invalid: no matcher
    ok, message = reload_defense(app, str(bad))
    assert ok is False and "RuleSyntaxError" in message
    # Old protection still enforced.
    assert c.get("/admin").status_code == 403

    # A valid reload swaps atomically.
    good2 = tmp_path / "good2.json"
    good2.write_text(json.dumps({
        "rate_limit": {"rate_per_sec": 1000, "burst": 50},
        "rules": [{"id": "b", "match": {"field": "path", "op": "prefix",
                                        "value": "/secret"}}],
    }))
    ok2, _ = reload_defense(app, str(good2))
    assert ok2 is True
    assert c.get("/admin").status_code == 200
    assert c.get("/secret").status_code == 403


async def _concurrent_gets(app, n, burst, rate):
    import asyncio
    import httpx
    a = make_app(cfg(rate_per_sec=rate, burst=burst))
    transport = httpx.ASGITransport(app=a)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        results = await asyncio.gather(*[ac.get("/") for _ in range(n)])
    return [r.status_code for r in results]


@pytest.mark.asyncio
async def test_http_level_concurrency_exact_boundary():
    statuses = await _concurrent_gets(None, n=60, burst=25, rate=0.0001)
    assert statuses.count(200) == 25
    assert statuses.count(429) == 35


@pytest.mark.asyncio
async def test_http_level_concurrency_with_rule_blocks_no_token_use():
    import asyncio
    import httpx
    app = make_app(cfg(rules=(RULE_ADMIN,), rate_per_sec=0.0001, burst=10))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        blocked = await asyncio.gather(*[ac.get("/admin") for _ in range(40)])
        good = await asyncio.gather(*[ac.get("/") for _ in range(15)])
    assert all(r.status_code == 403 for r in blocked)
    # 40 rule hits consumed nothing: all 10 burst tokens remain.
    assert sum(r.status_code == 200 for r in good) == 10
    assert sum(r.status_code == 429 for r in good) == 5


def test_invalid_startup_config_fails_safe_not_silent(tmp_path, caplog):
    """Present-but-invalid config: service stays up, rate limiting stays ON,
    blocking rules are empty, and the reason is loudly distinguishable."""
    bad = tmp_path / "bad.json"
    bad.write_text('{"rate_limit": {"rate_per_sec": -7}}')
    app = FastAPI()

    @app.get("/")
    def root():
        return {"Hello": "World"}

    with caplog.at_level(logging.CRITICAL, logger="defense"):
        cfg_obj, error = add_defense_safely(app, str(bad))
    assert error is not None and "ConfigSyntaxError" in error
    assert app.state.defense_config_error.startswith("ConfigSyntaxError")
    assert any("FAIL-SAFE STARTUP" in r.getMessage() for r in caplog.records)
    # Defaults applied: rate limiting still active (burst=10 default).
    c = TestClient(app, client=("5.5.5.5", 5000))
    codes = [c.get("/").status_code for _ in range(11)]
    assert codes.count(200) == 10 and codes.count(429) == 1


def test_strict_mode_propagates_config_error(tmp_path):
    import pytest as _pytest
    from defense.errors import RuleConfigError
    bad = tmp_path / "bad.json"
    bad.write_text('{"rules": [{"id": "x"}]}')
    app = FastAPI()
    with _pytest.raises(RuleConfigError):
        add_defense_safely(app, str(bad), strict=True)


def test_missing_config_uses_defaults_quietly(tmp_path):
    app = FastAPI()
    cfg_obj, error = add_defense_safely(app, str(tmp_path / "absent.json"))
    assert error is None
    assert cfg_obj.rules == () and cfg_obj.rate_per_sec == 5.0
