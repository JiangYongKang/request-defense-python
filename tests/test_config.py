"""配置加载与非法值处理。"""
from __future__ import annotations

import pytest

from request_defense.config import DefenseConfig, DefenseConfigError


def test_defaults(monkeypatch):
    for key in list(__import__("os").environ):
        if key.startswith("DEFENSE_"):
            monkeypatch.delenv(key, raising=False)
    cfg = DefenseConfig.from_env()
    assert cfg.rate_limit_enabled is True
    assert cfg.rate_per_second == 5.0
    assert cfg.burst == 10
    assert cfg.trusted_proxies == ()
    assert cfg.rules_file is None


def test_trusted_proxies_normalize_and_dedup(monkeypatch):
    monkeypatch.setenv("DEFENSE_TRUSTED_PROXIES",
                       "10.0.0.1, 10.0.0.0/8, 10.0.0.1, 2001:db8::1")
    cfg = DefenseConfig.from_env()
    assert cfg.trusted_proxies == ("10.0.0.1", "10.0.0.0/8", "2001:db8::1")


@pytest.mark.parametrize("key,value", [
    ("DEFENSE_BURST", "0"),
    ("DEFENSE_BURST", "x"),
    ("DEFENSE_RATE_PER_SECOND", "0"),
    ("DEFENSE_RATE_PER_SECOND", "abc"),
    ("DEFENSE_RATE_LIMIT_ENABLED", "maybe"),
    ("DEFENSE_ON_FORWARDED_FROM_UNTRUSTED", "wat"),
    ("DEFENSE_PROXY_HOP_COUNT", "0"),
    ("DEFENSE_TRUSTED_PROXIES", "not-an-ip"),
    ("DEFENSE_MAX_CLIENTS", "-1"),
])
def test_invalid_values_raise(monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(DefenseConfigError) as exc:
        DefenseConfig.from_env()
    assert key in str(exc.value)  # 错误消息必须能定位到具体配置项
