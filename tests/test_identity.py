"""信任模型与客户端身份判定。"""
from __future__ import annotations

from request_defense.identity import IdentityResolver


def test_spoofed_xff_from_untrusted_peer_is_ignored():
    r = IdentityResolver(("10.0.0.1",))
    ident = r.resolve("203.0.113.9", [("x-forwarded-for", "1.2.3.4")])
    assert ident.client_id == "203.0.113.9"
    assert ident.used_forwarded is False
    assert ident.anomalies == ("forwarded_headers_from_untrusted_peer",)
    assert ident.deny_reason is None
    assert ident.trace  # 判定链路可追溯


def test_spoofed_xff_deny_policy():
    r = IdentityResolver(("10.0.0.1",), on_untrusted_forwarded="deny")
    ident = r.resolve("203.0.113.9", [("x-forwarded-for", "1.2.3.4")])
    assert ident.client_id == "203.0.113.9"
    assert ident.deny_reason == "forwarded_headers_from_untrusted_source"


def test_trusted_proxy_forwarded_xff_is_used():
    r = IdentityResolver(("10.0.0.1",))
    ident = r.resolve("10.0.0.1", [("x-forwarded-for", "198.51.100.7")])
    assert ident.client_id == "198.51.100.7"
    assert ident.used_forwarded is True
    assert ident.anomalies == ()


def test_client_self_added_left_hop_cannot_override_identity():
    """攻击者自填 XFF，可信代理在右侧追加真实地址：必须取右侧地址。"""
    r = IdentityResolver(("10.0.0.1",))
    ident = r.resolve("10.0.0.1",
                      [("x-forwarded-for", "1.2.3.4, 198.51.100.7")])
    assert ident.client_id == "198.51.100.7"


def test_hop_count_two():
    r = IdentityResolver(("10.0.0.1",), hop_count=2)
    ident = r.resolve("10.0.0.1",
                      [("x-forwarded-for", "1.2.3.4, 198.51.100.7")])
    assert ident.client_id == "1.2.3.4"


def test_insufficient_hops_falls_back_to_peer():
    r = IdentityResolver(("10.0.0.1",), hop_count=2)
    ident = r.resolve("10.0.0.1", [("x-forwarded-for", "1.2.3.4")])
    assert ident.client_id == "10.0.0.1"
    assert "xff_insufficient_hops" in ident.anomalies


def test_malformed_xff_falls_back_to_peer():
    r = IdentityResolver(("10.0.0.1",))
    ident = r.resolve("10.0.0.1", [("x-forwarded-for", "not-an-ip")])
    assert ident.client_id == "10.0.0.1"
    assert "malformed_xff_entry" in ident.anomalies


def test_missing_forwarded_from_trusted_peer_falls_back():
    r = IdentityResolver(("10.0.0.1",))
    ident = r.resolve("10.0.0.1", [])
    assert ident.client_id == "10.0.0.1"
    assert "missing_forwarded_headers" in ident.anomalies


def test_cidr_trust_list():
    r = IdentityResolver(("10.1.0.0/16",))
    ident = r.resolve("10.1.9.9", [("x-forwarded-for", "8.8.8.8")])
    assert ident.client_id == "8.8.8.8"
    ident2 = r.resolve("10.2.9.9", [("x-forwarded-for", "8.8.8.8")])
    assert ident2.client_id == "10.2.9.9"


def test_x_real_ip_and_spoof():
    r = IdentityResolver(("10.0.0.1",))
    assert r.resolve("10.0.0.1", [("x-real-ip", "192.0.2.10")]).client_id == "192.0.2.10"
    ident = r.resolve("9.9.9.9", [("x-real-ip", "1.2.3.4")])
    assert ident.client_id == "9.9.9.9"
    assert ident.anomalies


def test_non_ip_peer_never_trusted():
    r = IdentityResolver(("10.0.0.1",))
    ident = r.resolve("testclient", [("x-forwarded-for", "1.2.3.4")])
    assert ident.client_id == "testclient"
    assert ident.used_forwarded is False
