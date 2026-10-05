"""信任模型与客户端身份判定。"""
from __future__ import annotations

from request_defense.identity import IdentityResolver, REASON_BOUNDARY_BREACH


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


def test_hop_count_two_all_hops_trusted_uses_left_candidate():
    """两级都可信：peer=二级代理 10.0.0.2 可信，右数第 1 跳=一级代理 10.0.0.1
    也必须可信，才允许采纳右数第 2 跳作为客户端。"""
    r = IdentityResolver(("10.0.0.1", "10.0.0.2"), hop_count=2)
    ident = r.resolve("10.0.0.2",
                      [("x-forwarded-for", "1.2.3.4, 10.0.0.1")])
    assert ident.client_id == "1.2.3.4"
    assert ident.used_forwarded is True
    assert ident.verified_trusted_hops == 1
    assert ident.anomalies == ()


def test_hop_count_two_middle_hop_untrusted_is_boundary_breach():
    """旧实现的不安全假设：hop_count=2 时不校验右数第 1 跳。
    新模型下该跳不可信即信任边界突破：禁止采信左侧地址，
    回退到由可信代理写入的边界地址（它不能被请求方伪造成任意受害者）。"""
    r = IdentityResolver(("10.0.0.2",), hop_count=2)
    ident = r.resolve("10.0.0.2",
                      [("x-forwarded-for", "1.2.3.4, 198.51.100.7")])
    assert ident.client_id == "198.51.100.7"
    assert ident.used_forwarded is True
    assert ident.resolution_reason == REASON_BOUNDARY_BREACH
    assert "untrusted_hop_in_trusted_segment" in ident.anomalies
    assert ident.trust_boundary == {
        "hop_index": 1,
        "boundary_addr": "198.51.100.7",
        "boundary_match_right": "peer",
    }
    # 与"跳数不足/畸形/缺失"等 peer 回退严格区分：回退后 peer_ip 仍是直连，
    # 但 client_id 不再等于 peer_ip
    assert ident.client_id != ident.peer_ip


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
