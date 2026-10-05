"""多级部分可信转发链路（chain 模式）下的客户端身份判定。

覆盖：正常多级可信、中间跳不可信、声明层数与实际拓扑不符（配多/配少）、
可信与不可信段混合、异常头部（非法/超长/超多条目/重复头）、
身份原因码与信任边界可程序化区分。
"""
from __future__ import annotations

import pytest

from request_defense.identity import (
    IdentityResolver,
    REASON_CHAIN_CLIENT_AT_BOUNDARY,
    REASON_CHAIN_UNTRUSTED_MID,
    REASON_CHAIN_TRUSTED_DEPTH_EXHAUSTED,
    REASON_CHAIN_SHORTER_THAN_DECLARED,
    REASON_MALFORMED_XFF,
    REASON_MALFORMED_XREAL,
    REASON_MULTIPLE_XREAL,
    REASON_DIRECT_PEER,
)

TRUSTED = ("10.0.0.0/8",)


def _resolve(trusted=TRUSTED, hops=2, peer="10.0.0.1", xff=None, xri=None,
             **kw):
    headers = []
    if xff is not None:
        headers.append(("x-forwarded-for", xff))
    if xri is not None:
        if isinstance(xri, list):
            headers.extend(("x-real-ip", v) for v in xri)
        else:
            headers.append(("x-real-ip", xri))
    return IdentityResolver(trusted, hop_count=hops, mode="chain",
                            **kw).resolve(peer, headers)


# ---- 正常多级可信链路 ----

def test_two_trusted_hops_normal_chain():
    ident = _resolve(xff="203.0.113.9, 10.0.0.2")
    assert ident.client_id == "203.0.113.9"
    assert ident.used_forwarded is True
    assert ident.reason == REASON_CHAIN_CLIENT_AT_BOUNDARY
    assert ident.trust_boundary_index == 2
    assert ident.anomalies == ()
    roles = [c["role"] for c in ident.chain]
    assert roles == ["peer", "trusted_hop", "client"]


def test_client_self_added_left_entries_are_ignored():
    """客户端在左段塞任意伪造地址：身份仍是真实边界地址。"""
    ident = _resolve(xff="1.2.3.4, 8.8.8.8, 203.0.113.9, 10.0.0.2")
    assert ident.client_id == "203.0.113.9"
    assert [c["role"] for c in ident.chain].count("ignored_left") == 2
    assert ident.anomalies == ()


def test_three_trusted_hops():
    ident = _resolve(hops=3, xff="203.0.113.9, 10.0.0.3, 10.0.0.2")
    assert ident.client_id == "203.0.113.9"
    assert [c["role"] for c in ident.chain] == [
        "peer", "trusted_hop", "trusted_hop", "client"]


# ---- 中间跳不可信：左侧任何地址不得采信 ----

def test_untrusted_midhop_blocks_left_side():
    # client 侧声明还有一跳可信，但中间夹了合作方不可信网关 192.168.5.5
    ident = _resolve(hops=3,
                     xff="203.0.113.9, 192.168.5.5, 10.0.0.2")
    # 回退到已证实的最近可信跳（peer 右一 10.0.0.2），绝不采信 192 左侧
    assert ident.client_id == "10.0.0.2"
    assert ident.reason == REASON_CHAIN_UNTRUSTED_MID
    assert "xff_untrusted_midhop" in ident.anomalies
    assert ident.trust_boundary_index == 2
    # 203.0.113.9 既不是身份也不进入可信链
    assert all(c["address"] != "203.0.113.9" or c["role"] == "ignored_left"
               for c in ident.chain)


def test_untrusted_address_exactly_at_boundary_is_the_client():
    """不可信合法地址恰好在声明的客户端位置：它由可信代理写入，采纳为身份。"""
    ident = _resolve(hops=2, xff="192.168.5.5, 10.0.0.2")
    assert ident.client_id == "192.168.5.5"
    assert ident.reason == REASON_CHAIN_CLIENT_AT_BOUNDARY
    chain_by_role = {c["role"]: c["address"] for c in ident.chain}
    assert chain_by_role["client"] == "192.168.5.5"


# ---- 声明层数与真实拓扑不一致：结论始终偏安全 ----

def test_declared_more_than_actual_hops_falls_back_safely():
    """配多了（声明 3 跳，实际只有 2 个地址：1 代理 + 1 客户端）。

    第 2 跳已是不可信客户端，却要求它也是可信代理 -> 拓扑对不上，
    回退到已证实可信跳，绝不把客户端自填地址当身份。
    """
    ident = _resolve(hops=3, xff="203.0.113.9, 10.0.0.2")
    assert ident.client_id == "10.0.0.2"
    assert ident.reason == REASON_CHAIN_UNTRUSTED_MID
    assert "xff_untrusted_midhop" in ident.anomalies


def test_declared_fewer_than_actual_hops_falls_back_safely():
    """配少了（声明 2 跳，实际有 3 层可信代理 + 客户端）。

    连续 2 跳已证实可信但左侧仍有条目：无法确认该左条目不是请求方自带，
    一律不采信，回退到最近已证实可信跳。
    """
    ident = _resolve(hops=2,
                     xff="203.0.113.9, 10.0.0.3, 10.0.0.2")
    assert ident.client_id == "10.0.0.3"
    assert ident.reason == REASON_CHAIN_SHORTER_THAN_DECLARED
    assert "xff_declared_hops_less_than_chain" in ident.anomalies
    assert ident.trust_boundary_index == 3


def test_attacker_cannot_exploit_over_declared_count():
    """配多了一跳时，攻击者即便在左段塞入任意地址也不会被采纳。"""
    ident = _resolve(hops=3,
                     xff="1.2.3.4, 203.0.113.9, 10.0.0.2")
    assert ident.client_id == "10.0.0.2"
    assert ident.client_id not in ("1.2.3.4", "203.0.113.9")


def test_chain_shorter_than_declared_insufficient_entries():
    """可信 peer 但 XFF 条目少于声明层数：回退到已证实可信跳。"""
    ident = _resolve(hops=3, xff="10.0.0.2")
    assert ident.client_id == "10.0.0.2"
    assert ident.reason == REASON_CHAIN_TRUSTED_DEPTH_EXHAUSTED
    assert "xff_declared_hops_exceed_chain" in ident.anomalies


def test_all_trusted_no_client_entry():
    """整条 XFF 全是可信地址、没有客户端条目：不凭空取地址，回退到最左已证实可信跳。

    拓扑：客户端 -> 10.0.0.3 -> 10.0.0.2 -> 服务(peer 10.0.0.1)，
    但 10.0.0.3 没写下一跳地址，最近的真实可证来源就是 10.0.0.3。
    """
    ident = _resolve(hops=2, xff="10.0.0.3, 10.0.0.2")
    assert ident.client_id == "10.0.0.3"
    assert "xff_declared_hops_exceed_chain" in ident.anomalies


def test_mixed_trusted_segments_then_untrusted_peer_is_anchor():
    """可信段 + 不可信直连 peer：身份锚定 peer，转发头完全不影响身份。"""
    ident = _resolve(peer="198.51.100.70",
                     xff="203.0.113.9, 10.0.0.2")
    assert ident.client_id == "198.51.100.70"
    assert ident.reason == REASON_DIRECT_PEER
    assert "forwarded_headers_from_untrusted_peer" in ident.anomalies
    assert ident.used_forwarded is False


# ---- 异常头部：必须有明确稳定结论，且不采信其左侧 ----

def test_malformed_entry_at_boundary_falls_back():
    ident = _resolve(hops=2, xff="203.0.113.9, ???garbage, 10.0.0.2")
    assert ident.client_id == "10.0.0.2"
    assert ident.reason == REASON_MALFORMED_XFF
    assert "malformed_xff_entry" in ident.anomalies
    assert ident.trust_boundary_index == 2


def test_malformed_entry_in_midhop_falls_back_to_last_safe():
    ident = _resolve(hops=3, xff="203.0.113.9, bad, 10.0.0.2".replace("bad", "nope"))
    assert ident.client_id == "10.0.0.2"
    assert ident.reason == REASON_MALFORMED_XFF
    assert ident.trust_boundary_index == 2


def test_illegal_characters_never_become_identity():
    for evil in ("a b c", "10.0.0.2<script>",
                 "999.999.999.999", "10.0.0", "10.0.0.2/32"):
        ident = _resolve(hops=1, xff=evil)
        assert ident.client_id == "10.0.0.1", evil
        assert "malformed_xff_entry" in ident.anomalies, evil


def test_empty_xff_value_is_treated_as_insufficient_hops():
    for empty in ("", "   ", " , , "):
        ident = _resolve(hops=1, xff=empty)
        assert ident.client_id == "10.0.0.1", empty
        assert "xff_declared_hops_exceed_chain" in ident.anomalies, empty


def test_excessive_hops_are_truncated_from_left():
    """超过 max_hops 的条目全部是左段（请求方侧），直接丢弃且有留痕。"""
    tokens = [f"203.0.113.{i}" for i in range(40)] + ["10.0.0.2"]
    ident = _resolve(hops=2, xff=", ".join(tokens), max_hops=4)
    assert "xff_too_many_hops_truncated_left" in ident.anomalies
    # 右数第 2 跳在保留窗口内，仍被正确采纳
    assert ident.client_id == "203.0.113.39"
    # chain 中出现的地址数有上界（peer + 至多 max_hops 条）
    assert len(ident.chain) <= 1 + 4


def test_oversized_header_value_is_bounded():
    """超长转发链：解析耗时/内存有上界，结论稳定且不崩。"""
    huge = "1.2.3.4, " + ("x" * 200_000) + ", 10.0.0.2"
    ident = _resolve(hops=2, xff=huge, max_header_bytes=256)
    assert "xff_header_too_long_truncated_left" in ident.anomalies
    # 回退到已证实可信跳；trace/chain 中任何字符串都有长度上界
    assert ident.client_id == "10.0.0.2"
    for step in ident.trace:
        assert len(step["input"]) <= 300
    for c in ident.chain:
        assert len(c["address"]) <= 64


def test_duplicate_xff_headers_are_flagged():
    r = IdentityResolver(TRUSTED, hop_count=2, mode="chain")
    ident = r.resolve("10.0.0.1", [("x-forwarded-for", "203.0.113.9"),
                                    ("x-forwarded-for", "10.0.0.2")])
    assert "multiple_xff_headers" in ident.anomalies
    assert ident.client_id == "203.0.113.9"


def test_duplicate_x_real_ip_falls_back_safely():
    ident = _resolve(xri=["203.0.113.9", "1.2.3.4"])
    assert ident.client_id == "10.0.0.1"
    assert ident.reason == REASON_MULTIPLE_XREAL
    assert "multiple_x_real_ip_headers" in ident.anomalies


def test_single_x_real_ip_is_used_when_peer_trusted():
    ident = _resolve(hops=1, xri="203.0.113.9")
    assert ident.client_id == "203.0.113.9"
    assert ident.used_forwarded is True


def test_malformed_x_real_ip_falls_back():
    ident = _resolve(hops=1, xri="not-an-ip")
    assert ident.client_id == "10.0.0.1"
    assert ident.reason == REASON_MALFORMED_XREAL


def test_missing_forwarded_headers_falls_back_to_peer():
    ident = _resolve(xff=None)
    assert ident.client_id == "10.0.0.1"
    assert "missing_forwarded_headers" in ident.anomalies


def test_topology_snapshot_exposes_effective_config():
    r = IdentityResolver(TRUSTED, hop_count=2, mode="chain",
                         max_hops=7, max_header_bytes=512)
    topo = r.topology_dict()
    assert topo == {
        "mode": "chain",
        "trusted_proxies": ["10.0.0.0/8"],
        "declared_trusted_hops": 2,
        "max_forward_hops": 7,
        "max_forward_header_bytes": 512,
        "on_forwarded_from_untrusted": "ignore",
    }


# ---- 配置与默认兼容性 ----

def test_invalid_mode_rejected_at_construction():
    with pytest.raises(ValueError):
        IdentityResolver(TRUSTED, mode="nope")


def test_default_mode_remains_legacy_hop_count():
    """不传 mode 时行为与旧版完全一致（固定右数第 N 跳）。"""
    legacy = IdentityResolver(TRUSTED, hop_count=2)
    chain = IdentityResolver(TRUSTED, hop_count=2, mode="chain")
    xff = "203.0.113.9, 10.0.0.2"
    headers = [("x-forwarded-for", xff)]
    assert legacy.resolve("10.0.0.1", headers).client_id == "203.0.113.9"
    assert chain.resolve("10.0.0.1", headers).client_id == "203.0.113.9"
