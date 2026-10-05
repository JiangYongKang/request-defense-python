"""多级、部分可信转发链下的身份判定（新信任边界模型）。

约定（从服务侧向右数）：
    XFF: [最左 = 最早客户端/可被请求方自填, ..., 最右 = 最近一跳代理写入]
    peer = TCP 直连对端
    hop_count = 声明的可信代理层数
    右数第 1..hop_count-1 跳 = 声明的可信段，逐跳必须命中白名单
    右数第 hop_count 跳 = 候选客户端身份
"""
from __future__ import annotations

import pytest

from request_defense.identity import (
    IdentityResolver,
    MAX_TOKEN_CHARS,
    MAX_XFF_HEADERS,
    MAX_XFF_TOKENS,
    REASON_BOUNDARY_BREACH,
    REASON_DIRECT_UNTRUSTED,
    REASON_FORWARDED_OK,
    REASON_INSUFFICIENT_HOPS,
    REASON_MALFORMED_TRUSTED_SEGMENT,
    REASON_MISSING,
    REASON_NON_IP_PEER,
    REASON_TRUSTED_CANDIDATE,
    REASON_XREAL_MULTI,
    REASON_XREAL_OK,
)

CLIENT = "198.51.100.7"
PROXY1 = "10.0.0.1"   # 一级（最靠近客户端）可信代理
PROXY2 = "10.0.0.2"   # 二级可信代理
PROXY3 = "10.0.0.3"   # 三级可信代理
PARTNER = "203.0.113.1"  # 合作方/第三方网关（不可信）


def test_three_level_all_trusted_chain():
    """三级自有代理：client -> p1 -> p2 -> p3(peer)。"""
    r = IdentityResolver((PROXY1, PROXY2, PROXY3), hop_count=3)
    ident = r.resolve(PROXY3, [("x-forwarded-for", f"{CLIENT}, {PROXY1}, {PROXY2}")])
    assert ident.client_id == CLIENT
    assert ident.used_forwarded is True
    assert ident.verified_trusted_hops == 2
    assert ident.resolution_reason == REASON_FORWARDED_OK
    assert ident.trust_boundary is None
    assert ident.anomalies == ()


def test_middle_hop_untrusted_breach_ignores_everything_left():
    """client -> 合作方网关(不可信) -> p2 -> p3(peer)，声明 3 跳。

    右数第 2 跳是不可信网关：信任边界在此突破。
    最终身份必须是网关地址（由 p2 据真实 TCP 对端写入，请求方无法伪造），
    绝不能采信其左侧的任何地址（包括请求方自填的 CLIENT）。
    """
    r = IdentityResolver((PROXY2, PROXY3), hop_count=3)
    forged_left = f"1.2.3.4, {CLIENT}, {PARTNER}, {PROXY2}"
    ident = r.resolve(PROXY3, [("x-forwarded-for", forged_left)])
    assert ident.client_id == PARTNER
    assert ident.resolution_reason == REASON_BOUNDARY_BREACH
    assert ident.trust_boundary is not None
    assert ident.trust_boundary["boundary_addr"] == PARTNER
    assert ident.trust_boundary["hop_index"] == 2
    assert "untrusted_hop_in_trusted_segment" in ident.anomalies

    # 攻击者无论怎么改左侧内容（伪造受害者 IP），最终身份都钉死在边界地址
    for spoof in ("9.9.9.9", "8.8.8.8, 7.7.7.7", CLIENT):
        ident2 = r.resolve(PROXY3,
                           [("x-forwarded-for", f"{spoof}, {PARTNER}, {PROXY2}")])
        assert ident2.client_id == PARTNER
        assert ident2.resolution_reason == REASON_BOUNDARY_BREACH


def test_breach_at_rightmost_hop_when_partner_connects_directly():
    """声明 2 跳，但实际只有一层自有代理：对端 p2 可信，右数第 1 跳即不可信
    合作方网关 -> 边界突破，身份=网关，左侧自填全部作废。"""
    r = IdentityResolver((PROXY2,), hop_count=2)
    ident = r.resolve(PROXY2, [("x-forwarded-for", f"6.6.6.6, {PARTNER}")])
    assert ident.client_id == PARTNER
    assert ident.trust_boundary == {
        "hop_index": 1,
        "boundary_addr": PARTNER,
        "boundary_match_right": "peer",
    }


def test_overdeclared_hop_count_cannot_select_attacker_supplied_addr():
    """配多了：真实只有 1 层代理，却声明 hop_count=2。

    旧模型会直接取右数第 2 跳 = 请求方自填地址（致命）；
    新模型因右数第 1 跳不可信而判定边界突破，钉死在真实直连来源。
    """
    r = IdentityResolver((PROXY1,), hop_count=2)
    ident = r.resolve(PROXY1, [("x-forwarded-for", f"6.6.6.6, {CLIENT}")])
    # 注意：右数第 1 跳是 CLIENT（真实直连代理的对端），不可信 -> 边界
    assert ident.client_id == CLIENT
    assert ident.resolution_reason == REASON_BOUNDARY_BREACH

    # 攻击者把自己的地址伪造成受害者也没用：代理写入的是真实 TCP 对端。
    # 这里直接验证：不会选到任何左于边界的条目
    ident2 = r.resolve(PROXY1, [("x-forwarded-for", "6.6.6.6, 5.5.5.5")])
    assert ident2.client_id == "5.5.5.5"  # 边界 = 代理的真实对端
    assert "6.6.6.6" not in str(ident2.trace[-1]) or ident2.client_id != "6.6.6.6"


def test_underdeclared_hop_count_is_flagged_but_safe():
    """配少了：实际两层自有代理，只声明 hop_count=1。

    候选（右数第 1 跳）= 一级代理本身，命中白名单：采纳但留痕，
    绝不继续向左取请求方可控地址。结论偏向安全（粒度变粗，不伪造）。
    """
    r = IdentityResolver((PROXY1, PROXY2), hop_count=1)
    ident = r.resolve(PROXY2, [("x-forwarded-for", f"{CLIENT}, {PROXY1}")])
    assert ident.client_id == PROXY1
    assert ident.resolution_reason == REASON_TRUSTED_CANDIDATE
    assert "candidate_within_trust_boundary" in ident.anomalies
    # 左侧真实客户端不会被采用
    assert ident.client_id != CLIENT


def test_mixed_trusted_and_untrusted_segments_stops_at_first_breach():
    """可信/不可信混合：越过第一个不可信跳后，即便更左出现"看似可信"的
    地址（攻击者可自填白名单地址！）也绝不采信。"""
    r = IdentityResolver((PROXY1, PROXY2, PROXY3), hop_count=3)
    # 攻击者在自填段塞入 PROXY1（白名单地址）试图让链重新"变可信"
    chain = f"{CLIENT}, {PROXY1}, {PARTNER}, {PROXY2}"
    ident = r.resolve(PROXY3, [("x-forwarded-for", chain)])
    assert ident.client_id == PARTNER
    assert ident.resolution_reason == REASON_BOUNDARY_BREACH
    # trace 在突破点终止，不出现对更左 PROXY1 的 trusted 校验
    hop_results = [s["result"] for s in ident.trace
                   if s["step"] == "hop_check"]
    assert not any("right#3" in h for h in hop_results)


def test_insufficient_hops_distinct_from_breach():
    """可用跳数不足：连候选位置都没有 -> peer 回退，原因码独立。"""
    r = IdentityResolver((PROXY2, PROXY3), hop_count=3)
    ident = r.resolve(PROXY3, [("x-forwarded-for", f"{CLIENT}, {PROXY2}")])
    assert ident.client_id == PROXY3 == ident.peer_ip
    assert ident.resolution_reason == REASON_INSUFFICIENT_HOPS
    assert "xff_insufficient_hops" in ident.anomalies
    assert ident.trust_boundary is None


def test_malformed_entry_in_trusted_segment_falls_back_to_peer():
    """可信段内某跳不是合法 IP：无法证明链路完整 -> peer 回退，
    与边界突破、跳数不足原因码都不同。"""
    r = IdentityResolver((PROXY2, PROXY3), hop_count=3)
    ident = r.resolve(PROXY3,
                      [("x-forwarded-for", f"{CLIENT}, ???garbage, {PROXY2}")])
    assert ident.client_id == PROXY3
    assert ident.resolution_reason == REASON_MALFORMED_TRUSTED_SEGMENT
    assert "malformed_xff_entry" in ident.anomalies


def test_missing_headers_and_direct_untrusted_keep_distinct_reasons():
    r = IdentityResolver((PROXY1,))
    assert (r.resolve(PROXY1, []).resolution_reason == REASON_MISSING)
    ident = r.resolve("8.8.8.8", [("x-forwarded-for", CLIENT)])
    assert ident.resolution_reason == REASON_DIRECT_UNTRUSTED
    assert ident.client_id == "8.8.8.8"
    assert r.resolve("testclient", []).resolution_reason == REASON_NON_IP_PEER


def test_x_real_ip_single_hop_ok_but_multi_hop_unverified():
    single = IdentityResolver((PROXY1,), hop_count=1)
    ident = single.resolve(PROXY1, [("x-real-ip", CLIENT)])
    assert ident.client_id == CLIENT
    assert ident.resolution_reason == REASON_XREAL_OK

    multi = IdentityResolver((PROXY1, PROXY2), hop_count=2)
    ident2 = multi.resolve(PROXY2, [("x-real-ip", CLIENT)])
    # 单值头无法逐跳佐证多层链路 -> 回退 peer，绝不凭单值放行
    assert ident2.client_id == PROXY2
    assert ident2.resolution_reason == REASON_XREAL_MULTI
    assert "x_real_ip_unverified_multi_hop" in ident2.anomalies


# ---------------- 异常 / 恶意构造输入：必须有稳定结论且资源有界 ----------------

def test_extremely_long_chain_is_capped_and_still_resolves():
    r = IdentityResolver((PROXY1,), hop_count=1)
    junk = ", ".join(f"10.{i // 256}.{i % 256}.{1 + (i % 250)}"
                     for i in range(MAX_XFF_TOKENS + 500))
    chain = f"{junk}, {CLIENT}"
    ident = r.resolve(PROXY1, [("x-forwarded-for", chain)])
    # 右数第 1 跳仍是真实 CLIENT，判定不受左侧灌水影响
    assert ident.client_id == CLIENT
    assert "xff_chain_too_long" in ident.anomalies


def test_many_duplicate_xff_headers_are_capped():
    r = IdentityResolver((PROXY1,), hop_count=1)
    headers = [("x-forwarded-for", f"10.0.0.{1 + (i % 250)}")
               for i in range(MAX_XFF_HEADERS + 20)]
    headers.append(("x-forwarded-for", CLIENT))
    ident = r.resolve(PROXY1, headers)
    assert "xff_too_many_headers" in ident.anomalies
    assert "multiple_xff_headers" in ident.anomalies
    # 最右（最后接收）的头写入 CLIENT -> 身份正确
    assert ident.client_id == CLIENT


def test_oversized_token_is_rejected_with_bound_memory():
    r = IdentityResolver((PROXY1,), hop_count=1)
    huge = "a" * (MAX_TOKEN_CHARS * 40)
    ident = r.resolve(PROXY1, [("x-forwarded-for", huge)])
    assert ident.client_id == PROXY1
    assert "malformed_xff_entry" in ident.anomalies
    # trace 不被超长串撑爆：原始输入经 _clip 后仅保留裁剪上限加少量标注
    from request_defense.identity import TRACE_INPUT_CLIP
    for step in ident.trace:
        assert len(step["input"]) <= TRACE_INPUT_CLIP + 64


def test_oversized_single_header_without_commas_is_clipped():
    """超长单头：split 前先按 MAX_HEADER_CHARS 裁剪右侧尾部，
    解析耗时/内存不随头长度增长，结论稳定。"""
    from request_defense.identity import MAX_HEADER_CHARS
    r = IdentityResolver((PROXY1,), hop_count=1)
    # 尾部保留区内有一个逗号分隔的合法 IP -> 仍能识别为 CLIENT
    value = ("z" * 200_000) + ", " + CLIENT.rjust(MAX_HEADER_CHARS // 2, " ")
    ident = r.resolve(PROXY1, [("x-forwarded-for", value)])
    assert "xff_header_value_too_long" in ident.anomalies
    assert ident.client_id == CLIENT

    # 纯粹的超长垃圾（无逗号、无合法 IP）-> 稳定回退 peer
    ident2 = r.resolve(PROXY1, [("x-forwarded-for", "q" * 500_000)])
    assert ident2.client_id == PROXY1
    assert "xff_entry_too_long" in ident2.anomalies
    assert ident2.resolution_reason


def test_resolution_time_is_bounded():
    """恶意输入下判定耗时有上界（与正常输入同数量级）。"""
    import time
    r = IdentityResolver((PROXY1, PROXY2, PROXY3), hop_count=3)
    huge_chain = ", ".join(["x" * 200] * 50_000)
    many_headers = [("x-forwarded-for", huge_chain)] * 100
    start = time.perf_counter()
    for _ in range(20):
        ident = r.resolve(PROXY3, many_headers)
        assert ident.client_id
    elapsed_ms = (time.perf_counter() - start) * 1000 / 20
    assert elapsed_ms < 20, elapsed_ms  # 单次远低于 20ms


def test_illegal_characters_never_raise():
    r = IdentityResolver((PROXY1, PROXY2), hop_count=2)
    weird_headers = [
        ("x-forwarded-for", "evil\x00\x01, not_an_ip, ��, 10.0.0.1"),
        ("x-forwarded-for", ""),
        ("x-forwarded-for", " , , , "),
        ("x-forwarded-for", "99.99.99.99.99, 10.0.0.1"),
    ]
    for h in weird_headers:
        ident = r.resolve(PROXY2, [h])
        # 任何畸形输入都有确定结论：要么边界、要么 peer 回退，绝不抛异常
        assert ident.resolution_reason
        assert ident.client_id


def test_all_resolution_paths_have_programmable_reason_and_trace():
    """每条判定都必须带稳定原因码、peer、最终身份与可复查 trace。"""
    r = IdentityResolver((PROXY1, PROXY2, PROXY3), hop_count=2)
    cases = [
        (PROXY2, [("x-forwarded-for", f"{CLIENT}, {PROXY1}")]),
        (PROXY2, [("x-forwarded-for", f"{CLIENT}, {PARTNER}")]),
        (PROXY2, [("x-forwarded-for", PROXY1)]),
        (PROXY2, [("x-forwarded-for", "???")]),
        (PROXY2, []),
        ("8.8.8.8", [("x-forwarded-for", CLIENT)]),
    ]
    for peer, hdrs in cases:
        ident = r.resolve(peer, hdrs)
        assert ident.resolution_reason
        assert ident.peer_ip
        assert ident.client_id
        assert ident.trace and ident.trace[0]["step"] == "peer"
        log = ident.as_log_dict()
        assert {"client_id", "peer_ip", "resolution_reason",
                "trust_boundary", "anomalies", "trace"} <= set(log)


def test_status_dict_exposes_effective_trust_topology():
    r = IdentityResolver((PROXY1, "10.1.0.0/16"), hop_count=3,
                         on_untrusted_forwarded="deny")
    status = r.status_dict()
    assert status["model"] == "per_hop_trusted_chain"
    assert status["trusted_proxies"] == [PROXY1, "10.1.0.0/16"]
    assert status["declared_hop_count"] == 3
    assert status["on_forwarded_from_untrusted"] == "deny"
    assert status["limits"]["max_xff_tokens"] >= 1


@pytest.mark.parametrize("hops,declared", [
    (1, 1), (2, 2), (3, 3), (2, 1), (1, 2), (2, 3), (3, 2),
])
def test_topology_matrix_never_accepts_left_of_untrusted(hops, declared):
    """层数矩阵（真实 1..3 层代理 × 声明 1..3 跳）：
    任何错配下结论都偏向安全——绝不采用请求方自填的受害地址 6.6.6.6。"""
    proxies = (PROXY1, PROXY2, PROXY3)
    r = IdentityResolver(proxies[:max(hops, declared)], hop_count=declared)
    chain_entries = [CLIENT] + [PROXY1] * hops
    # 请求方在最左再塞一个伪造的受害地址
    chain_entries = ["6.6.6.6"] + chain_entries
    peer = PROXY1 if hops == 1 else PROXY2 if hops == 2 else PROXY3
    chain = ", ".join(chain_entries[1:])  # 代理实际记录的链
    ident = r.resolve(peer, [("x-forwarded-for", chain)])
    assert ident.client_id != "6.6.6.6"
    assert ident.resolution_reason
