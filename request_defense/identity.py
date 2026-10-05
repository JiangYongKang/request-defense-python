"""'部分可信、多级转发链'下的客户端身份判定。

信任模型（详见 docs/）：
  * 身份判定永远从 TCP 直连对端 ``peer_ip`` 开始，它无法被请求头伪造。
  * 只有 ``peer_ip`` 命中可信代理白名单(IP 或 CIDR)时，
    ``X-Forwarded-For`` / ``X-Real-IP`` 构造链的权利才被认可。
  * 链校验从服务侧（XFF 右/尾端）开始，从右向左逐跳校验：
      - peer（TCP 对端）必须可信；
      - 右数第 1..hop_count-1 跳构成"声明的可信段"，每一跳都必须命中白名单；
      - 右数第 hop_count 跳为候选客户端身份；
      - 可信段内**任一跳不可信**即判定"信任边界突破"：立即停止向左采信，
        回退到首个越过边界的地址（由其右侧可信代理据真实 TCP 对端写入，
        请求方无法把它伪造成任意受害者地址），绝不信其左侧任何内容。
  * 候选跳本身命中白名单 -> 大概率是"声明层数偏少"，身份可采纳但留痕，
    且始终不采信更左侧请求方可控的任何地址。
  * 没带转发信息、格式非法、重复头、可用跳数不足、链长/头数/长度超限等
    任何异常都记为不同的稳定 anomaly 码，身份一律回退到不可伪造的来源：
    或回退 peer，或回退信任边界地址。判定过程全部写入 ``trace``。

资源上界：解析前截断到 MAX_XFF_HEADERS / MAX_XFF_TOKENS / MAX_TOKEN_CHARS，
trace 中记录的原始输入做长度裁剪，超长链/大量重复项/非法字符都有稳定结论，
不会把请求处理打崩。
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

#: 判定链路上的一步 {"step", "input", "result"}
TraceStep = dict[str, str]

XFF_HEADER = "x-forwarded-for"
XREAL_HEADER = "x-real-ip"

# ---- 解析资源上界（硬编码安全常数，非配置项；防止恶意构造头打爆解析） ----
#: 最多读取多少个 XFF 头（再多只取最靠右的若干个，并记 anomaly）
MAX_XFF_HEADERS = 8
#: 合并后最多解析多少跳（再多只保留最靠右的若干跳，并记 anomaly）
MAX_XFF_TOKENS = 64
#: 单个条目的最大字符数（超出视为非法条目，绝不读取全部内容到 trace）
MAX_TOKEN_CHARS = 256
#: 单个 XFF 头值参与解析的最大字符数（只保留右侧尾部；左侧灌水直接丢弃）
MAX_HEADER_CHARS = 8192
#: trace 中原始头值的最大记录长度
TRACE_INPUT_CLIP = 512

# ---- 稳定的结论原因码（可被程序化区分；新增，绝不复用 peer 回退码） ----
#: peer 非 IP
REASON_NON_IP_PEER = "non_ip_peer"
#: peer 不在可信白名单
REASON_DIRECT_UNTRUSTED = "direct_untrusted_peer"
#: peer 可信但完全没带转发头
REASON_MISSING = "fallback_peer_missing_headers"
#: 跳数不足回退 peer
REASON_INSUFFICIENT_HOPS = "fallback_peer_insufficient_hops"
#: 可信段内某跳解析失败回退 peer
REASON_MALFORMED_TRUSTED_SEGMENT = "fallback_peer_malformed_trusted_segment"
#: 信任边界突破：首个越界跳即为最终身份（本模块新增的核心原因码）
REASON_BOUNDARY_BREACH = "trust_boundary_breach_at_untrusted_hop"
#: 候选跳可信 -> 声明层数偏少
REASON_TRUSTED_CANDIDATE = "forwarded_trusted_candidate_underdeclared"
#: 正常采纳候选跳
REASON_FORWARDED_OK = "forwarded_ok"
#: 只有 X-Real-IP 且声明多层：证据不足回退 peer
REASON_XREAL_MULTI = "fallback_peer_x_real_ip_multi_hop_unverified"
#: 单层下 X-Real-IP 正常采纳
REASON_XREAL_OK = "x_real_ip_ok"
#: 单层下 X-Real-IP 解析失败回退 peer
REASON_XREAL_BAD = "fallback_peer_malformed_x_real_ip"


def _clip(text: str, limit: int = TRACE_INPUT_CLIP) -> str:
    if len(text) > limit:
        return text[:limit] + f"...<+{len(text) - limit}chars>"
    return text


def _normalize_ip(raw: str) -> ipaddress._BaseAddress | None:
    """尽力把字符串解析为 IP；返回 None 表示无法解析。

    解析前先按 MAX_TOKEN_CHARS 检查长度（明显异常的超长串直接失败，
    不做无界字符串操作）。IPv4-mapped IPv6 (::ffff:a.b.c.d) 归一化为 IPv4。
    容忍 XFF 中偶发的 "IPv4:port" 写法。
    """
    token = raw.strip()
    if not token or len(token) > MAX_TOKEN_CHARS:
        return None
    # 去掉方括号 IPv6 写法 [::1]
    if token.startswith("[") and token.endswith("]"):
        token = token[1:-1]
    if len(token) > MAX_TOKEN_CHARS:
        return None
    try:
        addr = ipaddress.ip_address(token)
    except ValueError:
        # 容忍 1.2.3.4:port（IPv6 不在此列，避免歧义）
        if token.count(":") == 1:
            host, _, port = token.partition(":")
            if port.isdigit() and len(host.strip()) <= MAX_TOKEN_CHARS:
                try:
                    addr = ipaddress.ip_address(host.strip())
                except ValueError:
                    return None
            else:
                return None
        else:
            return None
    maptoken = getattr(addr, "ipv4_mapped", None)
    return maptoken if maptoken is not None else addr


@dataclass
class ClientIdentity:
    """最终用于限流/拦截维度的客户端身份。"""

    client_id: str
    peer_ip: str
    used_forwarded: bool
    anomalies: tuple[str, ...] = ()
    #: 非 None 时表示该请求应直接被拒绝（如 deny 策略命中）
    deny_reason: str | None = None
    trace: list[TraceStep] = field(default_factory=list)
    #: 机器可区分的稳定结论码（见本模块 REASON_* 常量）
    resolution_reason: str = ""
    #: 信任边界突破点；None 表示未突破。{"hop_index", "boundary_addr",
    #: "boundary_match_right": 其右侧（服务侧方向）命中的白名单条目}
    trust_boundary: dict[str, str | int] | None = None
    #: 声明的可信段校验通过数（0..hop_count-1），用于审计层数是否对得上
    verified_trusted_hops: int = 0

    def as_log_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "peer_ip": self.peer_ip,
            "used_forwarded": self.used_forwarded,
            "anomalies": list(self.anomalies),
            "deny_reason": self.deny_reason,
            "resolution_reason": self.resolution_reason,
            "trust_boundary": self.trust_boundary,
            "verified_trusted_hops": self.verified_trusted_hops,
            "trace": self.trace,
        }


class IdentityResolver:
    """基于逐跳信任校验的多级转发链客户端身份解析器。"""

    def __init__(self, trusted_proxies: tuple[str, ...], hop_count: int = 1,
                 on_untrusted_forwarded: str = "ignore") -> None:
        if hop_count < 1:
            raise ValueError("hop_count 必须 >= 1")
        if on_untrusted_forwarded not in ("ignore", "deny"):
            raise ValueError("on_untrusted_forwarded 必须是 ignore/deny")
        self._networks = [ipaddress.ip_network(t, strict=False) for t in trusted_proxies]
        # 展示与审计保留入参的归一化字符串形式（裸 IP 不被改写成 /32）
        self.trusted_proxies = tuple(str(t) for t in trusted_proxies)
        self.hop_count = hop_count
        self.on_untrusted_forwarded = on_untrusted_forwarded

    def _is_trusted(self, addr: ipaddress._BaseAddress) -> str | None:
        """返回命中的白名单条目字符串；未命中返回 None。"""
        for net in self._networks:
            if addr.version == net.version and addr in net:
                return str(net)
        return None

    def status_dict(self) -> dict:
        """当前生效的信任拓扑配置（供本地状态端点/启动日志/审计使用）。"""
        return {
            "model": "per_hop_trusted_chain",
            "trusted_proxies": list(self.trusted_proxies),
            "declared_hop_count": self.hop_count,
            "on_forwarded_from_untrusted": self.on_untrusted_forwarded,
            "limits": {
                "max_xff_headers": MAX_XFF_HEADERS,
                "max_xff_tokens": MAX_XFF_TOKENS,
                "max_token_chars": MAX_TOKEN_CHARS,
                "max_header_chars": MAX_HEADER_CHARS,
            },
        }

    def resolve(self, peer_ip: str, headers: list[tuple[str, str]]) -> ClientIdentity:
        """headers 为已小写化的 (name, value) 列表。"""
        trace: list[TraceStep] = []
        anomalies: list[str] = []

        peer_addr = _normalize_ip(peer_ip)
        if peer_addr is None:
            # 非 IP 对端（如测试客户端 "testclient"）：直接以对端为身份，
            # 其携带的任何转发头都不可信。
            trace.append({"step": "peer", "input": _clip(peer_ip),
                          "result": "non_ip_peer_not_trusted"})
            return self._untrusted(peer_ip, headers, trace, anomalies,
                                   reason=REASON_NON_IP_PEER)

        match = self._is_trusted(peer_addr)
        trace.append({"step": "peer", "input": str(peer_addr),
                      "result": f"trusted_match={match}" if match else "not_in_trust_list"})
        if match is None:
            return self._untrusted(str(peer_addr), headers, trace, anomalies,
                                   reason=REASON_DIRECT_UNTRUSTED)

        # ---- peer 可信：允许采纳转发信息 ----
        xff_values = [v for k, v in headers if k == XFF_HEADER]
        xreal_values = [v for k, v in headers if k == XREAL_HEADER]

        if xff_values:
            return self._from_xff(str(peer_addr), xff_values, xreal_values,
                                  trace, anomalies)
        if xreal_values:
            return self._from_xreal(str(peer_addr), xreal_values[0], trace, anomalies)

        # 可信代理却没带任何转发头：身份回退为 peer，记录异常（可追溯）
        anomalies.append("missing_forwarded_headers")
        trace.append({"step": "forwarded", "input": "",
                      "result": "no_xff_no_xrealip_fallback_to_peer"})
        return ClientIdentity(str(peer_addr), str(peer_addr), False,
                              tuple(anomalies), None, trace,
                              resolution_reason=REASON_MISSING)

    def _untrusted(self, peer_ip: str, headers, trace, anomalies, *,
                   reason: str) -> ClientIdentity:
        forwarded_present = any(
            k in (XFF_HEADER, XREAL_HEADER) for k, _ in headers)
        if forwarded_present:
            anomalies.append("forwarded_headers_from_untrusted_peer")
            trace.append({
                "step": "forwarded",
                "input": "x-forwarded-for/x-real-ip present",
                "result": f"ignored policy={self.on_untrusted_forwarded}"})
            deny = ("forwarded_headers_from_untrusted_source"
                    if self.on_untrusted_forwarded == "deny" else None)
        else:
            deny = None
        return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies), deny,
                              trace, resolution_reason=reason)

    def _parse_chain(self, xff_values: list[str], anomalies: list[str],
                     trace: list[TraceStep]) -> list[str]:
        """合并多个 XFF 头并切分为条目列表，强制应用资源上界。

        只保留最靠右（最近写入端）的头与条目，因为身份只从服务侧向右数；
        被裁掉的是最左端攻击者最可能灌水的部分，不影响安全结论。
        """
        if len(xff_values) > MAX_XFF_HEADERS:
            anomalies.append("xff_too_many_headers")
            trace.append({"step": XFF_HEADER,
                          "input": f"{len(xff_values)} xff headers",
                          "result": f"keep_last_{MAX_XFF_HEADERS}_headers"})
            xff_values = xff_values[-MAX_XFF_HEADERS:]

        clipped_parts: list[str] = []
        for value in xff_values:
            value = value.strip()
            if len(value) > MAX_HEADER_CHARS:
                anomalies.append("xff_header_value_too_long")
                trace.append({"step": XFF_HEADER,
                              "input": f"header_value len={len(value)}",
                              "result": (f"keep_last_{MAX_HEADER_CHARS}"
                                         "_chars_of_header")})
                # 只保留右侧尾部：身份从右数，左端（攻击者灌水端）丢弃
                value = value[-MAX_HEADER_CHARS:]
            clipped_parts.append(value)
        joined_parts = clipped_parts
        raw = ", ".join(p for p in joined_parts if p)
        raw_tokens = [t.strip() for t in raw.split(",") if t.strip()]
        if len(xff_values) > 1:
            # 多个 XFF 头按接收顺序拼成同一条链（少见，显式留痕）
            anomalies.append("multiple_xff_headers")

        if len(raw_tokens) > MAX_XFF_TOKENS:
            anomalies.append("xff_chain_too_long")
            trace.append({"step": XFF_HEADER, "input": _clip(raw),
                          "result": (f"hops={len(raw_tokens)} "
                                     f"keep_last_{MAX_XFF_TOKENS}_hops")})
            raw_tokens = raw_tokens[-MAX_XFF_TOKENS:]
        else:
            trace.append({"step": XFF_HEADER, "input": _clip(raw),
                          "result": (f"hops={len(raw_tokens)} "
                                     f"declared_hop_count={self.hop_count}")})
        return raw_tokens

    def _from_xff(self, peer_ip: str, xff_values: list[str], xreal_values,
                  trace, anomalies) -> ClientIdentity:
        tokens = self._parse_chain(xff_values, anomalies, trace)
        n = len(tokens)

        # 跳数不足：连候选位置都不存在，回退 peer
        if self.hop_count > n:
            anomalies.append("xff_insufficient_hops")
            trace.append({"step": "select", "input": "",
                          "result": "insufficient_hops_fallback_to_peer"})
            return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies),
                                  None, trace,
                                  resolution_reason=REASON_INSUFFICIENT_HOPS)

        # 从右向左逐跳校验"声明的可信段"：右数第 1..hop_count-1 跳
        # tokens[n-1] 对应右数第 1 跳（紧邻 peer 的代理写入），
        # 与 peer 一样必须可信；依次向左直到右数第 hop_count-1 跳。
        verified = 0
        # offset=1 对应右数第 1 跳 = tokens[n-1]（紧邻 peer 的代理写入）
        for offset in range(1, self.hop_count):
            idx = n - offset
            entry = tokens[idx]
            if len(entry) > MAX_TOKEN_CHARS:
                anomalies.append("malformed_xff_entry")
                anomalies.append("xff_entry_too_long")
                trace.append({"step": "hop_check",
                              "input": f"right#{offset} len={len(entry)}",
                              "result": "entry_exceeds_limit_"
                                        f"{MAX_TOKEN_CHARS}_fallback_to_peer"})
                return ClientIdentity(peer_ip, peer_ip, False,
                                      tuple(anomalies), None, trace,
                                      resolution_reason=REASON_MALFORMED_TRUSTED_SEGMENT,
                                      verified_trusted_hops=verified)
            addr = _normalize_ip(entry)
            if addr is None:
                anomalies.append("malformed_xff_entry")
                trace.append({"step": "hop_check", "input": _clip(entry),
                              "result": (f"right#{offset} unparseable_ip "
                                         "fallback_to_peer")})
                return ClientIdentity(peer_ip, peer_ip, False,
                                      tuple(anomalies), None, trace,
                                      resolution_reason=REASON_MALFORMED_TRUSTED_SEGMENT,
                                      verified_trusted_hops=verified)
            hit = self._is_trusted(addr)
            if hit is None:
                # ---- 信任边界突破 ----
                # 该跳由其右侧（服务侧方向）最近一个可信代理据真实 TCP 对端写入，
                # 请求方无法把它伪造成任意第三方地址；这就是不可伪造的边界身份。
                # 其左侧任何地址一律不采信。
                anomalies.append("untrusted_hop_in_trusted_segment")
                boundary = {
                    "hop_index": offset,
                    "boundary_addr": str(addr),
                    "boundary_match_right": (
                        f"right#{offset - 1}" if offset > 1 else "peer"),
                }
                trace.append({"step": "hop_check", "input": str(addr),
                              "result": (f"right#{offset} not_in_trust_list "
                                         "TRUST_BOUNDARY_BREACH "
                                         "use_boundary_addr_ignore_left")})
                trace.append({"step": "select", "input": str(addr),
                              "result": f"client_id={addr} (boundary)"})
                return ClientIdentity(str(addr), peer_ip, True,
                                      tuple(anomalies), None, trace,
                                      resolution_reason=REASON_BOUNDARY_BREACH,
                                      trust_boundary=boundary,
                                      verified_trusted_hops=verified)
            trace.append({"step": "hop_check", "input": str(addr),
                          "result": f"right#{offset} trusted_match={hit}"})
            verified += 1

        # 可信段全部可信：候选位置 = 右数第 hop_count 跳
        candidate_raw = tokens[n - self.hop_count]
        if len(candidate_raw) > MAX_TOKEN_CHARS:
            anomalies.append("malformed_xff_entry")
            anomalies.append("xff_entry_too_long")
            trace.append({"step": "select",
                          "input": f"candidate len={len(candidate_raw)}",
                          "result": "candidate_exceeds_limit_fallback_to_peer"})
            return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies),
                                  None, trace,
                                  resolution_reason=REASON_MALFORMED_TRUSTED_SEGMENT,
                                  verified_trusted_hops=verified)
        candidate = _normalize_ip(candidate_raw)
        if candidate is None:
            anomalies.append("malformed_xff_entry")
            trace.append({"step": "select", "input": _clip(candidate_raw),
                          "result": "unparseable_ip_fallback_to_peer"})
            return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies),
                                  None, trace,
                                  resolution_reason=REASON_MALFORMED_TRUSTED_SEGMENT,
                                  verified_trusted_hops=verified)

        if self._is_trusted(candidate) is not None:
            # 候选跳仍在白名单：声明层数大概率偏少（真实层数更多）。
            # 采纳它（至少是不可伪造链路上的一跳，不会采到请求方自填地址），
            # 但显式留痕，提示运维 hop_count 与拓扑对不上。
            anomalies.append("candidate_within_trust_boundary")
            trace.append({"step": "select", "input": str(candidate),
                          "result": ("candidate_in_trust_list "
                                     "likely_underdeclared_hop_count "
                                     f"client_id={candidate}")})
            reason = REASON_TRUSTED_CANDIDATE
        else:
            trace.append({"step": "select", "input": str(candidate),
                          "result": f"client_id={candidate}"})
            reason = REASON_FORWARDED_OK
        return ClientIdentity(str(candidate), peer_ip, True, tuple(anomalies),
                              None, trace, resolution_reason=reason,
                              verified_trusted_hops=verified)

    def _from_xreal(self, peer_ip: str, raw: str, trace, anomalies) -> ClientIdentity:
        trace.append({"step": XREAL_HEADER, "input": _clip(raw.strip()),
                      "result": "parse"})
        addr = _normalize_ip(raw)
        if self.hop_count > 1:
            # 多层拓扑下 X-Real-IP 无法逐跳佐证：它是单个值，无法构成链，
            # 无法证明中间每一跳可信。证据不足，回退 peer，绝不放松。
            anomalies.append("x_real_ip_unverified_multi_hop")
            if addr is None:
                anomalies.append("malformed_x_real_ip")
            trace.append({"step": "select", "input": _clip(raw.strip()),
                          "result": ("multi_hop_declared_x_real_ip_cannot_verify"
                                     "_chain_fallback_to_peer")})
            return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies),
                                  None, trace, resolution_reason=REASON_XREAL_MULTI)
        if addr is None:
            anomalies.append("malformed_x_real_ip")
            trace.append({"step": "select", "input": _clip(raw.strip()),
                          "result": "unparseable_ip_fallback_to_peer"})
            return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies),
                                  None, trace, resolution_reason=REASON_XREAL_BAD)
        trace.append({"step": "select", "input": str(addr),
                      "result": f"client_id={addr}"})
        return ClientIdentity(str(addr), peer_ip, True, tuple(anomalies),
                              None, trace, resolution_reason=REASON_XREAL_OK)
