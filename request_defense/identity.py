"""反向代理场景下的客户端身份判定。

信任模型（详见 docs/）：
  * 身份判定永远从 TCP 直连对端 ``peer_ip`` 开始，它无法被请求头伪造。
  * 只有 ``peer_ip`` 命中可信代理白名单(IP 或 CIDR)时，
    ``X-Forwarded-For`` / ``X-Real-IP`` 才被允许影响身份。
  * **hop_count 模式（默认，旧行为）**：XFF 链从右向左取（右 = 最近一跳可信代理
    写入的地址），取第 ``hop_count`` 跳作为原始客户端。
  * **chain 模式（多级部分可信链路）**：从 peer 起沿 XFF 从右向左逐跳校验，
    连续的可信跳才允许被"穿过"；遇到的第一个合法但不可信的地址才是客户端，
    其**左侧的任何地址一律不采信**。任何与声明层数不符 / 非法 / 不足的情况
    都回退到请求方无法伪造的来源（peer 或已证实的可信跳），并给出可区分原因码。
  * 转发信息缺失、跳数不足、条目非法等任何异常都记为 anomaly：
    身份回退为直连 peer（过度阻断，绝不放松），判定过程写入 ``trace``。
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

#: 判定链路上的一步 {"step", "input", "result"}
TraceStep = dict[str, str]

XFF_HEADER = "x-forwarded-for"
XREAL_HEADER = "x-real-ip"

# ---- chain 模式稳定原因码（identity_reason，供程序化区分） ----
REASON_DIRECT_PEER = "direct_peer_untrusted"
REASON_DIRECT_PEER_DENY = "direct_peer_untrusted_deny"
REASON_NON_IP_PEER = "non_ip_peer"
REASON_LEGACY_XFF = "legacy_xff_hop_selected"
REASON_LEGACY_XREAL = "legacy_x_real_ip_selected"
REASON_CHAIN_CLIENT_AT_BOUNDARY = "chain_client_at_trust_boundary"
REASON_CHAIN_UNTRUSTED_MID = "chain_untrusted_midhop_fallback"
REASON_CHAIN_TRUSTED_DEPTH_EXHAUSTED = "chain_trusted_depth_exhausted_fallback"
REASON_CHAIN_SHORTER_THAN_DECLARED = "chain_shorter_than_declared_fallback"
REASON_MISSING_FORWARDED = "missing_forwarded_headers_fallback"
REASON_LEGACY_INSUFFICIENT = "legacy_insufficient_hops_fallback"
REASON_MALFORMED_XFF = "malformed_xff_fallback"
REASON_MALFORMED_XREAL = "malformed_x_real_ip_fallback"
REASON_MULTIPLE_XREAL = "multiple_x_real_ip_fallback"


def _normalize_ip(raw: str) -> ipaddress._BaseAddress | None:
    """尽力把字符串解析为 IP；返回 None 表示无法解析。

    IPv4-mapped IPv6 (::ffff:a.b.c.d) 归一化为 IPv4。
    容忍 XFF 中偶发的 "IPv4:port" 写法。
    """
    token = raw.strip()
    if not token:
        return None
    # XFF 条目只能是纯地址；CIDR/接口写法（10.0.0.0/8、10.0.0.1/32）一律非法
    if "/" in token:
        return None
    # 去掉方括号 IPv6 写法 [::1]
    if token.startswith("[") and token.endswith("]"):
        token = token[1:-1]
    try:
        addr = ipaddress.ip_address(token)
    except ValueError:
        # 容忍 1.2.3.4:port（IPv6 不在此列，避免歧义）
        if token.count(":") == 1:
            host, _, port = token.partition(":")
            if port.isdigit():
                try:
                    addr = ipaddress.ip_address(host.strip())
                except ValueError:
                    return None
            else:
                return None
        else:
            return None
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped if mapped is not None else addr


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
    #: 稳定原因码（见模块级 REASON_*），程序化区分"为什么是这个身份"
    reason: str = REASON_DIRECT_PEER
    #: chain 模式下逐跳信任结论；hop_count 模式仅在解析成功时给最终一跳
    #: 每项 {"address", "role": "peer"|"trusted_hop"|"untrusted_hop"|
    #|                     "client"|"ignored_left"|"unparseable",
    #|        "trusted_by": 命中的白名单条目或 None}
    chain: list[dict] = field(default_factory=list)
    #: 越过信任边界的位置：链上第一个不可信（或非法）条目距 XFF 右端的下标
    #: （右端第 1 条 = 1）；None 表示未越过（全可信或未进入链判定）
    trust_boundary_index: int | None = None

    def as_log_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "peer_ip": self.peer_ip,
            "used_forwarded": self.used_forwarded,
            "anomalies": list(self.anomalies),
            "deny_reason": self.deny_reason,
            "reason": self.reason,
            "trust_boundary_index": self.trust_boundary_index,
            "chain": self.chain,
            "trace": self.trace,
        }


class IdentityResolver:
    """基于可信代理白名单 + 跳数/逐跳链校验的客户端身份解析器。

    mode="hop_count"（默认）：完全保持旧行为，固定取 XFF 右数第 hop_count 跳。
    mode="chain"：从 peer 起逐跳向左校验信任（见模块文档串）。
    """

    def __init__(self, trusted_proxies: tuple[str, ...], hop_count: int = 1,
                 on_untrusted_forwarded: str = "ignore",
                 mode: str = "hop_count",
                 max_hops: int = 32,
                 max_header_bytes: int = 8192) -> None:
        if hop_count < 1:
            raise ValueError("hop_count 必须 >= 1")
        if on_untrusted_forwarded not in ("ignore", "deny"):
            raise ValueError("on_untrusted_forwarded 必须是 ignore/deny")
        if mode not in ("hop_count", "chain"):
            raise ValueError("mode 必须是 hop_count/chain")
        if max_hops < 1:
            raise ValueError("max_hops 必须 >= 1")
        if max_header_bytes < 64:
            raise ValueError("max_header_bytes 必须 >= 64")
        self._networks = [ipaddress.ip_network(t, strict=False) for t in trusted_proxies]
        self.hop_count = hop_count
        self.on_untrusted_forwarded = on_untrusted_forwarded
        self.mode = mode
        self.max_hops = max_hops
        self.max_header_bytes = max_header_bytes

    def topology_dict(self) -> dict:
        """当前生效的信任拓扑配置（供状态端点/审计展示）。"""
        return {
            "mode": self.mode,
            "trusted_proxies": [str(n) for n in self._networks],
            "declared_trusted_hops": self.hop_count,
            "max_forward_hops": self.max_hops,
            "max_forward_header_bytes": self.max_header_bytes,
            "on_forwarded_from_untrusted": self.on_untrusted_forwarded,
        }

    def _is_trusted(self, addr: ipaddress._BaseAddress) -> str | None:
        """返回命中的白名单条目字符串；未命中返回 None。"""
        for net in self._networks:
            if addr.version == net.version and addr in net:
                return str(net)
        return None

    def resolve(self, peer_ip: str, headers: list[tuple[str, str]]) -> ClientIdentity:
        """headers 为已小写化的 (name, value) 列表。"""
        trace: list[TraceStep] = []
        anomalies: list[str] = []

        peer_addr = _normalize_ip(peer_ip)
        if peer_addr is None:
            # 非 IP 对端（如测试客户端 "testclient"）：直接以对端为身份，
            # 其携带的任何转发头都不可信。
            trace.append({"step": "peer", "input": peer_ip,
                          "result": "non_ip_peer_not_trusted"})
            ident = self._untrusted(peer_ip, headers, trace, anomalies)
            ident.reason = REASON_NON_IP_PEER
            return ident

        match = self._is_trusted(peer_addr)
        trace.append({"step": "peer", "input": str(peer_addr),
                      "result": f"trusted_match={match}" if match else "not_in_trust_list"})
        if match is None:
            return self._untrusted(str(peer_addr), headers, trace, anomalies)

        # ---- peer 可信：允许采纳转发信息 ----
        xff_values = [v for k, v in headers if k == XFF_HEADER]
        xreal_values = [v for k, v in headers if k == XREAL_HEADER]

        if xff_values:
            if self.mode == "chain":
                return self._from_xff_chain(str(peer_addr), xff_values,
                                            trace, anomalies)
            return self._from_xff(str(peer_addr), xff_values, xreal_values,
                                  trace, anomalies)
        if xreal_values:
            if self.mode == "chain":
                return self._chain_from_xreal(str(peer_addr), xreal_values,
                                              trace, anomalies)
            return self._from_xreal(str(peer_addr), xreal_values[0], trace, anomalies)

        # 可信代理却没带任何转发头：身份回退为 peer，记录异常（可追溯）
        anomalies.append("missing_forwarded_headers")
        trace.append({"step": "forwarded", "input": "",
                      "result": "no_xff_no_xrealip_fallback_to_peer"})
        return ClientIdentity(str(peer_addr), str(peer_addr), False,
                              tuple(anomalies), None, trace,
                              reason=REASON_MISSING_FORWARDED,
                              chain=[{"address": str(peer_addr), "role": "peer",
                                      "trusted_by": match}])

    def _untrusted(self, peer_ip: str, headers, trace, anomalies):
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
            reason = (REASON_DIRECT_PEER_DENY if deny is not None
                      else REASON_DIRECT_PEER)
        else:
            deny = None
            reason = REASON_DIRECT_PEER
        return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies), deny,
                              trace, reason=reason,
                              chain=[{"address": peer_ip,
                                      "role": "peer", "trusted_by": None}])

    def _from_xff(self, peer_ip: str, xff_values: list[str], xreal_values,
                  trace, anomalies) -> ClientIdentity:
        # 多个 XFF 头按接收顺序拼成同一条链（少见，显式留痕）
        raw = ", ".join(xff_values)
        raw_tokens = [t.strip() for t in raw.split(",") if t.strip()]
        if len(xff_values) > 1:
            anomalies.append("multiple_xff_headers")
        trace.append({"step": XFF_HEADER, "input": raw,
                      "result": f"hops={len(raw_tokens)} hop_count={self.hop_count}"})

        if self.hop_count > len(raw_tokens):
            anomalies.append("xff_insufficient_hops")
            trace.append({"step": "select", "input": raw,
                          "result": "insufficient_hops_fallback_to_peer"})
            return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies), None,
                                  trace, reason=REASON_LEGACY_INSUFFICIENT)

        selected_raw = raw_tokens[-self.hop_count]
        selected = _normalize_ip(selected_raw)
        if selected is None:
            anomalies.append("malformed_xff_entry")
            trace.append({"step": "select", "input": selected_raw,
                          "result": "unparseable_ip_fallback_to_peer"})
            return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies), None,
                                  trace, reason=REASON_MALFORMED_XFF)

        trace.append({"step": "select", "input": selected_raw,
                      "result": f"client_id={selected}"})
        return ClientIdentity(str(selected), peer_ip, True, tuple(anomalies), None,
                              trace, reason=REASON_LEGACY_XFF)

    def _from_xreal(self, peer_ip: str, raw: str, trace, anomalies) -> ClientIdentity:
        trace.append({"step": XREAL_HEADER, "input": raw.strip(),
                      "result": "parse"})
        addr = _normalize_ip(raw)
        if addr is None:
            anomalies.append("malformed_x_real_ip")
            trace.append({"step": "select", "input": raw.strip(),
                          "result": "unparseable_ip_fallback_to_peer"})
            return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies), None,
                                  trace, reason=REASON_MALFORMED_XREAL)
        trace.append({"step": "select", "input": raw.strip(),
                      "result": f"client_id={addr}"})
        return ClientIdentity(str(addr), peer_ip, True, tuple(anomalies), None,
                              trace, reason=REASON_LEGACY_XREAL)

    # ------------------------------------------------------------------
    # chain 模式：多级部分可信转发链路
    # ------------------------------------------------------------------
    def _parse_xff_bounded(self, xff_values: list[str],
                           trace: list[TraceStep],
                           anomalies: list[str]) -> list[str]:
        """把若干 XFF 头解析为右对齐的、有上界的原始 token 列表。

        安全上界（两条独立保证）：
          * 原始字节总量超过 ``max_header_bytes``：只保留右端尾部，
            被丢弃的左段（请求方侧）绝不可能被选为身份；
          * token 数超过 ``max_hops``：同样只保留右端 ``max_hops`` 条；
          * 多个 XFF 头：记 ``multiple_xff_headers``。
        """
        if len(xff_values) > 1:
            anomalies.append("multiple_xff_headers")
        # 按接收顺序还原链；同时统计原始字节（latin1 长度==字节数）
        raw = ", ".join(xff_values)
        raw_bytes = raw.encode("latin1", errors="replace")
        if len(raw_bytes) > self.max_header_bytes:
            anomalies.append("xff_header_too_long_truncated_left")
            # 只保留右端字节预算内的尾部，并在首个逗号处对齐，
            # 避免把一个被半截切断的 token 当作地址解析
            tail = raw_bytes[-self.max_header_bytes:].decode(
                "latin1", errors="replace")
            comma = tail.find(",")
            raw = tail[comma + 1:] if comma != -1 else ""

        tokens = [t.strip() for t in raw.split(",") if t.strip()]
        truncated_by_bytes = "xff_header_too_long_truncated_left" in anomalies
        if len(tokens) > self.max_hops:
            anomalies.append("xff_too_many_hops_truncated_left")
            tokens = tokens[-self.max_hops:]
        trace.append({
            "step": XFF_HEADER,
            "input": raw[:256] + ("…<truncated-in-trace>" if len(raw) > 256 else ""),
            "result": (f"hops={len(tokens)} declared={self.hop_count} "
                       f"byte_truncated={truncated_by_bytes}"),
        })
        return tokens

    def _from_xff_chain(self, peer_ip: str, xff_values: list[str],
                        trace, anomalies) -> ClientIdentity:
        """逐跳信任校验，详见模块文档串。"""
        tokens = self._parse_xff_bounded(xff_values, trace, anomalies)
        chain: list[dict] = [
            {"address": peer_ip, "role": "peer",
             "trusted_by": self._is_trusted(ipaddress.ip_address(peer_ip))}]
        # 已证实的最近可信跳：任何失败都回退到它（它是请求方无法伪造的来源）
        last_safe = peer_ip

        n = len(tokens)
        for i in range(1, self.hop_count + 1):
            if i > n:
                # 声明的可信层数大于实际链长：层数对不上，安全回退
                anomalies.append("xff_declared_hops_exceed_chain")
                trace.append({"step": "chain_walk", "input": "",
                              "result": f"declared={self.hop_count} "
                                        f"actual={n} fallback_to={last_safe}"})
                return self._chain_identity(
                    last_safe, peer_ip, chain, anomalies, trace,
                    reason=REASON_CHAIN_TRUSTED_DEPTH_EXHAUSTED,
                    boundary=None)
            token = tokens[-i]
            addr = _normalize_ip(token)
            if addr is None:
                # 非法条目：该跳无法被证实为可信代理，其左侧全部不可采信
                anomalies.append("malformed_xff_entry")
                chain.append({"address": token[:64], "role": "unparseable",
                              "trusted_by": None})
                trace.append({"step": "chain_walk", "input": token[:64],
                              "result": f"unparseable_at_hop={i} "
                                        f"fallback_to={last_safe}"})
                return self._chain_identity(
                    last_safe, peer_ip, chain, anomalies, trace,
                    reason=REASON_MALFORMED_XFF, boundary=i)
            trusted_by = self._is_trusted(addr)
            if trusted_by is None:
                # 第一个不可信合法地址：
                #   i == hop_count -> 它正是声明层数指向的客户端位置，采纳
                #   i <  hop_count -> 中间夹了不可信跳，左侧全部不采信，回退
                chain.append({"address": str(addr),
                              "role": "client" if i == self.hop_count
                                     else "untrusted_hop",
                              "trusted_by": None})
                self._mark_ignored_left(chain, tokens, i)
                if i == self.hop_count:
                    trace.append({"step": "chain_walk", "input": str(addr),
                                  "result": f"client_at_boundary hop={i}"})
                    return self._chain_identity(
                        str(addr), peer_ip, chain, anomalies, trace,
                        reason=REASON_CHAIN_CLIENT_AT_BOUNDARY,
                        boundary=i, used_forwarded=True)
                anomalies.append("xff_untrusted_midhop")
                trace.append({"step": "chain_walk", "input": str(addr),
                              "result": f"untrusted_midhop={i} "
                                        f"declared={self.hop_count} "
                                        f"fallback_to={last_safe}"})
                return self._chain_identity(
                    last_safe, peer_ip, chain, anomalies, trace,
                    reason=REASON_CHAIN_UNTRUSTED_MID, boundary=i)
            # 合法且可信：穿过这一跳，继续向左
            chain.append({"address": str(addr), "role": "trusted_hop",
                          "trusted_by": trusted_by})
            last_safe = str(addr)

        # 连续 hop_count 跳全部可信，却还有更左的条目：
        # 真实可信层数 > 声明层数（配少了）。该左条目可能是请求方自己带进来的，
        # 绝不采信 -> 回退到最近的已证实可信跳。
        if n > self.hop_count:
            anomalies.append("xff_declared_hops_less_than_chain")
            self._mark_ignored_left(chain, tokens, self.hop_count)
            trace.append({"step": "chain_walk", "input": tokens[-self.hop_count - 1][:64],
                          "result": f"extra_left_entry_after_{self.hop_count}"
                                    f"_trusted_hops fallback_to={last_safe}"})
            return self._chain_identity(
                last_safe, peer_ip, chain, anomalies, trace,
                reason=REASON_CHAIN_SHORTER_THAN_DECLARED,
                boundary=self.hop_count + 1)

        # 链恰好由 hop_count 个可信跳组成、没有客户端条目：
        # 没有可采纳的转发身份，回退到最近可信跳
        anomalies.append("xff_declared_hops_exceed_chain")
        trace.append({"step": "chain_walk", "input": "",
                      "result": f"all_{n}_hops_trusted_no_client "
                                f"fallback_to={last_safe}"})
        return self._chain_identity(
            last_safe, peer_ip, chain, anomalies, trace,
            reason=REASON_CHAIN_TRUSTED_DEPTH_EXHAUSTED, boundary=None)

    @staticmethod
    def _mark_ignored_left(chain: list[dict], tokens: list[str],
                           boundary_from_right: int) -> None:
        """把信任边界左侧的原始条目标记为 ignored_left（仅留痕，不参与身份）。"""
        left_count = len(tokens) - boundary_from_right
        for j in range(left_count):
            chain.append({"address": tokens[j][:64],
                          "role": "ignored_left", "trusted_by": None})

    @staticmethod
    def _chain_identity(client_id: str, peer_ip: str, chain, anomalies, trace,
                        *, reason: str, boundary: int | None,
                        used_forwarded: bool = False) -> ClientIdentity:
        return ClientIdentity(client_id, peer_ip, used_forwarded,
                              tuple(anomalies), None, trace, reason=reason,
                              chain=chain, trust_boundary_index=boundary)

    def _chain_from_xreal(self, peer_ip: str, xreal_values: list[str],
                          trace, anomalies) -> ClientIdentity:
        """chain 模式下 X-Real-IP 只有一跳信息：peer 可信才采纳，重复头安全回退。"""
        match = self._is_trusted(ipaddress.ip_address(peer_ip))
        chain: list[dict] = [
            {"address": peer_ip, "role": "peer", "trusted_by": match}]
        if len(xreal_values) > 1:
            anomalies.append("multiple_x_real_ip_headers")
            trace.append({"step": XREAL_HEADER,
                          "input": f"{len(xreal_values)} headers",
                          "result": "multiple_x_real_ip_fallback_to_peer"})
            return self._chain_identity(
                peer_ip, peer_ip, chain, anomalies, trace,
                reason=REASON_MULTIPLE_XREAL, boundary=None)
        raw = xreal_values[0]
        trace.append({"step": XREAL_HEADER, "input": raw.strip()[:64],
                      "result": "single_hop_only"})
        addr = _normalize_ip(raw)
        if addr is None:
            anomalies.append("malformed_x_real_ip")
            chain.append({"address": raw.strip()[:64], "role": "unparseable",
                          "trusted_by": None})
            return self._chain_identity(
                peer_ip, peer_ip, chain, anomalies, trace,
                reason=REASON_MALFORMED_XREAL, boundary=1)
        chain.append({"address": str(addr), "role": "client", "trusted_by": None})
        trace.append({"step": "select", "input": str(addr),
                      "result": "client_from_x_real_ip"})
        return self._chain_identity(
            str(addr), peer_ip, chain, anomalies, trace,
            reason=REASON_CHAIN_CLIENT_AT_BOUNDARY, boundary=1,
            used_forwarded=True)
