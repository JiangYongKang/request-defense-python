"""反向代理场景下的客户端身份判定。

信任模型（详见 docs/）：
  * 身份判定永远从 TCP 直连对端 ``peer_ip`` 开始，它无法被请求头伪造。
  * 只有 ``peer_ip`` 命中可信代理白名单(IP 或 CIDR)时，
    ``X-Forwarded-For`` / ``X-Real-IP`` 才被允许影响身份。
  * XFF 链从右向左取（右 = 最近一跳可信代理写入的地址），
    取第 ``hop_count`` 跳作为原始客户端；左侧客户端自填的条目不影响结果。
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


def _normalize_ip(raw: str) -> ipaddress._BaseAddress | None:
    """尽力把字符串解析为 IP；返回 None 表示无法解析。

    IPv4-mapped IPv6 (::ffff:a.b.c.d) 归一化为 IPv4。
    容忍 XFF 中偶发的 "IPv4:port" 写法。
    """
    token = raw.strip()
    if not token:
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

    def as_log_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "peer_ip": self.peer_ip,
            "used_forwarded": self.used_forwarded,
            "anomalies": list(self.anomalies),
            "deny_reason": self.deny_reason,
            "trace": self.trace,
        }


class IdentityResolver:
    """基于可信代理白名单 + 跳数的客户端身份解析器。"""

    def __init__(self, trusted_proxies: tuple[str, ...], hop_count: int = 1,
                 on_untrusted_forwarded: str = "ignore") -> None:
        if hop_count < 1:
            raise ValueError("hop_count 必须 >= 1")
        if on_untrusted_forwarded not in ("ignore", "deny"):
            raise ValueError("on_untrusted_forwarded 必须是 ignore/deny")
        self._networks = [ipaddress.ip_network(t, strict=False) for t in trusted_proxies]
        self.hop_count = hop_count
        self.on_untrusted_forwarded = on_untrusted_forwarded

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
            return self._untrusted(peer_ip, headers, trace, anomalies)

        match = self._is_trusted(peer_addr)
        trace.append({"step": "peer", "input": str(peer_addr),
                      "result": f"trusted_match={match}" if match else "not_in_trust_list"})
        if match is None:
            return self._untrusted(str(peer_addr), headers, trace, anomalies)

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
                              tuple(anomalies), None, trace)

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
        else:
            deny = None
        return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies), deny, trace)

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
            return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies), None, trace)

        selected_raw = raw_tokens[-self.hop_count]
        selected = _normalize_ip(selected_raw)
        if selected is None:
            anomalies.append("malformed_xff_entry")
            trace.append({"step": "select", "input": selected_raw,
                          "result": "unparseable_ip_fallback_to_peer"})
            return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies), None, trace)

        trace.append({"step": "select", "input": selected_raw,
                      "result": f"client_id={selected}"})
        return ClientIdentity(str(selected), peer_ip, True, tuple(anomalies), None, trace)

    def _from_xreal(self, peer_ip: str, raw: str, trace, anomalies) -> ClientIdentity:
        trace.append({"step": XREAL_HEADER, "input": raw.strip(),
                      "result": "parse"})
        addr = _normalize_ip(raw)
        if addr is None:
            anomalies.append("malformed_x_real_ip")
            trace.append({"step": "select", "input": raw.strip(),
                          "result": "unparseable_ip_fallback_to_peer"})
            return ClientIdentity(peer_ip, peer_ip, False, tuple(anomalies), None, trace)
        trace.append({"step": "select", "input": raw.strip(),
                      "result": f"client_id={addr}"})
        return ClientIdentity(str(addr), peer_ip, True, tuple(anomalies), None, trace)
