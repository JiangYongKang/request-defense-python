"""配置加载（环境变量驱动）。

任何环境变量取值非法都会在启动时抛出 ``DefenseConfigError``：
宁可启动失败并给出明确原因，也不静默使用一个"关闭防护"的错误配置。
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass

_TRUE = {"1", "true", "yes", "on", "y", "t"}
_FALSE = {"0", "false", "no", "off", "n", "f", ""}
_UNTRUSTED_FORWARD_POLICIES = ("ignore", "deny")
_FORWARD_TRUST_MODES = ("hop_count", "chain")


class DefenseConfigError(ValueError):
    """环境变量配置非法。异常消息可直接用于定位具体配置项。"""


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    low = raw.strip().lower()
    if low in _TRUE:
        return True
    if low in _FALSE:
        return False
    raise DefenseConfigError(
            f"{name} 必须是布尔值(true/false/1/0)，实际为: {raw!r}")


def _get_float(name: str, default: float, *, positive: bool) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise DefenseConfigError(f"{name} 必须是数字，实际为: {raw!r}") from exc
    if positive and value <= 0:
        raise DefenseConfigError(f"{name} 必须为正数，实际为: {value}")
    return value


def _get_int(name: str, default: int, *, minimum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise DefenseConfigError(f"{name} 必须是整数，实际为: {raw!r}") from exc
    if value < minimum:
        raise DefenseConfigError(f"{name} 必须 >= {minimum}，实际为: {value}")
    return value


def _get_choice(name: str, default: str, choices: tuple[str, ...]) -> str:
    raw = os.environ.get(name)
    if raw is None:
        return default
    if raw.strip().lower() not in choices:
        raise DefenseConfigError(
                f"{name} 必须是 {choices} 之一，实际为: {raw!r}")
    return raw.strip().lower()


def parse_trusted_proxies(raw: str | None) -> tuple[str, ...]:
    """解析逗号分隔的可信代理 IP/CIDR 列表，并归一化。

    非法条目抛 ``DefenseConfigError``，保证不会带着坏配置进入运行期。
    """
    if not raw or not raw.strip():
        return ()
    normalized: list[str] = []
    seen: set[str] = set()
    for item in raw.split(","):
        token = item.strip()
        if not token:
            continue
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                norm = str(net)
            else:
                norm = str(ipaddress.ip_address(token))
        except ValueError as exc:
            raise DefenseConfigError(
                    f"DEFENSE_TRUSTED_PROXIES 含非法 IP/CIDR 条目: {token!r}") from exc
        if norm not in seen:
            seen.add(norm)
            normalized.append(norm)
    return tuple(normalized)


@dataclass(frozen=True)
class DefenseConfig:
    # ---- 限流 ----
    rate_limit_enabled: bool = True
    rate_per_second: float = 5.0
    burst: int = 10
    # ---- 身份 / 信任模型 ----
    #: 可信代理的 IP/CIDR 白名单（归一化字符串）
    trusted_proxies: tuple[str, ...] = ()
    #: 可信链上取倒数第几跳作为客户端（1 = 紧邻代理写入的那一跳）
    proxy_hop_count: int = 1
    #: 直连来源（不在白名单）携带转发头时的策略：ignore 忽略 / deny 拒绝
    on_forwarded_from_untrusted: str = "ignore"
    #: 转发链信任模式：
    #:   hop_count —— 旧行为：固定从 XFF 右侧取第 proxy_hop_count 跳
    #:   chain     —— 逐跳信任校验：从 peer 起每一跳都必须可信，
    #:                 第一个不可信跳才作为客户端，其左侧任何地址一律不采信
    forward_trust_mode: str = "hop_count"
    #: chain 模式下最多解析的 XFF 条目数（超出部分视为左侧伪造内容直接丢弃）
    max_forward_hops: int = 32
    #: 所有转发头原始字节总长度上限（防超长链打满解析耗时/内存）
    max_forward_header_bytes: int = 8192
    #: 本地判定历史保留条数（0=关闭；仅 /__defense/decisions 查询用）
    decision_history_size: int = 0
    # ---- 规则 ----
    rules_file: str | None = None
    # ---- 资源回收 ----
    max_clients: int = 100_000
    client_idle_ttl_seconds: float = 300.0
    sweep_interval_seconds: float = 60.0

    @classmethod
    def from_env(cls) -> "DefenseConfig":
        return cls(
            rate_limit_enabled=_get_bool("DEFENSE_RATE_LIMIT_ENABLED", True),
            rate_per_second=_get_float("DEFENSE_RATE_PER_SECOND", 5.0, positive=True),
            burst=_get_int("DEFENSE_BURST", 10, minimum=1),
            trusted_proxies=parse_trusted_proxies(os.environ.get("DEFENSE_TRUSTED_PROXIES")),
            proxy_hop_count=_get_int("DEFENSE_PROXY_HOP_COUNT", 1, minimum=1),
            on_forwarded_from_untrusted=_get_choice(
                "DEFENSE_ON_FORWARDED_FROM_UNTRUSTED", "ignore",
                _UNTRUSTED_FORWARD_POLICIES),
            forward_trust_mode=_get_choice(
                "DEFENSE_FORWARD_TRUST_MODE", "hop_count",
                _FORWARD_TRUST_MODES),
            max_forward_hops=_get_int("DEFENSE_MAX_FORWARD_HOPS", 32, minimum=1),
            max_forward_header_bytes=_get_int(
                "DEFENSE_MAX_FORWARD_HEADER_BYTES", 8192, minimum=64),
            decision_history_size=_get_int(
                "DEFENSE_DECISION_HISTORY_SIZE", 0, minimum=0),
            rules_file=(os.environ.get("DEFENSE_RULES_FILE") or None),
            max_clients=_get_int("DEFENSE_MAX_CLIENTS", 100_000, minimum=1),
            client_idle_ttl_seconds=_get_float(
                "DEFENSE_CLIENT_IDLE_TTL", 300.0, positive=True),
            sweep_interval_seconds=_get_float(
                "DEFENSE_SWEEP_INTERVAL", 60.0, positive=True),
        )
