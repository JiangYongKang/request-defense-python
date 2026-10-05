"""防护层 ASGI 中间件。

判定顺序（详见 docs/）：
    1. 身份判定（IdentityResolver）
         直连 peer 不可信时携带转发头 -> 按 ignore/deny 策略处理
    2. 规则拦截（RuleEngine）
         命中即拒绝，且不消耗限流令牌（恶意请求不占用正常配额）
    3. 限流（RateLimiter）
         按 client_id 维度约束平均速率与瞬时突发
顺序设计为：恶意请求在最前面被挡下，且无法通过制造命中来耗尽他人令牌。
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from .config import DefenseConfig
from .identity import IdentityResolver
from .ratelimit import RateLimiter
from .rules import RuleEngine

logger = logging.getLogger("request_defense")

# 拒绝原因 -> 稳定的字符串码（可区分、可被调用方程序化处理）
DENY_UNTRUSTED_FORWARDED = "forwarded_headers_from_untrusted_source"
DENY_RULE = "rule_denied"
DENY_RATE_LIMITED = "rate_limited"


async def _json_response(send, status: int, payload: dict[str, Any],
                         extra_headers: list[tuple[bytes, bytes]] | None = None) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = [
        (b"content-type", b"application/json; charset=utf-8"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class DefenseMiddleware:
    """纯 ASGI 中间件：无额外队列，判定与请求处理在同一任务上下文内。"""

    def __init__(self, app, config: DefenseConfig | None = None) -> None:
        self.app = app
        self.config = config or DefenseConfig.from_env()
        self.resolver = IdentityResolver(
            tuple(self.config.trusted_proxies),
            hop_count=self.config.proxy_hop_count,
            on_untrusted_forwarded=self.config.on_forwarded_from_untrusted,
        )
        self.limiter: RateLimiter | None = None
        if self.config.rate_limit_enabled:
            self.limiter = RateLimiter(
                rate_per_second=self.config.rate_per_second,
                burst=self.config.burst,
                max_clients=self.config.max_clients,
                idle_ttl=self.config.client_idle_ttl_seconds,
                sweep_interval=self.config.sweep_interval_seconds,
            )
        self.rules = RuleEngine.load(self.config.rules_file)
        logger.warning(
            "request_defense initialized: %s",
            json.dumps({
                "rate_limit_enabled": self.config.rate_limit_enabled,
                "rate_per_second": self.config.rate_per_second,
                "burst": self.config.burst,
                "trusted_proxies": list(self.config.trusted_proxies),
                "proxy_hop_count": self.config.proxy_hop_count,
                "on_forwarded_from_untrusted": self.config.on_forwarded_from_untrusted,
                "identity": self.resolver.status_dict(),
                "rule_engine": self.rules.status_dict(),
            }, ensure_ascii=False),
        )

    # ---- ASGI ----
    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        scope["defense_middleware"] = self
        started = time.perf_counter()
        headers = self._decode_headers(scope)
        peer_ip, peer_port = self._peer(scope)
        method = scope.get("method", "")
        path = scope.get("path", "")
        query = scope.get("query_string", b"").decode("latin1", errors="replace")

        identity = self.resolver.resolve(peer_ip, headers)
        decision_header = b"allow"
        deny: dict[str, Any] | None = None

        # 1) 身份策略拒绝（伪造转发头 + deny 策略）
        if identity.deny_reason is not None:
            deny = {
                "status": 403,
                "error": DENY_UNTRUSTED_FORWARDED,
                "message": ("直连来源不在可信代理白名单内，却携带了转发头；"
                            "已忽略转发信息并拒绝请求"),
                "retryable": False,
            }
            decision_header = b"deny:untrusted_forwarded"

        # 2) 规则拦截
        match = None
        if deny is None:
            match = self.rules.evaluate(method, path, headers, query,
                                        identity.client_id)
            if match is not None:
                deny = {
                    "status": match.rule.status_code,
                    "error": DENY_RULE,
                    "rule_id": match.rule.id,
                    "rule_reason": match.rule.reason,
                    "detail": match.detail,
                    "message": f"请求命中拦截规则 {match.rule.id}",
                    "retryable": False,
                }
                decision_header = f"deny:rule:{match.rule.id}".encode("ascii", "replace")

        # 3) 限流（被规则拒绝的请求不取令牌）
        rl_result = None
        if deny is None and self.limiter is not None:
            rl_result = self.limiter.check(identity.client_id)
            if not rl_result.allowed:
                deny = {
                    "status": 429,
                    "error": DENY_RATE_LIMITED,
                    "message": "请求超过客户端速率限制",
                    "retry_after_seconds": round(rl_result.retry_after_seconds, 3),
                    "retryable": True,
                    "hint": ("请按 retry_after_seconds / Retry-After 退避后重试；"
                             "该等待仅针对当前客户端维度"),
                }
                decision_header = b"deny:rate_limited"

        self._log_decision(method, path, query, identity, rl_result, match,
                           deny, started)

        if deny is not None:
            extra: list[tuple[bytes, bytes]] = []
            if deny["status"] == 429:
                retry_after = str(max(1, int(round(deny["retry_after_seconds"]))))
                extra.append((b"retry-after", retry_after.encode("ascii")))
            extra.append((b"x-defense-decision", decision_header))
            await _json_response(send, deny["status"], deny, extra)
            return

        # 放行：保持下游接口行为不变，仅追加一个判定结论响应头
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                msg_headers = list(message.get("headers") or [])
                if not any(k.lower() == b"x-defense-decision" for k, _ in msg_headers):
                    msg_headers.append((b"x-defense-decision", decision_header))
                message = dict(message, headers=msg_headers)
            await send(message)

        await self.app(scope, receive, send_wrapper)

    # ---- 工具 ----
    @staticmethod
    def _decode_headers(scope) -> list[tuple[str, str]]:
        decoded: list[tuple[str, str]] = []
        for raw_name, raw_value in scope.get("headers") or []:
            name = raw_name.decode("latin1", errors="replace").lower()
            value = raw_value.decode("latin1", errors="replace")
            decoded.append((name, value))
        return decoded

    @staticmethod
    def _peer(scope) -> tuple[str, int | None]:
        client = scope.get("client")
        if not client:
            return "unknown", None
        return client[0], client[1]

    def _log_decision(self, method, path, query, identity, rl_result, match,
                      deny, started) -> None:
        record: dict[str, Any] = {
            "event": "defense_decision",
            "input": {
                "method": method,
                "path": path,
                "query": query,
                "peer_ip": identity.peer_ip,
                "client_id": identity.client_id,
                "used_forwarded": identity.used_forwarded,
                "anomalies": list(identity.anomalies),
                "resolution_reason": identity.resolution_reason,
                "trust_boundary": identity.trust_boundary,
                "verified_trusted_hops": identity.verified_trusted_hops,
                "identity_trace": identity.trace,
            },
            "rate_limit": None,
            "rule": None,
            "decision": "allow" if deny is None else "deny",
        }
        if rl_result is not None:
            record["rate_limit"] = {
                "reason": rl_result.reason,
                "tokens_before": round(rl_result.tokens_before, 4),
                "tokens_after": round(rl_result.tokens_after, 4),
                "retry_after_seconds": round(rl_result.retry_after_seconds, 4),
            }
        if match is not None:
            record["rule"] = {"id": match.rule.id, "detail": match.detail}
        if deny is not None:
            record["deny"] = {k: v for k, v in deny.items()
                              if k in ("status", "error", "rule_id",
                                       "retry_after_seconds")}
        record["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
        logger.warning(json.dumps(record, ensure_ascii=False))
