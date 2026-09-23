"""ASGI adapter around :class:`defense.engine.DefenseEngine`.

Verdict order: identity -> interception rules -> rate limit (see engine).
The middleware owns no mutable state; it delegates to the engine so that
hot reloads affect the instance embedded in the Starlette stack.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from defense.config import DefenseConfig
from defense.engine import DefenseEngine

ENGINE_ATTR = "defense_engine"


class DefenseMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config: DefenseConfig, clock=None, engine=None):
        super().__init__(app)
        # When the factory supplies a shared engine, use it (reload-visible);
        # standalone construction still works by making its own.
        self.engine = engine or DefenseEngine(config, clock=clock)

    def _deny(self, *, status, error, reason, message, request_id,
              retry_after=None, extra_headers=None):
        headers = {"X-Request-ID": request_id}
        if retry_after is not None:
            headers["Retry-After"] = str(max(1, int(retry_after + 0.999999)))
        if extra_headers:
            headers.update(extra_headers)
        return JSONResponse(
            status_code=status,
            content={"error": error, "reason": reason, "message": message,
                     "request_id": request_id},
            headers=headers,
        )

    async def dispatch(self, request: Request, call_next):
        raw_headers = request.scope.get("headers", [])
        headers = {k.decode().lower(): v.decode(errors="replace")
                   for k, v in raw_headers}
        peer_ip = request.scope.get("client")[0] if request.scope.get("client") else None
        cfg = self.engine.config

        verdict = await self.engine.evaluate(
            peer_ip=peer_ip,
            headers=headers,
            method=request.method,
            path=request.url.path,
            query=dict(request.query_params),
            body_fetcher=request.body,
        )

        request.state.defense_client_id = verdict["client"]
        request.state.defense_identity_source = verdict["identity"].source
        request_id = verdict["request_id"]
        outcome = verdict["outcome"]

        if outcome == "deny_rule":
            hit = verdict["hit"]
            return self._deny(
                status=cfg.blocked_status,
                error="rule_blocked",
                reason=hit.reason,
                message=f"Request rejected by interception rule {hit.rule_id}.",
                request_id=request_id,
                extra_headers={"X-Defense-Reason": f"rule:{hit.rule_id}"},
            )
        if outcome == "deny_rule_error":
            return self._deny(
                status=cfg.blocked_status,
                error="rule_internal_error",
                reason="rule_internal_error",
                message="Request rejected: interception rule could not be "
                        "evaluated; contact the operator.",
                request_id=request_id,
            )
        if outcome == "deny_rate":
            d = verdict["decision"]
            return self._deny(
                status=cfg.ratelimit_status,
                error="rate_limited",
                reason="rate_limited",
                message=f"Rate limit exceeded for client {verdict['client']}. "
                        f"Retry after {d.retry_after_seconds}s.",
                request_id=request_id,
                retry_after=d.retry_after,
                extra_headers={
                    "X-RateLimit-Limit": str(d.limit),
                    "X-RateLimit-Remaining": "0",
                    "X-Defense-Reason": "rate_limited",
                },
            )

        response = await call_next(request)
        d = verdict["decision"]
        response.headers["X-RateLimit-Limit"] = str(d.limit)
        response.headers["X-RateLimit-Remaining"] = str(max(d.remaining, 0))
        response.headers["X-Request-ID"] = request_id
        return response
