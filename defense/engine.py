"""Stateless-request / mutable-state split.

``DefenseEngine`` owns the configuration, the (mutable) rate-limit tables
and the verdict logic. The ASGI middleware holds a *reference* to the
engine, so ``reload`` mutating engine state takes effect on the very same
instance that lives inside the built Starlette stack - no stack rebuild
and no window with protection disabled.
"""

import logging
import time
import uuid

from defense.config import DefenseConfig
from defense.identity import resolve_identity
from defense.ratelimit import RateLimitConfig, RateLimiter
from defense.rules import MatchContext

logger = logging.getLogger("defense")

BODY_INSPECT_LIMIT = 8192  # bytes; rules never need the whole payload


class RuleEvaluationError(Exception):
    """A rule raised while evaluating a request (fail-closed, distinct reason)."""

    def __init__(self, rule_id: str):
        super().__init__(f"rule {rule_id} evaluation failed")
        self.rule_id = rule_id


class DefenseEngine:
    def __init__(self, config: DefenseConfig, clock=None):
        self._clock = clock or time.monotonic
        self._config = config
        self._limiter = self._build_limiter(config)

    def _build_limiter(self, config: DefenseConfig) -> RateLimiter:
        return RateLimiter(
            RateLimitConfig(config.rate_per_sec, config.burst),
            max_clients=config.max_clients,
            clock=self._clock,
        )

    @property
    def config(self) -> DefenseConfig:
        return self._config

    def reload(self, config: DefenseConfig) -> None:
        """Swap config and rate-limit tables atomically.

        Rate counters intentionally reset (documented trade-off): limiter
        state is never partially migrated, so counts cannot drift. Existing
        buckets are simply replaced; rules/config swap in the same step.
        """
        self._config = config
        self._limiter = self._build_limiter(config)

    def cleanup_idle_clients(self) -> int:
        return self._limiter.cleanup()

    async def evaluate(self, *, peer_ip, headers, method, path, query, body_fetcher):
        """Run identity -> rules -> rate limit. Returns a verdict dict.

        ``headers``: dict[str,str] with lower-cased names.
        ``body_fetcher``: zero-arg async callable returning bytes, used only
        when a configured rule inspects bodies.
        """
        request_id = headers.get("x-request-id") or uuid.uuid4().hex
        identity = resolve_identity(
            peer_ip, headers, self._config.trusted_networks,
            self._config.forward_depth,
        )
        client = identity.client_id

        # 1) Rules ----------------------------------------------------------
        body_snippet = ""
        needs_body = any(
            m.field == "body" for r in self._config.rules for m in r.matchers
        )
        if needs_body:
            raw = await body_fetcher()
            body_snippet = raw[:BODY_INSPECT_LIMIT].decode("utf-8", errors="replace")
        ctx = MatchContext(method=method, path=path, headers=headers,
                           query=query, body_snippet=body_snippet)

        for rule in self._config.rules:
            try:
                hit = rule.evaluate(ctx)
            except Exception:
                logger.exception("rule_evaluation_error rule_id=%s request_id=%s",
                                 getattr(rule, "id", "?"), request_id)
                return {
                    "outcome": "deny_rule_error",
                    "request_id": request_id,
                    "client": client,
                    "identity": identity,
                }
            if hit is not None:
                logger.info(
                    "defense_verdict request_id=%s peer=%s client_id=%s "
                    "id_source=%s identity_trusted=%s method=%s path=%s "
                    "verdict=deny:rule_blocked rule_id=%s reason=%s field=%s "
                    "trail=%s",
                    request_id, identity.peer, client, identity.source,
                    identity.trusted, method, path, hit.rule_id, hit.reason,
                    hit.field, "|".join(identity.trail),
                )
                return {
                    "outcome": "deny_rule",
                    "request_id": request_id,
                    "client": client,
                    "identity": identity,
                    "hit": hit,
                }

        # 2) Rate limit (blocked traffic never reaches this point) ---------
        decision = self._limiter.check(client)
        if not decision.allowed:
            logger.info(
                "defense_verdict request_id=%s peer=%s client_id=%s "
                "id_source=%s identity_trusted=%s method=%s path=%s "
                "verdict=deny:rate_limited retry_after=%.3f remaining=%d "
                "trail=%s",
                request_id, identity.peer, client, identity.source,
                identity.trusted, method, path, decision.retry_after,
                decision.remaining, "|".join(identity.trail),
            )
            return {
                "outcome": "deny_rate",
                "request_id": request_id,
                "client": client,
                "identity": identity,
                "decision": decision,
            }

        logger.info(
            "defense_verdict request_id=%s peer=%s client_id=%s "
            "id_source=%s identity_trusted=%s method=%s path=%s "
            "verdict=allow remaining=%d trail=%s",
            request_id, identity.peer, client, identity.source,
            identity.trusted, method, path, decision.remaining,
            "|".join(identity.trail),
        )
        return {
            "outcome": "allow",
            "request_id": request_id,
            "client": client,
            "identity": identity,
            "decision": decision,
        }
