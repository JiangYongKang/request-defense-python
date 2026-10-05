"""面向外部请求的防护层：身份判定 -> 规则拦截 -> 限流。"""
from .config import DefenseConfig, DefenseConfigError
from .identity import (
    ClientIdentity,
    IdentityResolver,
    REASON_BOUNDARY_BREACH,
    REASON_DIRECT_UNTRUSTED,
    REASON_FORWARDED_OK,
    REASON_INSUFFICIENT_HOPS,
    REASON_MALFORMED_TRUSTED_SEGMENT,
    REASON_MISSING,
    REASON_NON_IP_PEER,
    REASON_TRUSTED_CANDIDATE,
    REASON_XREAL_BAD,
    REASON_XREAL_MULTI,
    REASON_XREAL_OK,
)
from .ratelimit import RateLimiter, RateLimitResult, TokenBucket
from .rules import RuleEngine, RuleMatch
from .middleware import DefenseMiddleware

__all__ = [
    "DefenseConfig",
    "DefenseConfigError",
    "ClientIdentity",
    "IdentityResolver",
    "RateLimiter",
    "RateLimitResult",
    "TokenBucket",
    "RuleEngine",
    "RuleMatch",
    "DefenseMiddleware",
    "REASON_BOUNDARY_BREACH",
    "REASON_DIRECT_UNTRUSTED",
    "REASON_FORWARDED_OK",
    "REASON_INSUFFICIENT_HOPS",
    "REASON_MALFORMED_TRUSTED_SEGMENT",
    "REASON_MISSING",
    "REASON_NON_IP_PEER",
    "REASON_TRUSTED_CANDIDATE",
    "REASON_XREAL_BAD",
    "REASON_XREAL_MULTI",
    "REASON_XREAL_OK",
]
