"""面向外部请求的防护层：身份判定 -> 规则拦截 -> 限流。"""
from .audit import DecisionHistory
from .config import DefenseConfig, DefenseConfigError
from .identity import ClientIdentity, IdentityResolver
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
    "DecisionHistory",
]
