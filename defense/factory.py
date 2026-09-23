"""Factory helpers: build/mount the defense layer and hot-reload its config.

Reload policy
-------------
A candidate config is fully validated *before* the running engine is
touched. On any failure (missing file / bad JSON / invalid rule) the error
is returned and logged with its concrete type while the existing rules and
rate limiter keep running. The only moment protection changes is one
atomic engine swap - it can never be silently "off".
"""

import logging

from starlette.middleware import Middleware

from defense.config import DefenseConfig, default_config, load_config
from defense.engine import DefenseEngine
from defense.errors import RuleConfigError
from defense.middleware import DefenseMiddleware, ENGINE_ATTR

logger = logging.getLogger("defense")


def add_defense_safely(
    app, config_path: str | None = None, clock=None, *, strict: bool = False
) -> tuple[DefenseConfig, str | None]:
    """Mount the layer with an explicit bad-config policy.

    * Missing file          -> safe defaults (rate limiting ON, no rules).
    * Present but invalid   -> CRITICAL alarm + safe defaults; the service
      stays available and rate limiting stays ON (protection is never
      silently all-off). The concrete reason is stored on
      ``app.state.defense_config_error`` and returned.
    * ``strict=True``       -> the error propagates so the process can be
      crashed deliberately (e.g. hardened deployments).
    """
    error: str | None = None
    try:
        config = load_config(config_path)
    except RuleConfigError as exc:
        if strict:
            raise
        error = f"{type(exc).__name__}: {exc}"
        logger.critical(
            "defense_config_invalid kind=%s detail=%s -- FAIL-SAFE STARTUP: "
            "running defaults (rate limiting ON, blocking rules EMPTY). "
            "Fix the config or set REQUEST_DEFENSE_STRICT=1 to fail fast.",
            type(exc).__name__, exc,
        )
        app.state.defense_config_error = error
        config = default_config(config_path)
    else:
        if config.config_path:
            logger.info("defense_enabled config=%s rules=%d",
                        config.config_path, len(config.rules))
        else:
            logger.info("defense_enabled config=<defaults> rules=0")
    build_defense(app, config, clock=clock)
    return config, error


def build_defense(app, config: DefenseConfig, clock=None) -> DefenseEngine:
    engine = DefenseEngine(config, clock=clock)
    setattr(app, ENGINE_ATTR, engine)
    app.user_middleware.insert(
        0, Middleware(DefenseMiddleware, config=config, clock=clock, engine=engine)
    )
    app.middleware_stack = app.build_middleware_stack()
    return engine


def add_defense(app, config_path: str | None = None, clock=None) -> DefenseConfig:
    """Load config (safe defaults when file missing) and mount the layer."""
    config = load_config(config_path)
    if config.config_path:
        logger.info("defense_enabled config=%s rules=%d",
                    config.config_path, len(config.rules))
    else:
        logger.info("defense_enabled config=<defaults> rules=0")
    build_defense(app, config, clock=clock)
    return config


def get_engine(app) -> DefenseEngine | None:
    return getattr(app, ENGINE_ATTR, None)


def reload_defense(app, config_path: str) -> tuple[bool, str]:
    """Hot reload. Returns (ok, message); on failure old protection persists."""
    engine = get_engine(app)
    if engine is None:
        return False, "defense middleware not installed"
    try:
        candidate = load_config(config_path, use_default_if_missing=False)
    except RuleConfigError as exc:
        logger.error("defense_reload_failed kind=%s: %s",
                     type(exc).__name__, exc)
        return False, f"{type(exc).__name__}: {exc}"
    engine.reload(candidate)
    logger.info("defense_reloaded rules=%d rate=%s burst=%s",
                len(candidate.rules), candidate.rate_per_sec, candidate.burst)
    return True, "reloaded"
