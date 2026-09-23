"""Defense layer configuration loading.

JSON config shape (every key optional)::

    {
      "rate_limit": {"rate_per_sec": 5.0, "burst": 10},
      "trusted_proxies": ["10.0.0.0/8", "203.0.113.5"],
      "forward_depth": 1,
      "max_clients": 10000,
      "status_codes": {"blocked": 403, "rate_limited": 429},
      "rules_file": "rules.json",
      "rules": [ {"id": "...", "match": {...}} ]
    }

Failure policy (explicit, never silent)
---------------------------------------
* ``load_config(None)``             -> built-in safe defaults (no proxies
  trusted, no blocking rules). Protection stays ON with rate limiting.
* Explicitly given/default file missing
  -> :class:`ConfigFileNotFound`: the caller decides defaults vs fail-fast.
* Unreadable / bad JSON / bad shape -> a distinct :class:`RuleConfigError`
  subclass. The previously loaded ruleset is kept by the running service
  (see factory reload), protection is never silently switched off.
"""

import ipaddress
import json
import os
from dataclasses import dataclass, field

from defense.errors import RuleConfigError, RuleFileError, RuleSyntaxError
from defense.rules import CompiledRule, compile_rules

DEFAULT_RATE = 5.0
DEFAULT_BURST = 10
DEFAULT_MAX_CLIENTS = 10_000
DEFAULT_FORWARD_DEPTH = 1
DEFAULT_BLOCKED_STATUS = 403
DEFAULT_RATELIMIT_STATUS = 429
DEFAULT_CONFIG_PATH = os.environ.get("REQUEST_DEFENSE_CONFIG", "defense_config.json")


class ConfigFileNotFound(RuleConfigError):
    """Referenced config file does not exist."""


class ConfigSyntaxError(RuleConfigError):
    """Config file is not valid JSON or has wrong shape/values."""


@dataclass(frozen=True)
class RateLimitSettings:
    rate_per_sec: float
    burst: int


@dataclass(frozen=True)
class DefenseConfig:
    rate_per_sec: float = DEFAULT_RATE
    burst: int = DEFAULT_BURST
    trusted_networks: tuple = ()   # tuple[IPv4Network | IPv6Network]
    forward_depth: int = DEFAULT_FORWARD_DEPTH
    max_clients: int = DEFAULT_MAX_CLIENTS
    rules: tuple[CompiledRule, ...] = field(default_factory=tuple)
    blocked_status: int = DEFAULT_BLOCKED_STATUS
    ratelimit_status: int = DEFAULT_RATELIMIT_STATUS
    config_path: str | None = None

    @property
    def rate_limit_settings(self) -> RateLimitSettings:
        return RateLimitSettings(self.rate_per_sec, self.burst)


def default_config(config_path: str | None = None) -> DefenseConfig:
    """Safe defaults: only the unspoofable peer is trusted, no rules."""
    return DefenseConfig(config_path=config_path)


def _read_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError as exc:
        raise ConfigFileNotFound(f"config file not found: {path}") from exc
    except OSError as exc:
        raise RuleFileError(f"config file unreadable: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuleFileError(
            f"config file is not valid JSON ({path}): line {exc.lineno}: {exc.msg}"
        ) from exc


def _parse_networks(values, where: str) -> tuple:
    if not isinstance(values, list):
        raise ConfigSyntaxError(f"{where}: must be a list of IP/CIDR strings")
    nets = []
    for v in values:
        if not isinstance(v, str):
            raise ConfigSyntaxError(f"{where}: entries must be strings, got {v!r}")
        try:
            nets.append(ipaddress.ip_network(v, strict=False))
        except ValueError as exc:
            raise ConfigSyntaxError(f"{where}: invalid network {v!r}: {exc}") from exc
    return tuple(nets)


def _load_rules_from_file(path: str):
    data = _read_json(path)
    try:
        return compile_rules(data)
    except RuleSyntaxError as exc:
        raise RuleSyntaxError(f"rules file {path!r}: {exc}") from exc


def parse_config(data, source_path: str | None = None) -> DefenseConfig:
    """Validate a decoded JSON object and build a DefenseConfig."""
    if not isinstance(data, dict):
        raise ConfigSyntaxError("top-level config must be a JSON object")
    unknown = set(data) - {
        "rate_limit", "trusted_proxies", "forward_depth", "max_clients",
        "status_codes", "rules_file", "rules",
    }
    if unknown:
        raise ConfigSyntaxError(f"unknown config keys: {sorted(unknown)}")

    rate, burst = DEFAULT_RATE, DEFAULT_BURST
    rl = data.get("rate_limit", {})
    if not isinstance(rl, dict):
        raise ConfigSyntaxError("rate_limit must be an object")
    rate = rl.get("rate_per_sec", rate)
    burst = rl.get("burst", burst)
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or rate <= 0:
        raise ConfigSyntaxError("rate_limit.rate_per_sec must be a positive number")
    if isinstance(burst, bool) or not isinstance(burst, int) or burst <= 0:
        raise ConfigSyntaxError("rate_limit.burst must be a positive integer")

    depth = data.get("forward_depth", DEFAULT_FORWARD_DEPTH)
    if isinstance(depth, bool) or not isinstance(depth, int) or depth < 1:
        raise ConfigSyntaxError("forward_depth must be a positive integer (>= 1)")

    max_clients = data.get("max_clients", DEFAULT_MAX_CLIENTS)
    if isinstance(max_clients, bool) or not isinstance(max_clients, int) or max_clients <= 0:
        raise ConfigSyntaxError("max_clients must be a positive integer")

    nets = _parse_networks(data.get("trusted_proxies", []), "trusted_proxies")

    blocked, limited = DEFAULT_BLOCKED_STATUS, DEFAULT_RATELIMIT_STATUS
    codes = data.get("status_codes", {})
    if not isinstance(codes, dict):
        raise ConfigSyntaxError("status_codes must be an object")
    for key, attr in (("blocked", "blocked"), ("rate_limited", "limited")):
        if key in codes:
            val = codes[key]
            if isinstance(val, bool) or not isinstance(val, int) or not (100 <= val <= 599):
                raise ConfigSyntaxError(f"status_codes.{key} must be an integer 100-599")
            if key == "blocked":
                blocked = val
            else:
                limited = val

    rules: list[CompiledRule] = []
    inline = data.get("rules", [])
    if inline:
        try:
            rules.extend(compile_rules(inline))
        except RuleSyntaxError as exc:
            raise RuleSyntaxError(f"inline rules: {exc}") from exc
    rules_file = data.get("rules_file")
    if rules_file is not None:
        if not isinstance(rules_file, str) or not rules_file.strip():
            raise ConfigSyntaxError("rules_file must be a non-empty string")
        rules.extend(_load_rules_from_file(rules_file))

    return DefenseConfig(
        rate_per_sec=float(rate),
        burst=burst,
        trusted_networks=nets,
        forward_depth=depth,
        max_clients=max_clients,
        rules=tuple(rules),
        blocked_status=blocked,
        ratelimit_status=limited,
        config_path=source_path,
    )


def load_config(path: str | None = None, *, use_default_if_missing: bool = True) -> DefenseConfig:
    """Load configuration.

    ``path=None`` -> safe defaults.
    A missing file is ignored only when ``use_default_if_missing`` is True;
    every other loading/validation failure propagates as a distinct
    :class:`RuleConfigError` subclass.
    """
    if path is None:
        return default_config()
    try:
        data = _read_json(path)
    except ConfigFileNotFound:
        if use_default_if_missing:
            return default_config(path)
        raise
    return parse_config(data, source_path=path)
