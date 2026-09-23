"""Configurable request interception rules.

Rule JSON shape
---------------
A rule file contains a JSON list of rules::

    [
      {
        "id": "block-admin",                 # required, unique, non-empty
        "description": "optional note",
        "reason_code": "admin_area",         # optional machine-readable code
        "match": {"field": "path", "op": "prefix", "value": "/admin"}
      },
      {
        "id": "sqli-in-q",
        "all": [                             # AND-combined matchers
          {"field": "query", "name": "q", "op": "regex",
           "value": "(?i)union\\s+select"}
        ]
      }
    ]

Exactly one of ``match`` / ``all`` must be given.

Fields: ``method`` ``path`` ``header`` ``query`` ``body``.
Operators: ``present`` ``equals`` ``iequals`` ``prefix`` ``suffix``
``contains`` ``regex`` ``in`` (``in`` requires a JSON list value).
For ``header`` / ``query`` the ``name`` key selects the entry (header
names are matched case-insensitively).

Everything checkable (shape, types, regex compilation) is validated at
compile time and raises :class:`RuleSyntaxError`, so a typo can never
silently disable protection.
"""

import re
from dataclasses import dataclass
from typing import Any, Callable

from defense.errors import RuleSyntaxError

_ALLOWED_KEYS = {"id", "description", "reason_code", "match", "all"}
_FIELDS = {"method", "path", "header", "query", "body"}
_OPS = {"present", "equals", "iequals", "prefix", "suffix", "contains", "regex", "in"}
_OPS_NEED_VALUE = _OPS - {"present"}
_MATCHER_KEYS = {"field", "op", "name", "value"}


@dataclass(frozen=True)
class MatchContext:
    method: str
    path: str
    headers: dict[str, str]   # keys already lower-cased
    query: dict[str, str]     # first value per parameter name
    body_snippet: str


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    reason: str
    field: str


@dataclass(frozen=True)
class _Matcher:
    field: str
    op: str
    name: str | None
    value: Any
    regex: re.Pattern[str] | None
    description: str

    def _extract(self, ctx: MatchContext) -> str | None:
        if self.field == "method":
            return ctx.method
        if self.field == "path":
            return ctx.path
        if self.field == "body":
            return ctx.body_snippet
        if self.field == "header":
            return ctx.headers.get((self.name or "").lower())
        if self.field == "query":
            return ctx.query.get(self.name or "")
        return None  # pragma: no cover - field set validated at compile time

    def matches(self, ctx: MatchContext) -> bool:
        target = self._extract(ctx)
        if self.op == "present":
            return target is not None
        if target is None:
            # Missing header/query never equals a configured value.
            return False
        if self.op == "equals":
            return target == self.value
        if self.op == "iequals":
            return target.casefold() == str(self.value).casefold()
        if self.op == "prefix":
            return target.startswith(self.value)
        if self.op == "suffix":
            return target.endswith(self.value)
        if self.op == "contains":
            return self.value in target
        if self.op == "regex":
            assert self.regex is not None
            try:
                return self.regex.search(target) is not None
            except Exception:  # pragma: no cover - search on str is total
                return False
        if self.op == "in":
            return target in self.value
        return False  # pragma: no cover


def _compile_matcher(raw: Any, rule_id: str, index: int) -> _Matcher:
    where = f"rule {rule_id!r} matcher #{index}"
    if not isinstance(raw, dict):
        raise RuleSyntaxError(f"{where}: matcher must be an object")
    unknown = set(raw) - _MATCHER_KEYS
    if unknown:
        raise RuleSyntaxError(f"{where}: unknown keys {sorted(unknown)}")
    field = raw.get("field")
    if field not in _FIELDS:
        raise RuleSyntaxError(f"{where}: field must be one of {sorted(_FIELDS)}")
    op = raw.get("op")
    if op not in _OPS:
        raise RuleSyntaxError(f"{where}: op must be one of {sorted(_OPS)}")
    name = raw.get("name")
    if field in ("header", "query"):
        if not isinstance(name, str) or not name:
            raise RuleSyntaxError(f"{where}: non-empty 'name' required for {field}")
    elif name is not None:
        raise RuleSyntaxError(f"{where}: 'name' only valid for header/query")
    value = raw.get("value")
    compiled_re = None
    if op == "present":
        if value is not None:
            raise RuleSyntaxError(f"{where}: 'present' takes no value")
    else:
        if op == "in":
            if not isinstance(value, list) or not value or not all(
                isinstance(v, str) for v in value
            ):
                raise RuleSyntaxError(f"{where}: 'in' requires a non-empty string list")
        else:
            if not isinstance(value, str) or value == "":
                raise RuleSyntaxError(f"{where}: op {op!r} requires a non-empty string")
        if op == "regex":
            try:
                compiled_re = re.compile(value)
            except re.error as exc:
                raise RuleSyntaxError(f"{where}: invalid regex: {exc}") from exc
    desc = f"{field}" + (f".{name}" if name else "") + f" {op} {value!r}"
    return _Matcher(field, op, name, value, compiled_re, desc)


class CompiledRule:
    """An immutable rule with one matcher or an AND-list of matchers."""

    def __init__(self, raw: dict[str, Any]):
        if not isinstance(raw, dict):
            raise RuleSyntaxError("rule entry must be an object")
        unknown = set(raw) - _ALLOWED_KEYS
        if unknown:
            raise RuleSyntaxError(f"rule: unknown keys {sorted(unknown)}")
        rid = raw.get("id")
        if not isinstance(rid, str) or not rid.strip():
            raise RuleSyntaxError("rule: non-empty string 'id' is required")
        self.id: str = rid
        self.description: str = raw.get("description", "")
        if not isinstance(self.description, str):
            raise RuleSyntaxError(f"rule {rid!r}: description must be a string")
        self.reason_code: str = raw.get("reason_code", f"rule:{rid}")
        if not isinstance(self.reason_code, str) or not self.reason_code.strip():
            raise RuleSyntaxError(f"rule {rid!r}: reason_code must be a non-empty string")
        has_match, has_all = "match" in raw, "all" in raw
        if has_match == has_all:
            raise RuleSyntaxError(
                f"rule {rid!r}: exactly one of 'match' or 'all' is required"
            )
        raw_matchers = raw["all"] if has_all else [raw["match"]]
        if not isinstance(raw_matchers, list) or not raw_matchers:
            raise RuleSyntaxError(f"rule {rid!r}: 'all' must be a non-empty list")
        self.matchers: tuple[_Matcher, ...] = tuple(
            _compile_matcher(m, rid, i) for i, m in enumerate(raw_matchers)
        )

    def evaluate(self, ctx: MatchContext) -> RuleHit | None:
        # All matchers must hit (AND). Evaluate fully so the trail is complete.
        results = [m.matches(ctx) for m in self.matchers]
        if all(results):
            field = self.matchers[0].field
            return RuleHit(rule_id=self.id, reason=self.reason_code, field=field)
        return None


def compile_rules(raw_rules: Any) -> list[CompiledRule]:
    """Validate and compile a raw JSON rules list."""
    if not isinstance(raw_rules, list):
        raise RuleSyntaxError("rules document must be a JSON list of rule objects")
    compiled: list[CompiledRule] = []
    seen: set[str] = set()
    for i, raw in enumerate(raw_rules):
        rule = CompiledRule(raw)
        if rule.id in seen:
            raise RuleSyntaxError(f"rule #{i}: duplicate rule id {rule.id!r}")
        seen.add(rule.id)
        compiled.append(rule)
    return compiled
