"""可配置请求拦截规则引擎。

规则文件为 JSON，顶层结构：
    {"version": 1, "rules": [ {规则}, ... ]}

单条规则字段：
    id            规则唯一标识（字符串，必填）
    field         method | path | path_prefix | header | query | ip
    match         equals | prefix | regex | contains | cidr
    value         比较值（字符串，必填）
    header_name   field=header 时指定头名（大小写不敏感）
    status_code   命中后返回的 HTTP 状态码（默认 403，允许 400-499）
    reason        对外暴露的拒绝原因（默认 blocked_by_rule）

失败处理策略（可预期、绝不静默）：
  * 未配置 DEFENSE_RULES_FILE      -> loaded=None，空规则，状态 "no_rules_configured"
  * 文件不存在                     -> loaded=False，空规则，状态 "rules_file_missing"
  * JSON/结构非法（整体不可用）    -> loaded=False，空规则/保留旧规则，load_error 有值
  * 部分规则非法                   -> loaded=True，非法条目逐条进入 invalid_rules，
                                      合法规则照常生效，绝不因一条坏规则关掉全部防护
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

VALID_FIELDS = ("method", "path", "path_prefix", "header", "query", "ip")
VALID_MATCHERS = ("equals", "prefix", "regex", "contains", "cidr")

# field -> 允许的 match 集合
_ALLOWED: dict[str, tuple[str, ...]] = {
    "method": ("equals",),
    "path": ("equals", "prefix", "regex", "contains"),
    "path_prefix": ("prefix",),
    "header": ("equals", "contains", "regex"),
    "query": ("equals", "contains", "regex"),
    "ip": ("cidr", "equals"),
}


@dataclass(frozen=True)
class Rule:
    id: str
    field: str
    match: str
    value: str
    header_name: str | None = None
    status_code: int = 403
    reason: str = "blocked_by_rule"
    # 预编译产物
    regex: re.Pattern[str] | None = field(default=None, compare=False, repr=False)
    network: ipaddress._BaseNetwork | None = field(default=None, compare=False, repr=False)


@dataclass
class RuleMatch:
    rule: Rule
    detail: str


@dataclass
class InvalidRule:
    index: int
    rule_id: str | None
    error: str
    raw: Any


@dataclass
class RuleEngine:
    rules: list[Rule] = field(default_factory=list)
    #: None=从未配置/未尝试；True=加载成功；False=整体加载失败
    loaded: bool | None = None
    status: str = "no_rules_configured"
    load_error: str | None = None
    invalid_rules: list[InvalidRule] = field(default_factory=list)
    source_path: str | None = None

    # ---- 加载 ----
    @classmethod
    def load(cls, path: str | None) -> "RuleEngine":
        if path is None:
            return cls(status="no_rules_configured")
        engine = cls(source_path=path)
        if not os.path.exists(path):
            engine.loaded = False
            engine.status = "rules_file_missing"
            engine.load_error = f"规则文件不存在: {path}"
            return engine
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            engine.loaded = False
            engine.status = "rules_file_invalid_json"
            engine.load_error = f"规则文件不是合法 JSON (line {exc.lineno} col {exc.colno}): {exc.msg}"
            return engine
        except OSError as exc:
            engine.loaded = False
            engine.status = "rules_file_unreadable"
            engine.load_error = f"规则文件无法读取: {exc}"
            return engine

        raw_rules, structural_error = _extract_rules(data)
        if structural_error is not None:
            engine.loaded = False
            engine.status = "rules_file_invalid_structure"
            engine.load_error = structural_error
            return engine

        seen_ids: set[str] = set()
        for index, raw in enumerate(raw_rules):
            try:
                rule = _build_rule(raw, index, seen_ids)
            except RuleValidationError as exc:
                engine.invalid_rules.append(InvalidRule(
                    index=index,
                    rule_id=(raw.get("id") if isinstance(raw, dict) else None),
                    error=str(exc),
                    raw=raw,
                ))
                continue
            seen_ids.add(rule.id)
            engine.rules.append(rule)

        engine.loaded = True
        engine.status = "loaded" if not engine.invalid_rules else "loaded_with_invalid_rules"
        return engine

    # ---- 匹配 ----
    def evaluate(self, method: str, path: str, headers: list[tuple[str, str]],
                 query: str, client_id: str) -> RuleMatch | None:
        header_map: dict[str, str] = {}
        for k, v in headers:
            header_map.setdefault(k.lower(), v)
        for rule in self.rules:
            detail = _match_one(rule, method, path, header_map, query, client_id)
            if detail is not None:
                return RuleMatch(rule, detail)
        return None

    def status_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "loaded": self.loaded,
            "source_path": self.source_path,
            "load_error": self.load_error,
            "rules_loaded": len(self.rules),
            "invalid_rules": [
                {"index": x.index, "rule_id": x.rule_id, "error": x.error}
                for x in self.invalid_rules
            ],
        }


class RuleValidationError(ValueError):
    """单条规则非法。"""


def _extract_rules(data: Any) -> tuple[list[Any], str | None]:
    if not isinstance(data, dict):
        return [], "规则文件顶层必须是对象，形如 {'version': 1, 'rules': [...]}"
    raw = data.get("rules")
    if raw is None:
        return [], "缺少 'rules' 字段"
    if not isinstance(raw, list):
        return [], "'rules' 必须是数组"
    return raw, None


def _build_rule(raw: Any, index: int, seen_ids: set[str]) -> Rule:
    if not isinstance(raw, dict):
        raise RuleValidationError("规则必须是对象")
    rid = raw.get("id")
    if not isinstance(rid, str) or not rid.strip():
        raise RuleValidationError("缺少字符串类型的 'id'")
    if rid in seen_ids:
        raise RuleValidationError(f"规则 id 重复: {rid!r}")
    fld = raw.get("field")
    if fld not in VALID_FIELDS:
        raise RuleValidationError(f"field 必须是 {VALID_FIELDS} 之一，实际: {fld!r}")
    matcher = raw.get("match")
    if matcher not in VALID_MATCHERS:
        raise RuleValidationError(f"match 必须是 {VALID_MATCHERS} 之一，实际: {matcher!r}")
    if matcher not in _ALLOWED[fld]:
        raise RuleValidationError(f"field={fld!r} 不支持 match={matcher!r}，"
                                  f"允许: {_ALLOWED[fld]}")
    value = raw.get("value")
    if not isinstance(value, str):
        raise RuleValidationError("'value' 必须是字符串")
    header_name = None
    if fld == "header":
        header_name = raw.get("header_name")
        if not isinstance(header_name, str) or not header_name.strip():
            raise RuleValidationError("field=header 时必须提供非空 header_name")
        header_name = header_name.lower()
    status_code = raw.get("status_code", 403)
    if not isinstance(status_code, int) or isinstance(status_code, bool) \
            or not (400 <= status_code <= 499):
        raise RuleValidationError(f"status_code 必须是 400-499 的整数，实际: {status_code!r}")
    reason = raw.get("reason", "blocked_by_rule")
    if not isinstance(reason, str) or not reason.strip():
        raise RuleValidationError("reason 必须是非空字符串")

    compiled_re = None
    network = None
    if matcher == "regex":
        try:
            compiled_re = re.compile(value)
        except re.error as exc:
            raise RuleValidationError(f"regex 编译失败: {exc}") from exc
    if fld == "ip" and matcher == "cidr":
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise RuleValidationError(f"非法 CIDR {value!r}: {exc}") from exc

    return Rule(id=rid, field=fld, match=matcher, value=value,
                header_name=header_name, status_code=status_code, reason=reason,
                regex=compiled_re, network=network)


def _match_one(rule: Rule, method: str, path: str,
               header_map: dict[str, str], query: str, client_id: str) -> str | None:
    if rule.field == "method":
        target = method.upper()
        operand = rule.value.upper()
        return f"method {target} equals {operand}" if target == operand else None

    if rule.field in ("path", "path_prefix"):
        if rule.match == "equals":
            return f"path {path} equals {rule.value}" if path == rule.value else None
        if rule.match == "prefix":
            return f"path {path} prefix {rule.value}" if path.startswith(rule.value) else None
        if rule.match == "contains":
            return f"path {path} contains {rule.value}" if rule.value in path else None
        if rule.match == "regex" and rule.regex is not None:
            m = rule.regex.search(path)
            return f"path {path} regex {rule.value} -> {m.group(0)!r}" if m else None

    if rule.field == "header":
        assert rule.header_name is not None
        present = rule.header_name in header_map
        hv = header_map.get(rule.header_name, "")
        if rule.match == "equals":
            if present and hv == rule.value:
                return f"header {rule.header_name!r} equals {rule.value!r}"
            return None
        if rule.match == "contains":
            if present and rule.value in hv:
                return f"header {rule.header_name!r} contains {rule.value!r}"
            return None
        if rule.match == "regex" and rule.regex is not None:
            m = rule.regex.search(hv) if present else None
            if m:
                return f"header {rule.header_name!r} regex {rule.value} -> {m.group(0)!r}"
            return None

    if rule.field == "query":
        if rule.match == "equals":
            return f"query {query!r} equals {rule.value!r}" if query == rule.value else None
        if rule.match == "contains":
            return f"query {query!r} contains {rule.value!r}" if rule.value in query else None
        if rule.match == "regex" and rule.regex is not None:
            m = rule.regex.search(query)
            if m:
                return f"query regex {rule.value} -> {m.group(0)!r}"
            return None

    if rule.field == "ip":
        if rule.match == "equals":
            return f"client_ip {client_id} equals {rule.value}" if client_id == rule.value else None
        if rule.match == "cidr" and rule.network is not None:
            try:
                addr = ipaddress.ip_address(client_id)
            except ValueError:
                return None
            if getattr(addr, "ipv4_mapped", None) is not None:
                addr = addr.ipv4_mapped  # type: ignore[assignment]
            if addr.version == rule.network.version and addr in rule.network:
                return f"client_ip {client_id} in cidr {rule.value}"
            return None

    return None
