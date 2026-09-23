"""规则加载失败策略与匹配。"""
from __future__ import annotations

import json

import pytest

from request_defense.rules import RuleEngine


def _write(tmp_path, name, payload):
    path = tmp_path / name
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_no_rules_configured():
    e = RuleEngine.load(None)
    assert e.status == "no_rules_configured"
    assert e.loaded is None and e.load_error is None


def test_missing_file_is_distinct_state(tmp_path):
    e = RuleEngine.load(str(tmp_path / "nope.json"))
    assert e.status == "rules_file_missing"
    assert e.loaded is False
    assert "不存在" in e.load_error
    # 不会因此关闭限流；规则集合为空
    assert e.rules == []


def test_invalid_json_is_distinct(tmp_path):
    p = _write(tmp_path, "r.json", "{rules: [")
    e = RuleEngine.load(p)
    assert e.status == "rules_file_invalid_json"
    assert e.loaded is False and "JSON" in e.load_error


def test_bad_structure_is_distinct(tmp_path):
    p = _write(tmp_path, "r.json", {"rules": "nope"})
    e = RuleEngine.load(p)
    assert e.status == "rules_file_invalid_structure"
    assert e.loaded is False


def test_top_level_must_be_object(tmp_path):
    p = _write(tmp_path, "r.json", [1, 2, 3])
    e = RuleEngine.load(p)
    assert e.status == "rules_file_invalid_structure"


def test_partial_invalid_rules_keep_valid_ones(tmp_path):
    payload = {"rules": [
        {"id": "good", "field": "path_prefix", "match": "prefix", "value": "/admin"},
        {"id": "bad-regex", "field": "path", "match": "regex", "value": "(["},
        {"id": "", "field": "path", "match": "equals", "value": "/x"},
        {"id": "bad-field", "field": "nope", "match": "equals", "value": "/x"},
        {"id": "bad-combo", "field": "method", "match": "regex", "value": ".*"},
        {"id": "bad-status", "field": "path", "match": "equals",
         "value": "/x", "status_code": 503},
        {"id": "dup", "field": "method", "match": "equals", "value": "GET"},
        {"id": "dup", "field": "path", "match": "equals", "value": "/y"},
        "not-a-dict",
    ]}
    e = RuleEngine.load(_write(tmp_path, "r.json", payload))
    assert e.loaded is True
    assert e.status == "loaded_with_invalid_rules"
    assert [r.id for r in e.rules] == ["good", "dup"]
    assert len(e.invalid_rules) == 7
    errors = {x.error for x in e.invalid_rules}
    assert any("regex" in x for x in errors)
    assert any("重复" in x for x in errors)
    assert any("field" in x for x in errors)


def test_rules_actually_block(tmp_path):
    payload = {"rules": [
        {"id": "admin", "field": "path_prefix", "match": "prefix", "value": "/admin"},
        {"id": "ua", "field": "header", "match": "contains",
         "header_name": "user-agent", "value": "sqlmap",
         "status_code": 403, "reason": "scanner"},
        {"id": "net", "field": "ip", "match": "cidr", "value": "192.0.2.0/24"},
    ]}
    e = RuleEngine.load(_write(tmp_path, "r.json", payload))
    assert e.evaluate("GET", "/admin/x", [], "", "8.8.8.8").rule.id == "admin"
    assert e.evaluate("GET", "/", [("user-agent", "sqlmap/1")], "",
                      "8.8.8.8").rule.id == "ua"
    assert e.evaluate("GET", "/", [], "", "192.0.2.9").rule.id == "net"
    assert e.evaluate("GET", "/", [("user-agent", "chrome")], "",
                      "8.8.8.8") is None
    # 非 IP 身份不会让 cidr 规则抛异常（异常输入稳定）
    assert e.evaluate("GET", "/", [], "", "garbage") is None


def test_first_match_wins_in_file_order(tmp_path):
    payload = {"rules": [
        {"id": "first", "field": "path_prefix", "match": "prefix", "value": "/a"},
        {"id": "second", "field": "path_prefix", "match": "prefix", "value": "/a/b"},
    ]}
    e = RuleEngine.load(_write(tmp_path, "r.json", payload))
    assert e.evaluate("GET", "/a/b", [], "", "1.1.1.1").rule.id == "first"


def test_query_and_regex_matching(tmp_path):
    payload = {"rules": [
        {"id": "sqli", "field": "query", "match": "contains", "value": "union select"},
        {"id": "traversal", "field": "path", "match": "regex", "value": r"\.\./"},
    ]}
    e = RuleEngine.load(_write(tmp_path, "r.json", payload))
    m = e.evaluate("GET", "/p", [], "x=1 union select 2", "1.1.1.1")
    assert m.rule.id == "sqli"
    assert e.evaluate("GET", "/../etc", [], "", "1.1.1.1").rule.id == "traversal"
    assert e.evaluate("GET", "/ok", [], "x=1", "1.1.1.1") is None
