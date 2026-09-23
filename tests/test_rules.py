"""Rule compilation (strict) and matching tests."""

import pytest

from defense.errors import RuleSyntaxError
from defense.rules import CompiledRule, MatchContext, compile_rules

CTX = MatchContext(
    method="GET",
    path="/admin/panel",
    headers={"x-evil": "yes", "user-agent": "sqlmap/1.0"},
    query={"q": "1 UNION SELECT x"},
    body_snippet="",
)


def test_simple_match_and_miss():
    r = CompiledRule({"id": "r1", "match": {"field": "path", "op": "prefix", "value": "/admin"}})
    assert r.evaluate(CTX).rule_id == "r1"
    ok = MatchContext("GET", "/health", {}, {}, "")
    assert r.evaluate(ok) is None


def test_header_case_insensitive_and_regex():
    r = CompiledRule({
        "id": "ua",
        "match": {"field": "header", "name": "User-Agent", "op": "regex",
                  "value": r"(?i)sqlmap"},
    })
    assert r.evaluate(CTX) is not None


def test_all_requires_every_matcher():
    r = CompiledRule({
        "id": "combo",
        "all": [
            {"field": "method", "op": "equals", "value": "GET"},
            {"field": "query", "name": "q", "op": "contains", "value": "UNION"},
        ],
    })
    assert r.evaluate(CTX) is not None
    post = MatchContext("POST", CTX.path, CTX.headers, CTX.query, "")
    assert r.evaluate(post) is None


def test_present_and_in_and_missing_value():
    assert CompiledRule({"id": "p", "match": {"field": "header", "name": "x-evil",
                                              "op": "present"}}).evaluate(CTX)
    r = CompiledRule({"id": "m", "match": {"field": "method", "op": "in",
                                           "value": ["POST", "DELETE"]}})
    assert r.evaluate(CTX) is None


@pytest.mark.parametrize(
    "raw",
    [
        "not-an-object",
        {"match": {"field": "path", "op": "equals", "value": "x"}},           # no id
        {"id": "x"},                                                            # no matcher
        {"id": "x", "match": {}, "all": []},                                    # both
        {"id": "x", "match": {"field": "bogus", "op": "equals", "value": "a"}},
        {"id": "x", "match": {"field": "path", "op": "frobnicate", "value": "a"}},
        {"id": "x", "match": {"field": "header", "op": "equals", "value": "a"}},  # no name
        {"id": "x", "match": {"field": "query", "name": "q", "op": "in", "value": []}},
        {"id": "x", "match": {"field": "path", "op": "regex", "value": "([abc"}},
        {"id": "x", "match": {"field": "path", "op": "present", "value": "x"}},
    ],
)
def test_invalid_rules_rejected(raw):
    with pytest.raises(RuleSyntaxError):
        compile_rules([raw]) if isinstance(raw, dict) else CompiledRule(raw)


def test_duplicate_ids_rejected():
    rule = {"id": "dup", "match": {"field": "path", "op": "equals", "value": "/"}}
    with pytest.raises(RuleSyntaxError):
        compile_rules([rule, rule])


def test_document_must_be_list():
    with pytest.raises(RuleSyntaxError):
        compile_rules({"id": "x"})
