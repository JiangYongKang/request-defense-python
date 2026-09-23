"""Config loading: defaults, missing files, broken JSON, invalid values/rules."""

import json

import pytest

from defense.config import (
    ConfigFileNotFound,
    ConfigSyntaxError,
    default_config,
    load_config,
    parse_config,
)
from defense.errors import RuleFileError, RuleSyntaxError


def write(tmp_path, name, content):
    p = tmp_path / name
    if isinstance(content, (dict, list)):
        p.write_text(json.dumps(content))
    else:
        p.write_text(content)
    return str(p)


def test_none_path_gives_safe_defaults():
    cfg = load_config(None)
    assert cfg.rate_per_sec == 5.0 and cfg.burst == 10
    assert cfg.trusted_networks == () and cfg.rules == ()


def test_missing_file_policy(tmp_path):
    p = str(tmp_path / "nope.json")
    cfg = load_config(p)  # default: keep service up with defaults
    assert cfg.rules == ()
    with pytest.raises(ConfigFileNotFound):
        load_config(p, use_default_if_missing=False)


def test_broken_json_is_distinct_from_missing(tmp_path):
    p = write(tmp_path, "bad.json", "{not json")
    with pytest.raises(RuleFileError):
        load_config(p, use_default_if_missing=False)


def test_full_config_with_inline_and_file_rules(tmp_path):
    rules_path = write(tmp_path, "rules.json", [
        {"id": "r-ext", "match": {"field": "path", "op": "prefix", "value": "/evil"}},
    ])
    p = write(tmp_path, "cfg.json", {
        "rate_limit": {"rate_per_sec": 2.5, "burst": 4},
        "trusted_proxies": ["10.0.0.0/8", "192.168.1.1"],
        "forward_depth": 2,
        "max_clients": 77,
        "status_codes": {"blocked": 403, "rate_limited": 503},
        "rules_file": rules_path,
        "rules": [
            {"id": "r-in", "match": {"field": "header", "name": "x-bad",
                                     "op": "present"}},
        ],
    })
    cfg = load_config(p, use_default_if_missing=False)
    assert cfg.rate_per_sec == 2.5 and cfg.burst == 4
    assert cfg.forward_depth == 2 and cfg.max_clients == 77
    assert cfg.ratelimit_status == 503
    assert {r.id for r in cfg.rules} == {"r-ext", "r-in"}
    assert len(cfg.trusted_networks) == 2


@pytest.mark.parametrize(
    "data,exc",
    [
        ([{"oops": 1}], ConfigSyntaxError),                 # not an object
        ({"rate_limit": {"rate_per_sec": 0}}, ConfigSyntaxError),
        ({"rate_limit": {"burst": 1.5}}, ConfigSyntaxError),
        ({"forward_depth": 0}, ConfigSyntaxError),
        ({"trusted_proxies": ["999.1.1.1"]}, ConfigSyntaxError),
        ({"status_codes": {"blocked": 99}}, ConfigSyntaxError),
        ({"unknown_key": 1}, ConfigSyntaxError),
        ({"rules": [{"id": ""}]}, RuleSyntaxError),
        ({"rules": "nope"}, RuleSyntaxError),
    ],
)
def test_invalid_config_rejected(data, exc):
    with pytest.raises(exc):
        parse_config(data)


def test_rules_file_with_bad_rule_wraps_error(tmp_path):
    rp = write(tmp_path, "rules.json", [{"id": "x"}])
    p = write(tmp_path, "cfg.json", {"rules_file": rp})
    with pytest.raises(RuleSyntaxError):
        load_config(p, use_default_if_missing=False)


def test_rules_file_missing_is_file_error(tmp_path):
    p = write(tmp_path, "cfg.json", {"rules_file": str(tmp_path / "missing.json")})
    with pytest.raises(ConfigFileNotFound):
        load_config(p, use_default_if_missing=False)


def test_default_config_is_usable():
    cfg = default_config()
    assert cfg.blocked_status == 403 and cfg.ratelimit_status == 429
