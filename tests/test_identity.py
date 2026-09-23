"""Client identity: trust chain, forged headers, malformed inputs."""

import ipaddress

import pytest

from defense.identity import UNKNOWN_CLIENT, resolve_identity

TRUST = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("203.0.113.5/32")]
H = lambda xff=None, xri=None: {  # noqa: E731
    k: v for k, v in (("x-forwarded-for", xff), ("x-real-ip", xri)) if v is not None
}


def test_untrusted_peer_ignores_forwarded_headers():
    # Attacker connects directly and claims to be someone else.
    r = resolve_identity("1.2.3.4", H(xff="8.8.8.8", xri="9.9.9.9"), TRUST, 1)
    assert r.client_id == "1.2.3.4"
    assert r.trusted is False
    assert r.source == "forged-headers-ignored"


def test_direct_client_no_headers():
    r = resolve_identity("1.2.3.4", {}, TRUST, 1)
    assert r.client_id == "1.2.3.4" and r.source == "direct"


def test_trusted_proxy_single_hop_xff():
    r = resolve_identity("10.0.0.1", H(xff="8.8.8.8"), TRUST, 1)
    assert r.client_id == "8.8.8.8" and r.trusted is True and r.source == "forwarded"


def test_client_supplied_left_entry_is_ignored():
    # Attacker prefixes a fake address; trusted proxy appends real client.
    r = resolve_identity("10.0.0.1", H(xff="9.9.9.9, 8.8.8.8"), TRUST, 1)
    assert r.client_id == "8.8.8.8"


def test_depth_two_chain():
    r = resolve_identity("10.0.0.2", H(xff="8.8.8.8, 10.0.0.1"), TRUST, 2)
    assert r.client_id == "8.8.8.8" and r.source == "forwarded"


def test_depth_two_but_untrusted_inner_hop_falls_back():
    # The hop that forwarded us claims the inner proxy is untrusted: ignore.
    r = resolve_identity("10.0.0.2", H(xff="8.8.8.8, 6.6.6.6"), TRUST, 2)
    assert r.client_id == "10.0.0.2"
    assert r.source == "forwarded-chain-untrusted"


def test_truncated_chain_falls_back():
    r = resolve_identity("10.0.0.1", H(xff=""), TRUST, 2)
    assert r.client_id == "10.0.0.1" and r.source == "trusted-proxy-no-headers"
    r2 = resolve_identity("10.0.0.1", H(xff="8.8.8.8"), TRUST, 2)
    assert r2.source == "forwarded-incomplete"


def test_malformed_xff_falls_back():
    r = resolve_identity("10.0.0.1", H(xff="not-an-ip"), TRUST, 1)
    assert r.client_id == "10.0.0.1" and r.source == "forwarded-invalid"
    r2 = resolve_identity("10.0.0.1", H(xff="8.8.8.8, , 10.0.0.1"), TRUST, 2)
    assert r2.source == "forwarded-invalid"


def test_x_real_ip_only_used_from_trusted_peer():
    assert resolve_identity("1.2.3.4", H(xri="8.8.8.8"), TRUST, 1).client_id == "1.2.3.4"
    r = resolve_identity("10.0.0.1", H(xri="8.8.8.8"), TRUST, 1)
    assert r.client_id == "8.8.8.8" and r.source == "real-ip"
    assert resolve_identity("10.0.0.1", H(xri="junk"), TRUST, 1).source == "forwarded-invalid"


def test_missing_or_invalid_peer():
    assert resolve_identity(None, H(xff="8.8.8.8"), TRUST, 1).client_id == UNKNOWN_CLIENT
    r = resolve_identity("garbage", H(xff="8.8.8.8"), TRUST, 1)
    assert r.client_id == "garbage" and r.source == "peer-invalid"
