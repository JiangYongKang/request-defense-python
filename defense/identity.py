"""Client identity resolution behind (possibly forged) reverse proxies.

Trust model
-----------
The only identity a server cannot be lied about at layer 4 is the immediate
TCP peer (``peer_ip``).  ``X-Forwarded-For`` / ``X-Real-IP`` are plain text
and trivially forged, so they influence the result **only** when every proxy
hop from the client to us belongs to the configured trusted set.

Resolution order (depth = number of trusted proxies in front of us):

1. Peer not trusted -> forwarding headers are ignored entirely (they came
   from an untrusted sender). Identity = peer.
2. Peer trusted -> take the ``depth``-th address from the right end of
   ``X-Forwarded-For`` as the client, and verify the ``depth-1`` addresses
   to its right are each trusted. Addresses further left were client-
   supplied and are ignored.
3. XFF missing/invalid but ``X-Real-IP`` is a valid IP (and peer trusted)
   -> use it.
4. Anything malformed, truncated, or failing the chain check -> fall back to
   the TCP peer. Forgery therefore can never *weaken* a bucket/rule key; it
   can at best be ignored.

Every step is recorded in ``IdentityResult.trail`` for audit logging.
"""

import ipaddress
from dataclasses import dataclass, field

UNKNOWN_CLIENT = "unknown"
_MAX_XFF_ENTRIES = 32  # header DoS / ambiguity guard


@dataclass(frozen=True)
class IdentityResult:
    client_id: str
    trusted: bool               # True iff identity derives from a verified chain
    source: str                 # direct | forged-headers-ignored | forwarded |
    #                            # real-ip | forwarded-invalid |
    #                            # forwarded-chain-untrusted | forwarded-incomplete
    peer: str
    trail: tuple[str, ...] = field(default_factory=tuple)


def _parse_ip(value: str):
    try:
        return ipaddress.ip_address(value.strip())
    except (ValueError, TypeError):
        return None


def _in_trusted(ip, networks) -> bool:
    return any(ip in net for net in networks)


def resolve_identity(
    peer_ip: str | None,
    headers: dict[str, str] | None,
    trusted_networks,
    forward_depth: int = 1,
) -> IdentityResult:
    trail: list[str] = []
    peer = peer_ip.strip() if isinstance(peer_ip, str) and peer_ip.strip() else ""
    headers = headers or {}
    xff_raw = headers.get("x-forwarded-for", "")
    xri_raw = headers.get("x-real-ip", "")
    trail.append(f"peer={peer or UNKNOWN_CLIENT}")
    trail.append(f"xff_present={bool(xff_raw)}")
    trail.append(f"x_real_ip_present={bool(xri_raw)}")

    if not peer:
        # No transport identity either; use a shared constant key and fail closed.
        trail.append("verdict=identity:unknown:no-peer")
        return IdentityResult(UNKNOWN_CLIENT, False, "no-peer", UNKNOWN_CLIENT, tuple(trail))

    peer_ip_obj = _parse_ip(peer)
    if peer_ip_obj is None:
        # Unparseable peer transport string; do not trust any header.
        trail.append("verdict=identity:peer-invalid")
        return IdentityResult(peer, False, "peer-invalid", peer, tuple(trail))

    peer_trusted = _in_trusted(peer_ip_obj, trusted_networks)
    trail.append(f"peer_in_trusted={peer_trusted}")
    if not peer_trusted:
        if xff_raw or xri_raw:
            trail.append("forwarded_headers=ignored:untrusted-peer")
            trail.append("verdict=identity:peer:forged-headers-ignored")
            return IdentityResult(peer, False, "forged-headers-ignored", peer, tuple(trail))
        trail.append("verdict=identity:peer:direct")
        return IdentityResult(peer, False, "direct", peer, tuple(trail))

    # Peer is a trusted proxy. Parse X-Forwarded-For.
    if forward_depth < 1:
        trail.append("verdict=identity:peer:forward-depth-misconfigured")
        return IdentityResult(peer, False, "forward-depth-misconfigured", peer, tuple(trail))

    if xff_raw:
        entries = [tok.strip() for tok in xff_raw.split(",")]
        trail.append(f"xff_entries={len(entries)}")
        if len(entries) > _MAX_XFF_ENTRIES or any(not e for e in entries):
            trail.append("verdict=identity:peer:forwarded-invalid")
            return IdentityResult(peer, False, "forwarded-invalid", peer, tuple(trail))
        parsed = [_parse_ip(e) for e in entries]
        if any(ip is None for ip in parsed):
            trail.append("xff_check=malformed-ip")
            trail.append("verdict=identity:peer:forwarded-invalid")
            return IdentityResult(peer, False, "forwarded-invalid", peer, tuple(trail))

        if len(entries) < forward_depth:
            # A configured proxy did not append its hop; chain is incomplete.
            trail.append(
                f"xff_check=incomplete need={forward_depth} got={len(entries)}"
            )
            trail.append("verdict=identity:peer:forwarded-incomplete")
            return IdentityResult(peer, False, "forwarded-incomplete", peer, tuple(trail))

        idx = len(entries) - forward_depth
        client = entries[idx]
        hops = parsed[idx + 1:]
        untrusted_hops = [str(ip) for ip in hops if not _in_trusted(ip, trusted_networks)]
        if untrusted_hops:
            trail.append(f"xff_check=untrusted-hop {untrusted_hops}")
            trail.append("verdict=identity:peer:forwarded-chain-untrusted")
            return IdentityResult(peer, False, "forwarded-chain-untrusted", peer, tuple(trail))

        trail.append(f"resolved_client={client}")
        trail.append("verdict=identity:forwarded")
        return IdentityResult(client, True, "forwarded", peer, tuple(trail))

    # No XFF; X-Real-IP may carry the client from a trusted proxy.
    if xri_raw:
        ip = _parse_ip(xri_raw)
        if ip is None:
            trail.append("x_real_ip_check=malformed")
            trail.append("verdict=identity:peer:forwarded-invalid")
            return IdentityResult(peer, False, "forwarded-invalid", peer, tuple(trail))
        trail.append(f"resolved_client={str(ip)}")
        trail.append("verdict=identity:real-ip")
        return IdentityResult(str(ip), True, "real-ip", peer, tuple(trail))

    trail.append("verdict=identity:peer:trusted-proxy-no-headers")
    return IdentityResult(peer, False, "trusted-proxy-no-headers", peer, tuple(trail))
