"""Target normalization: hostname/CIDR → list of IPv4 strings."""

from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List


_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def _is_ipv4(spec: str) -> bool:
    """Return True if *spec* looks like a bare IPv4 address."""
    return bool(_IPV4_RE.match(spec))


def _resolve_hostname(hostname: str) -> List[str]:
    """Resolve *hostname* to all IPv4 A-records.

    Runs getaddrinfo in a thread executor because it blocks.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve hostname '{hostname}': {exc}") from exc

    ips: set[str] = set()
    for _family, _socktype, _proto, _canonname, sockaddr in infos:
        ip = sockaddr[0]
        if _IPV4_RE.match(ip):
            ips.add(ip)
    if not ips:
        raise ValueError(f"No IPv4 addresses found for hostname '{hostname}'")
    return sorted(ips)


def resolve_target(spec: str) -> List[str]:
    """Normalize *spec* to a deduplicated, sorted list of IPv4 strings.

    Accepts:
      - bare IPv4 (e.g. ``1.2.3.4``)
      - hostname (resolved via DNS)
      - CIDR notation (e.g. ``10.0.0.0/24``)
    """
    spec = spec.strip()

    if not spec:
        raise ValueError("Target specification is empty")

    # Bare IPv4
    if _is_ipv4(spec):
        return [spec]

    # CIDR
    if "/" in spec:
        try:
            net = ipaddress.IPv4Network(spec, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR '{spec}': {exc}") from exc
        return sorted(str(ip) for ip in net.hosts())

    # Hostname (fallback)
    return _resolve_hostname(spec)
