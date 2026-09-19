"""Port list expansion, presets, and validation."""

from __future__ import annotations

import re
from typing import List

# -- Presets ---------------------------------------------------------------

_PRESETS: dict[str, List[int]] = {
    "top100": [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
        1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
        26, 59, 113, 137, 161, 162, 220, 389, 445, 465, 513, 514, 587,
        636, 992, 1080, 1194, 1433, 1521, 2082, 2083, 2181, 2375, 2376,
        3128, 3306, 3637, 3690, 4000, 4444, 4567, 4662, 5000, 5001, 5003,
        5004, 5190, 5222, 5269, 5404, 5432, 5632, 5900, 5984, 6000, 6001,
        6346, 6347, 6379, 6699, 6789, 6969, 7000, 7001, 7499, 7980, 8080,
        8081, 8118, 8123, 8222, 8290, 8300, 8443, 8500, 8600, 8787, 8888,
        8989, 9090, 9418, 9999, 11211, 12000, 12345, 14330, 15567, 16000,
        17501, 18100, 19000, 20000, 20490, 21000, 22222, 23456, 24000,
    ],
    "web": [80, 443, 8080, 8443, 8888, 9443, 10443],
    "common": [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
        1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
        161, 445, 465, 514, 587, 636, 992, 1194, 1433, 1521, 3128, 4444,
        5000, 5190, 5222, 5984, 6000, 6346, 6347, 6699, 7000, 7001, 7499,
        8081, 8118, 8290, 8300, 8500, 8600, 8888, 9090, 9418, 9999, 11211,
    ],
    "all": list(range(1, 65536)),
}

_PRESET_NAMES = sorted(_PRESETS.keys())

# -- Helpers ---------------------------------------------------------------

_PORT_RE = re.compile(r"^(\d+)(?:-(\d+))?$")


def expand_ports(spec: str) -> List[int]:
    """Expand a port specification into a sorted, deduplicated list of integers.

    *spec* may contain:
      - comma-separated port numbers (``22,80,443``)
      - ranges (``1000-2000``)
      - preset names (``top100``, ``web``, ``common``, ``all``)

    Raises ``ValueError`` on invalid input (non-numeric, out-of-range, inverted range).
    """
    spec = spec.strip()
    if not spec:
        raise ValueError("Port specification is empty")

    # Preset lookup — must match exactly
    if spec in _PRESETS:
        return sorted(set(_PRESETS[spec]))

    parts = [p.strip() for p in spec.split(",")]
    ports: set[int] = set()

    for part in parts:
        if not part:
            continue
        m = _PORT_RE.match(part)
        if not m:
            raise ValueError(f"Invalid port entry '{part}': expected N or N-M")
        low = int(m.group(1))
        high = int(m.group(2)) if m.group(2) is not None else low

        if low < 1 or low > 65535:
            raise ValueError(f"Port {low} out of range (1-65535)")
        if high < 1 or high > 65535:
            raise ValueError(f"Port {high} out of range (1-65535)")
        if low > high:
            raise ValueError(f"Inverted range {low}-{high}")

        for p in range(low, high + 1):
            ports.add(p)

    if not ports:
        raise ValueError("No valid ports in specification")

    return sorted(ports)


def list_presets() -> List[str]:
    """Return the list of available preset names."""
    return _PRESET_NAMES
