"""Banner grabbing: protocol-aware probes + response reading."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from config import ScanConfig
from utils import setup_logging

import sys, os
_sys_path_insert = os.path.dirname(os.path.abspath(__file__))
if _sys_path_insert not in sys.path:
    sys.path.insert(0, _sys_path_insert)


logger = setup_logging()


# -- Per-service probe builders ---------------------------------------------

def _probe_for_port(host: str, port: int) -> Optional[bytes]:
    """Return the bytes to send immediately after connect, or None if the

    service sends a banner unsolicited (SSH, FTP, SMTP, etc.)."""
    if port in (22, 23):
        # SSH / Telnet send banner on connect — no probe needed.
        return None
    if port == 21:
        # FTP also sends banner on connect (though some servers wait).
        return None
    if port == 25:
        # SMTP sends 220 banner on connect.
        return None
    if port in (80, 8080, 8443, 8888, 9090, 9443, 10000,
                18080, 18081, 3000, 5000, 5001, 8000, 8081):
        # HTTP-like services
        return f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: PortScanner/1.0\r\n\r\n".encode()
    # Generic: send a blank line and read whatever comes back.
    return b"\r\n"


async def grab_banner(
    host: str,
    port: int,
    config: ScanConfig,
) -> Optional[str]:
    """Attempt a protocol-appropriate banner grab on an open port.

    Returns the banner text (decoded, stripped) or None if silent/timeout.
    Uses a fresh connection + short read window — safe and best-effort.
    """
    probe = _probe_for_port(host, port)
    read_timeout = max(config.timeout_sec, 1.0)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=read_timeout,
        )
    except Exception:
        logger.debug("Banner: could not connect to %s:%d", host, port)
        return None

    try:
        if probe is not None:
            try:
                writer.write(probe)
                await writer.drain()
            except Exception as exc:
                logger.debug("Banner: write failed for %s:%d (%s)", host, port, exc)
                writer.close()
                return None

        # Read until we get something or timeout.
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=read_timeout)
        except asyncio.TimeoutError:
            data = b""

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if not data:
            logger.debug("Banner: no data from %s:%d", host, port)
            return None

        # Decode with latin-1 fallback (preserves bytes 1:1, no decode errors).
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = data.decode("latin-1", errors="replace")

        # Collapse whitespace and strip.
        text = " ".join(text.split())
        if not text:
            return None

        logger.debug("Banner from %s:%d: %r", host, port, text[:200])
        return text

    except Exception as exc:
        logger.warning("Banner error on %s:%d: %s", host, port, exc)
        try:
            writer.close()
        except Exception:
            pass
        return None
