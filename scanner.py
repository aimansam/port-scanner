"""Async scan engine: semaphore-wrapped dispatcher, per-port probe."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from config import ScanConfig
from utils import setup_logging

import sys, os
_sys_path_insert = os.path.dirname(os.path.abspath(__file__))
if _sys_path_insert not in sys.path:
    sys.path.insert(0, _sys_path_insert)


logger = setup_logging()


class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass
class PortResult:
    port: int
    state: PortState
    error: Optional[str] = None


async def _probe_port(
    host: str,
    port: int,
    config: ScanConfig,
    semaphore: asyncio.Semaphore,
) -> PortResult:
    """Probe a single TCP port with a connect scan."""

    async with semaphore:
        if config.rate_limit_sec and config.rate_limit_sec > 0:
            await asyncio.sleep(config.rate_limit_sec)

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=config.timeout_sec,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            logger.debug("Port %d on %s: OPEN", port, host)
            return PortResult(port=port, state=PortState.OPEN)

        except asyncio.TimeoutError:
            logger.debug("Port %d on %s: TIMEOUT (filtered)", port, host)
            return PortResult(port=port, state=PortState.FILTERED,
                              error="Connection timed out")

        except ConnectionRefusedError:
            logger.debug("Port %d on %s: REFUSED (closed)", port, host)
            return PortResult(port=port, state=PortState.CLOSED,
                              error="Connection refused")

        except OSError as exc:
            # Distinguish timeout-like OSError from other errors
            err_str = str(exc).lower()
            if any(k in err_str for k in ("timeout", "timed out")):
                logger.debug("Port %d on %s: OSError timeout (filtered)", port, host)
                return PortResult(port=port, state=PortState.FILTERED,
                                  error=f"Connection timed out: {exc}")
            # if "refused" appears, it's closed; otherwise treat as filtered
            if "refused" in err_str:
                logger.debug("Port %d on %s: OSError refused (closed)", port, host)
                return PortResult(port=port, state=PortState.CLOSED,
                                  error=f"Connection refused: {exc}")
            logger.warning("Port %d on %s: OSError %s (filtered)", port, host, exc)
            return PortResult(port=port, state=PortState.FILTERED,
                              error=f"OS error: {exc}")


async def scan_target(
    host: str,
    ports: List[int],
    config: ScanConfig,
) -> List[PortResult]:
    """Scan *host* for the given *ports* and return results in port order.

    Returns a list of PortResult, one per scanned port, ordered by port number.
    Results are collected even if the scan is cancelled.
    """
    logger.info("Starting scan of %s (%d ports, max_concurrent=%d, timeout=%.1fs)",
                host, len(ports), config.max_concurrent, config.timeout_sec)

    semaphore = asyncio.Semaphore(config.max_concurrent)
    tasks = [
        asyncio.create_task(_probe_port(host, port, config, semaphore))
        for port in ports
    ]

    # Gather results; if cancelled, collect what we have.
    try:
        results = await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logger.warning("Scan cancelled; collecting partial results for %s", host)
        # Cancel pending tasks
        for t in tasks:
            if not t.done():
                t.cancel()
        # Await cancelled tasks to finish (they raise CancelledError)
        partial = await asyncio.gather(*tasks, return_exceptions=True)
        results = tuple(_extract_result(r) for r in partial)

    # Sort by port number before returning
    sorted_results = sorted(results, key=lambda r: r.port)
    return list(sorted_results)


def _extract_result(item) -> PortResult:
    """Unwrap a gather result: PortResult or exception."""
    if isinstance(item, PortResult):
        return item
    if isinstance(item, BaseException):
        # Shouldn't normally happen, but be defensive
        logger.error("Unexpected exception in task: %s", item)
        # We don't have a port number here; return a placeholder.
        # This case is rare; real scans should not hit it.
        return PortResult(port=0, state=PortState.FILTERED,
                          error=f"Task exception: {item}")
    # Last resort
    return PortResult(port=0, state=PortState.FILTERED,
                      error=f"Unexpected result type: {type(item)}")
