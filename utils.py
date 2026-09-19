"""Utilities: logging setup, timeout constants, validation helpers."""

from __future__ import annotations

import logging
import sys
from typing import Optional


# -- Logging ----------------------------------------------------------------

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure and return the package logger.

    When *verbose* is True, emit DEBUG-level messages to stderr.
    Otherwise emit INFO-level only.
    """
    logger = logging.getLogger("port_scanner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        if verbose:
            handler.setLevel(logging.DEBUG)
            fmt = "%(asctime)s [%(levelname)s] %(name)s %(message)s"
        else:
            handler.setLevel(logging.INFO)
            fmt = "%(asctime)s %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)

    return logger


# -- Constants --------------------------------------------------------------

DEFAULT_TIMEOUT_SEC = 2.0
MAX_CONCURRENT_CAP = 1000

# -- Validation helpers -------------------------------------------------------

def validate_target_string(spec: str) -> str:
    """Raise ValueError with a helpful message if *spec* is clearly invalid."""
    spec = spec.strip()
    if not spec:
        raise ValueError("Target must be an IP address, hostname, or CIDR range")
    # Heuristic: if it looks like an IPv4 address, it's likely valid target format.
    # We rely on resolve_target for full validation.
    return spec
