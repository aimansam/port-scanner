"""Configuration dataclass for the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class ScanConfig:
    """Configuration for a scanning run."""

    target: str
    ports: List[int]
    protocol: str = "tcp"
    max_concurrent: int = 100
    timeout_sec: float = 2.0
    rate_limit_sec: float | None = None
    banner: bool = True
    dry_run: bool = False
    output: str | None = None
    verbose: bool = False

    def __post_init__(self) -> None:
        # Clamp concurrency to sane range
        if self.max_concurrent < 1:
            self.max_concurrent = 1
        if self.max_concurrent > 1000:
            self.max_concurrent = 1000
        if self.timeout_sec < 0.1:
            self.timeout_sec = 0.1


# CLI default port spec: the ``top100`` preset
DEFAULT_PORT_SPEC = "top100"
