"""Report model + JSON writer."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger("port_scanner.reporter")


# -- Report dataclass -------------------------------------------------------

@dataclass
class PortEntry:
    """One row in the report's ``ports`` array."""
    port: int
    state: str
    service: str
    banner: str | None
    risk: str
    risk_rationale: str


@dataclass
class ScanMeta:
    """Scan-level metadata."""
    target: str
    target_ip: str
    protocol: str
    ports_scanned: int
    ports_open: int
    start_time: str
    end_time: str
    duration_seconds: float


@dataclass
class RiskSummary:
    """Counts per risk level."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0

    def to_dict(self) -> Dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "informational": self.informational,
        }


@dataclass
class TargetReport:
    """One target (IP) worth of scan results."""
    target: str
    target_ip: str
    ports: List[PortEntry]
    scan: ScanMeta
    summary: RiskSummary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan": {
                "target": self.scan.target,
                "target_ip": self.scan.target_ip,
                "protocol": self.scan.protocol,
                "ports_scanned": self.scan.ports_scanned,
                "ports_open": self.scan.ports_open,
                "start_time": self.scan.start_time,
                "end_time": self.scan.end_time,
                "duration_seconds": round(self.scan.duration_seconds, 2),
            },
            "ports": [
                {
                    "port": e.port,
                    "state": e.state,
                    "service": e.service,
                    "banner": e.banner,
                    "risk": e.risk,
                    "risk_rationale": e.risk_rationale,
                }
                for e in self.ports
            ],
            "summary": self.summary.to_dict(),
        }


@dataclass
class ScanReport:
    """Top-level report; v1 may contain a single target or multiple."""
    targets: List[TargetReport]

    def to_dict(self) -> Dict[str, Any]:
        if len(self.targets) == 1:
            # v1 convenience: unwrap single target for simpler output.
            return self.targets[0].to_dict()
        return {
            "targets": [t.to_dict() for t in self.targets],
        }


# -- Build helpers -----------------------------------------------------------

def _now_iso() -> str:
    """Current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def build_report(
    target: str,
    target_ip: str,
    scanned_ports: List[int],
    results: List[dict],  # each dict: port, state, service, banner, risk, risk_rationale
    protocol: str = "tcp",
    start_time: str | None = None,
) -> TargetReport:
    """Assemble a TargetReport from scan output.

    *results* should be a list of dicts with keys:
    ``port``, ``state`` (open/closed/filtered), ``service``, ``banner``,
    ``risk``, ``risk_rationale``.
    """
    start = start_time or _now_iso()
    end = _now_iso()

    open_count = sum(1 for r in results if r["state"] == "open")

    summary = RiskSummary()
    for r in results:
        lvl = r["risk"]
        if lvl in ("critical", "high", "medium", "low", "informational"):
            setattr(summary, lvl, getattr(summary, lvl) + 1)

    ports = [PortEntry(**r) for r in results]

    scan = ScanMeta(
        target=target,
        target_ip=target_ip,
        protocol=protocol,
        ports_scanned=len(scanned_ports),
        ports_open=open_count,
        start_time=start,
        end_time=end,
        duration_seconds=0.0,  # caller should patch if they have real timing
    )

    return TargetReport(
        target=target,
        target_ip=target_ip,
        ports=ports,
        scan=scan,
        summary=summary,
    )


# -- Output sinks ------------------------------------------------------------

def write_json(report: ScanReport, path: str) -> None:
    """Pretty-print the report as JSON to *path*."""
    payload = report.to_dict()
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    logger.info("Report written to %s", path)


def print_report(report: ScanReport) -> None:
    """Pretty-print the report as JSON to stdout."""
    payload = report.to_dict()
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    print(text)
