"""CLI entry point: argparse, ethical warning, confirmation, orchestration."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timezone
from typing import List

from .banner import grab_banner
from .config import ScanConfig, DEFAULT_PORT_SPEC
from .port_list import expand_ports, list_presets
from .reporter import ScanReport, TargetReport, build_report, print_report, write_json
from .risk import assess_risk
from .scanner import PortState, scan_target
from .services import service_name
from .target import resolve_target
from .utils import setup_logging

logger = setup_logging()


# -- CLI ---------------------------------------------------------------------

_USAGE = """%(prog)s [OPTIONS] TARGET

TCP connect port scanner with banner grabbing and JSON reporting.

TARGET: IPv4 address, hostname, or CIDR range (e.g. 192.168.1.1, scanme.nmap.org, 10.0.0.0/24)
"""


def _add_ethical_warning() -> None:
    print("=" * 72)
    print("  ETHICAL USE NOTICE")
    print("=" * 72)
    print(
        "This tool is designed for network reconnaissance of systems you own or"
        "\nhave explicit written permission to scan."
        "\n\n"
        "Scanning networks or hosts without authorization may be illegal in your"
        "\njurisdiction and violates the terms of service of most hosting providers."
        "\n\n"
        "By using this tool you confirm that you are authorized to scan the target"
        "\nand accept responsibility for your actions."
        "\n"
        "=" * 72
    )


def _maybe_confirm(ports_count: int, is_cidr: bool) -> None:
    """Prompt for confirmation when scanning large ranges."""
    large_scan = ports_count > 1000 or is_cidr
    if not large_scan:
        return
    print()
    print(f"Target will be scanned with {ports_count} port(s).")
    if is_cidr:
        print("CIDR range detected — this will scan multiple hosts.")
    try:
        answer = input("Continue? [y/N]: ").strip().lower()
    except EOFError:
        print("No input — aborting.")
        sys.exit(1)
    if answer not in ("y", "yes"):
        print("Aborted.")
        sys.exit(0)


def _build_args_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port_scanner",
        description="TCP connect port scanner with banner grabbing.",
        epilog=(
            "Examples:\n"
            "  python -m port_scanner 192.168.1.1\n"
            "  python -m port_scanner scanme.nmap.org --preset web --output report.json\n"
            "  python -m port_scanner 10.0.0.0/30 --ports 1-1024 --max-concurrent 50\n"
            "  python -m port_scanner scanme.nmap.org --dry-run\n"
            "\n"
            "Safe targets for testing: scanme.nmap.org (NMAP's test server), localhost."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage=_USAGE,
    )

    parser.add_argument(
        "target",
        nargs="?",
        help="Target IP address, hostname, or CIDR range.",
    )
    parser.add_argument(
        "--ports",
        default=DEFAULT_PORT_SPEC,
        help=(
            "Port specification: comma-separated ports and ranges "
            "(e.g. '22,80,443,1000-2000'), or a preset name. "
            f"Available presets: {', '.join(list_presets())}. "
            f"Default: {DEFAULT_PORT_SPEC}."
        ),
    )
    parser.add_argument(
        "--preset",
        choices=list_presets(),
        default=None,
        help="Shortcut for --ports: use a named preset.",
    )
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=100,
        help="Maximum concurrent connections (1-1000, default: 100).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Timeout in seconds per connection attempt (default: 2.0).",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=None,
        help="Delay in seconds between probes (optional rate limiting).",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        default=False,
        help="Skip banner grabbing.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Resolve target and print port list without sending any probes.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write JSON report to the given file path (default: stdout).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Enable verbose (DEBUG) output.",
    )
    return parser


def _parse_args(argv: List[str] | None = None) -> ScanConfig:
    parser = _build_args_parser()
    args = parser.parse_args(argv)

    # Target required
    if args.target is None:
        parser.error("the following arguments are required: TARGET")

    # Resolve port spec
    if args.preset is not None:
        port_spec = args.preset
    else:
        port_spec = args.ports

    try:
        ports = expand_ports(port_spec)
    except ValueError as exc:
        parser.error(str(exc))

    # Resolve target early (we need it for dry-run and confirmation)
    try:
        ips = resolve_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    # Confirm large scans
    is_cidr = "/" in args.target.strip()
    _maybe_confirm(len(ports), is_cidr)

    # Determine target IP for the report — we scan ALL resolved IPs, but the
    # simplest v1 approach is to scan the first IP only. Keep a single target
    # per invocation as per plan assumption 3 (single target per invocation).
    # For hostnames resolving to multiple IPs, scan the first one.
    target_ip = ips[0]

    config = ScanConfig(
        target=args.target,
        ports=ports,
        max_concurrent=args.max_concurrent,
        timeout_sec=args.timeout,
        rate_limit_sec=args.rate_limit,
        banner=not args.no_banner,
        dry_run=args.dry_run,
        output=args.output,
        verbose=args.verbose,
    )
    return config


# -- Run ---------------------------------------------------------------------

def _run_dry_run(config: ScanConfig) -> None:
    """Print resolved target IP(s) and the expanded port list, then exit."""
    print(f"Target (input): {config.target}")
    # Re-resolve to show all IPs
    ips = resolve_target(config.target)
    if len(ips) == 1:
        print(f"Resolved IP: {ips[0]}")
    else:
        print(f"Resolved IPs ({len(ips)}):")
        for ip in ips:
            print(f"  - {ip}")
    print(f"Ports to scan ({len(config.ports)}):")
    # Print in a compact range format
    ranges = _compress_port_list(config.ports)
    print(f"  {', '.join(ranges)}")
    print()
    print("Dry run — no network probes will be made.")


def _compress_port_list(ports: List[int]) -> List[str]:
    """Compress a sorted port list into range strings for display."""
    if not ports:
        return []
    ranges: List[str] = []
    start = ports[0]
    end = start
    for p in ports[1:]:
        if p == end + 1:
            end = p
        else:
            ranges.append(str(start) if start == end else f"{start}-{end}")
            start = p
            end = p
    ranges.append(str(start) if start == end else f"{start}-{end}")
    return ranges


async def _run_scan(config: ScanConfig) -> ScanReport:
    """Run the full scan pipeline and return a ScanReport."""
    target = config.target
    ips = resolve_target(target)
    # v1: scan the first resolved IP
    target_ip = ips[0]
    host = target_ip

    start_time = datetime.now(timezone.utc)

    # Scan
    results = await scan_target(host, config.ports, config)

    # Sort results by port (scanner already does, but be safe)
    results.sort(key=lambda r: r.port)

    # Banner grabbing + service + risk
    enriched: List[dict] = []
    open_ports = [r for r in results if r.state == PortState.OPEN]

    if config.banner:
        logger.info("Banner grabbing on %d open port(s)...", len(open_ports))
        for res in open_ports:
            banner = None
            try:
                banner = await grab_banner(host, res.port, config)
            except Exception as exc:
                logger.warning("Banner grab failed for %s:%d: %s", host, res.port, exc)
            # Augment service name with version hint if banner contains ssh version
            svc = service_name(res.port)
            if res.port == 22 and banner and "ssh-2.0-" in (banner or "").lower():
                # include the banner version in service field
                # but keep base name readable
                svc = f"ssh ({banner.split()[0]})" if banner else svc
            risk_level, rationale = assess_risk(res.port, svc, banner)
            enriched.append({
                "port": res.port,
                "state": res.state.value,
                "service": svc,
                "banner": banner,
                "risk": risk_level,
                "risk_rationale": rationale,
            })
    else:
        for res in results:
            svc = service_name(res.port)
            risk_level, rationale = assess_risk(res.port, svc, None)
            enriched.append({
                "port": res.port,
                "state": res.state.value,
                "service": svc,
                "banner": None,
                "risk": risk_level,
                "risk_rationale": rationale,
            })

    # Also include non-open ports with service + risk (but no banner)
    for res in results:
        if res.state != PortState.OPEN:
            if config.banner:
                # already added above only for open; skip non-open
                continue
            svc = service_name(res.port)
            risk_level, rationale = assess_risk(res.port, svc, None)
            enriched.append({
                "port": res.port,
                "state": res.state.value,
                "service": svc,
                "banner": None,
                "risk": risk_level,
                "risk_rationale": rationale,
            })

    # Re-sort by port
    enriched.sort(key=lambda r: r["port"])

    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

    report = build_report(
        target=target,
        target_ip=target_ip,
        scanned_ports=config.ports,
        results=enriched,
        protocol=config.protocol,
        start_time=start_time.isoformat(),
    )
    # Patch duration
    report.scan.duration_seconds = elapsed
    return ScanReport(targets=[report])


def main(argv: List[str] | None = None) -> None:
    """CLI entry point; callable from ``python -m port_scanner``."""
    config = _parse_args(argv)

    # Set up logging for the module logger only (setup_logging reconfigures the
    # package logger). We already called setup_logging in utils import; re-init.
    global logger
    logger = setup_logging(verbose=config.verbose)

    _add_ethical_warning()

    if config.dry_run:
        _run_dry_run(config)
        return

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        report = loop.run_until_complete(_run_scan(config))
    except KeyboardInterrupt:
        print("\nScan interrupted by user.", file=sys.stderr)
        # Optionally write partial — we don't have partial results here in v1.
        sys.exit(130)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        logger.exception("Unhandled error during scan")
        sys.exit(1)

    if config.output:
        write_json(report, config.output)
    else:
        print_report(report)


if __name__ == "__main__":
    main()
