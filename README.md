# Port Scanner

```text
╔══════════════════════════════╗
║        PORT SCANNER          ║
║  discover services safely    ║
╚══════════════════════════════╝
```

Network port scanner in Python using socket programming. Fast, concurrent port scanning with service detection and risk assessment.

[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)


## Features

- **Port Scanning** — TCP connect scan for common and custom port ranges
- **Service Detection** — Identify services running on open ports
- **Banner Grabbing** — Capture service banners for identification
- **Risk Assessment** — Evaluate port/service risk levels
- **Reporting** — Generate detailed scan reports in multiple formats
- **Concurrent Scanning** — Scan multiple ports and hosts efficiently

## Installation

```bash
git clone https://github.com/aimansam/port-scanner
cd port-scanner
pip install -e .
```

## Quick Start

Scan common ports on a target:

```bash
port-scanner 192.168.1.1
```

Scan specific ports:

```bash
port-scanner 192.168.1.1 --ports 22,80,443,8080
```

Scan a range:

```bash
port-scanner 192.168.1.1 --ports 1-1024
```

Scan multiple targets:

```bash
port-scanner 192.168.1.1 192.168.1.2 192.168.1.3
```

Generate a report:

```bash
port-scanner 192.168.1.1 --output scan_report.json
```

## Requirements

- Python 3.9+
- No external dependencies (stdlib only)

## License

MIT
