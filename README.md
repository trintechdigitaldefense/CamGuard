# TrinTech CamGuard

**CCTV & IP Camera Cybersecurity Assessment**

CamGuard is an authorized, scope-limited network inventory and security assessment tool from TrinTech Digital Defense. The first MVP focuses on safe TCP service discovery, asset inventory, risk findings, and JSON/Markdown reporting.

> **Authorization required:** Only assess networks and devices that you own or have explicit written permission to test. The operator must confirm authorization with `--authorized`. This flag is an operator attestation, not a substitute for written client consent.

## MVP capabilities

- IPv4 CIDR scope validation (private IPv4 ranges only by default).
- Bounded TCP connection checks for common CCTV/NVR management and streaming ports.
- Asset inventory with responsive ports and timestamps.
- Conservative findings for exposed management services.
- JSON and Markdown reports; no passwords, video streams, or credentials are collected.
- Unit tests using Python's standard library.

## Safety limits

- No exploitation, password guessing, brute force, authentication attempts, RTSP stream access, or camera footage collection.
- No UDP scans, raw sockets, packet capture, or stealth functionality.
- The default maximum scope is 256 addresses; concurrency and connection timeout are bounded.
- The tool checks TCP reachability only. An open port does not prove a vulnerability.
- Firmware/CVE correlation, authenticated configuration review, and continuous monitoring are planned follow-on features, not implemented claims.

## Requirements

- Python 3.10+
- No third-party dependencies for the MVP

## Quick start

```bash
python -m camguard --help
python -m camguard scan --cidr 192.168.10.0/24 --authorized --output-dir reports
```

Run the command only after confirming written authorization and that the CIDR exactly matches the approved scope.

## Example output

CamGuard writes:
- `camguard-<timestamp>.json` — machine-readable inventory and findings
- `camguard-<timestamp>.md` — human-readable assessment summary

## Development

```bash
python -m unittest discover -s tests -v
```

## Project status

**MVP foundation — active development.** This release is a bounded TCP inventory and reporting prototype, not a full CCTV vulnerability scanner or managed monitoring service.

## Roadmap

1. MVP: scoped TCP discovery, findings, JSON/Markdown reports.
2. Asset enrichment: vendor/model/firmware inventory from operator-provided records.
3. Advisory matching: curated CVE references with source and confidence tracking.
4. Configuration review: guided, non-invasive checks for NVR/router/camera settings.
5. PDF reporting and remediation history.
6. Optional scheduled monitoring with explicit client approval.

## TrinTech Digital Defense

Website: https://trintechdigitaldefense.github.io  
Phone: +1 (868) 362-0679
