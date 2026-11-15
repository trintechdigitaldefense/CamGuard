"""Command-line interface."""
from __future__ import annotations

import argparse
import sys

from .reporting import write_reports
from .scanner import ScopeError, scan_network


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="camguard", description="Authorized CCTV/IP camera network assessment.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Inventory common camera/NVR TCP services in an authorized private IPv4 scope.")
    scan.add_argument("--cidr", required=True, help="Approved private IPv4 CIDR, e.g. 192.168.10.0/28")
    scan.add_argument("--authorized", action="store_true", help="Attest that written authorization covers this exact scope.")
    scan.add_argument("--timeout", type=float, default=0.8, help="Per-port TCP timeout (0.1–2.0 seconds).")
    scan.add_argument("--workers", type=int, default=16, help="Concurrent hosts (1–32).")
    scan.add_argument("--output-dir", default="reports", help="Directory for JSON and Markdown reports.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        try:
            result = scan_network(args.cidr, args.authorized, args.timeout, args.workers)
            json_path, md_path = write_reports(result, args.output_dir)
        except (ScopeError, OSError) as exc:
            print(f"CamGuard error: {exc}", file=sys.stderr)
            return 2
        print(f"Assessment complete: {len(result['assets'])} responsive assets, {len(result['findings'])} findings.")
        print(f"JSON report: {json_path}")
        print(f"Markdown report: {md_path}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
