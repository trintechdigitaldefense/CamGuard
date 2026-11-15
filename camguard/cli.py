"""Command-line interface."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from .advisory_ingest import AdvisoryIngestionError, export_approved, ingest_sources
from .intelligence import enrich_assets, load_advisories, load_inventory
from .metadata import collect_metadata
from .pdf_report import write_pdf_report
from .reporting import write_reports
from .risk import apply_risk_scores
from .scanner import ScopeError, scan_network


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="camguard", description="Authorized CCTV/IP camera network assessment.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Inventory common camera/NVR TCP services in an authorized private IPv4 scope.")
    scan.add_argument("--cidr", required=True, help="Approved private IPv4 CIDR, e.g. 192.168.10.0/28")
    scan.add_argument("--authorized", action="store_true", help="Attest that written authorization covers this exact scope.")
    scan.add_argument("--timeout", type=float, default=0.8, help="Per-port TCP timeout (0.1–2.0 seconds).")
    scan.add_argument("--workers", type=int, default=16, help="Concurrent hosts (1–32).")
    scan.add_argument("--output-dir", default="reports", help="Directory for JSON, Markdown and PDF reports.")

    metadata = sub.add_parser("metadata", help="Collect minimal unauthenticated HTTPS metadata from an explicit approved IP allowlist.")
    metadata.add_argument("--targets", required=True, help="Text file with one approved RFC1918 IPv4 address per line.")
    metadata.add_argument("--authorized", action="store_true", help="Attest written authorization covers every listed IP.")
    metadata.add_argument("--timeout", type=float, default=1.0, help="HTTPS timeout (0.1–2.0 seconds).")
    metadata.add_argument("--output", default="camguard-metadata.json", help="JSON output path.")

    ingest = sub.add_parser("ingest-advisories", help="Fetch NVD and CISA KEV data into a pending analyst-review inbox.")
    ingest.add_argument("--days", type=int, default=7, help="NVD modified lookback window (1–120 days).")
    ingest.add_argument("--output-dir", default="data/advisories/inbox", help="Pending review output directory.")

    approve = sub.add_parser("export-approved", help="Validate analyst decisions and export only explicitly approved advisories.")
    approve.add_argument("--approvals", required=True, help="Analyst-maintained approvals JSON file.")
    approve.add_argument("--output", default="data/advisories/approved-advisories.json", help="Approved advisory output path.")

    assess = sub.add_parser("assess", help="Enrich an operator-supplied verified camera inventory and match a local CVE advisory file.")
    assess.add_argument("--inventory", required=True, help="JSON or CSV inventory supplied from approved client records.")
    assess.add_argument("--advisories", help="Local JSON advisory dataset; no external API calls are made.")
    assess.add_argument("--output-dir", default="reports", help="Directory for assessment reports.")
    return parser


def _write_all(result, output_dir):
    json_path, md_path = write_reports(result, output_dir)
    pdf_path = write_pdf_report(result, f"{output_dir}/camguard-assessment.pdf")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    print(f"PDF report: {pdf_path}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            result = scan_network(args.cidr, args.authorized, args.timeout, args.workers)
            apply_risk_scores(result)
            _write_all(result, args.output_dir)
            print(f"Assessment complete: {len(result['assets'])} responsive assets, {len(result['findings'])} findings.")
            return 0
        if args.command == "metadata":
            from pathlib import Path
            import json
            targets = [line.strip() for line in Path(args.targets).read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
            result = collect_metadata(targets, args.authorized, timeout=args.timeout)
            Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
            print("Metadata report: " + args.output)
            print("Targets assessed: " + str(len(result["targets"])))
            return 0
        if args.command == "ingest-advisories":
            import os
            paths = ingest_sources(args.output_dir, days=args.days, api_key=os.environ.get("NVD_API_KEY"))
            for name, path in paths.items():
                print(f"{name}: {path}")
            print("Downloaded records are pending review only; no CVE matches were approved.")
            return 0
        if args.command == "export-approved":
            count = export_approved(args.approvals, args.output)
            print(f"Exported {count} analyst-approved advisories: {args.output}")
            return 0
        if args.command == "assess":
            inventory = load_inventory(args.inventory)
            advisories = load_advisories(args.advisories) if args.advisories else []
            result = {
                "tool": "TrinTech CamGuard", "version": "0.4.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scope": {"cidr": "operator-supplied inventory", "addresses_considered": len(inventory), "authorization_attested": False},
                "scan_type": "offline inventory enrichment and exact CVE advisory matching; no network probes",
                "assets": [{"ip": ip, "open_ports": [], "observed_at": None} for ip in sorted(inventory)],
                "findings": [], "limitations": [
                    "Identity and firmware values are only as reliable as the operator-supplied source.",
                    "CVE matches require verified inventory, exact CPE equality and exact firmware-version equality.",
                    "The advisory file may be incomplete or stale; verify each advisory with its publisher.",
                    "No device login, HTTP fingerprinting, external lookup, or configuration change is performed.",
                ],
            }
            result = enrich_assets(result, inventory, advisories)
            apply_risk_scores(result)
            _write_all(result, args.output_dir)
            print(f"Assessment complete: {len(result['assets'])} inventory records, {len(result['findings'])} matched findings.")
            return 0
    except (ScopeError, AdvisoryIngestionError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"CamGuard error: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
