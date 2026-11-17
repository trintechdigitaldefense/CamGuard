"""Command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from datetime import datetime, timezone

from . import __version__
from .advisory_ingest import AdvisoryIngestionError, export_approved, ingest_sources
from .intelligence import enrich_assets, load_advisories, load_inventory
from .manufacturer_intel import normalize_device_identity, supported_manufacturers
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
    scan.add_argument("--assessment-id", help="Assessment identifier used to link technician inspection records.")
    scan.add_argument("--inspection", action="append", default=[], help="Inspection JSON to attach to this report; repeat for multiple assets.")

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
    approve.add_argument("--inbox", required=True, help="Pending inbox used to verify each approved CVE.")
    approve.add_argument("--audit", default="data/advisories/review-audit.jsonl", help="Hash-chained analyst review audit log.")

    review = sub.add_parser("review-advisories", help="Search pending advisories, record analyst decisions and verify the audit log.")
    review_actions = review.add_subparsers(dest="review_action", required=True)

    review_list = review_actions.add_parser("list", help="List and search pending advisory candidates.")
    review_list.add_argument("--inbox", default="data/advisories/inbox/pending-review.json", help="Pending advisory inbox JSON.")
    review_list.add_argument("--approvals", default="data/advisories/approvals.json", help="Existing analyst decisions to hide from the queue.")
    review_list.add_argument("--query", default="", help="Search CVE, vendor, product or description.")
    review_list.add_argument("--limit", type=int, default=50, help="Maximum results (1–500).")
    review_list.add_argument("--offset", type=int, default=0, help="Number of matching results to skip.")
    review_list.add_argument("--kev-only", action="store_true", help="Show only CISA KEV entries.")

    review_decide = review_actions.add_parser("decide", help="Record an analyst decision with evidence and an audit entry.")
    review_decide.add_argument("--inbox", default="data/advisories/inbox/pending-review.json", help="Pending advisory inbox JSON.")
    review_decide.add_argument("--approvals", default="data/advisories/approvals.json", help="Analyst decisions JSON output.")
    review_decide.add_argument("--audit", default="data/advisories/review-audit.jsonl", help="Hash-chained audit log.")
    review_decide.add_argument("--cve", required=True, help="CVE identifier to review.")
    review_decide.add_argument("--decision", required=True, choices=("approved", "rejected", "pending"))
    review_decide.add_argument("--reviewed-by", required=True, help="Analyst identifier.")
    review_decide.add_argument("--rationale", required=True, help="Reason for the decision.")
    review_decide.add_argument("--evidence-url", required=True, help="HTTPS vendor advisory/evidence URL.")
    review_decide.add_argument("--cpe", help="Exact CPE 2.3 for an approval.")
    review_decide.add_argument("--cvss-score", type=float, help="Analyst-sourced CVSS score required for KEV-only candidates.")
    review_decide.add_argument("--affected-version", action="append", default=[], help="Explicit affected firmware version; repeat as needed.")

    review_verify = review_actions.add_parser("verify-audit", help="Verify the hash chain in the analyst audit log.")
    review_verify.add_argument("--audit", default="data/advisories/review-audit.jsonl", help="Hash-chained audit log to verify.")

    normalize = sub.add_parser("normalize-device", help="Normalize a supplied manufacturer and generic product-family alias.")
    normalize.add_argument("--vendor", required=True, help="Manufacturer name or known alias.")
    normalize.add_argument("--product", help="Product family or model name; unknown model identifiers are preserved.")

    sub.add_parser("manufacturer-catalog", help="Show supported CCTV manufacturer names and exact aliases.")

    assess = sub.add_parser("assess", help="Enrich verified camera inventory using audit-verified analyst-approved advisories.")
    assess.add_argument("--inventory", required=True, help="JSON or CSV inventory supplied from approved client records.")
    assess.add_argument("--approvals", help="Analyst approvals JSON produced by the review workflow.")
    assess.add_argument("--inbox", help="Current pending advisory inbox used to verify approvals.")
    assess.add_argument("--audit", help="Hash-chained analyst review audit log.")
    assess.add_argument("--output-dir", default="reports", help="Directory for assessment reports.")
    assess.add_argument("--assessment-id", help="Assessment identifier used to link technician inspection records.")
    assess.add_argument("--inspection", action="append", default=[], help="Inspection JSON to attach to this report; repeat for multiple assets.")

    inspection = sub.add_parser("inspection", help="Create and manage manual technician-assisted CCTV inspection records.")
    inspection_actions = inspection.add_subparsers(dest="inspection_action", required=True)

    inspection_create = inspection_actions.add_parser("create", help="Create a blank inspection record for one inventoried asset.")
    inspection_create.add_argument("--assessment-id", required=True, help="Client assessment identifier.")
    inspection_create.add_argument("--asset-id", required=True, help="Asset identifier from the client inventory.")
    inspection_create.add_argument("--device-ip", required=True, help="Camera/NVR IPv4 address recorded in the inventory.")
    inspection_create.add_argument("--inspector", required=True, help="Technician identifier or name.")
    inspection_create.add_argument("--inspected-at", help="Inspection timestamp (ISO 8601); defaults to current UTC.")
    inspection_create.add_argument("--output", required=True, help="New inspection JSON file to create.")

    inspection_template = inspection_actions.add_parser("template", help="Display the six checklist categories and their 30 check IDs.")
    inspection_template.add_argument("--category", choices=("account_permissions", "default_credential_policy", "nvr_configuration", "remote_access", "physical_security", "recording_retention"), help="Show one category; omit to show all.")

    inspection_record = inspection_actions.add_parser("record", help="Record or replace one technician response in an inspection JSON file.")
    inspection_record.add_argument("--input", required=True, help="Existing inspection JSON file.")
    inspection_record.add_argument("--category", required=True, choices=("account_permissions", "default_credential_policy", "nvr_configuration", "remote_access", "physical_security", "recording_retention"))
    inspection_record.add_argument("--check", required=True, help="Exact check ID shown by 'camguard inspection template'.")
    inspection_record.add_argument("--status", required=True, choices=("pass", "fail", "not_verified", "not_applicable", "needs_attention"))
    inspection_record.add_argument("--notes", default="", help="Technician explanation; never include credentials, tokens or secrets.")
    inspection_record.add_argument("--evidence-ref", action="append", default=[], help="Operator-managed evidence reference; repeat for multiple references. Never attach footage or secrets.")
    inspection_record.add_argument("--reviewed-at", help="Response timestamp (ISO 8601); defaults to current UTC.")
    inspection_record.add_argument("--output", help="Output JSON path; defaults to updating --input.")

    inspection_validate = inspection_actions.add_parser("validate", help="Validate an inspection and show its completion summary.")
    inspection_validate.add_argument("--input", required=True, help="Inspection JSON file to validate.")
    inspection_validate.add_argument("--require-complete", action="store_true", help="Return an error unless all 30 checks have responses.")

    return parser


def _write_all(result, output_dir):
    json_path, md_path = write_reports(result, output_dir)
    pdf_path = write_pdf_report(result, f"{output_dir}/camguard-assessment.pdf")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    print(f"PDF report: {pdf_path}")


def _load_attached_inspections(paths: list[str], assets: list[dict], assessment_id: str | None):
    """Load technician records and bind them to assets in this assessment."""
    if not paths:
        return []
    from .inspection import validate_inspection

    if not assessment_id:
        raise ValueError("--assessment-id is required when attaching --inspection records.")
    known_ips = {asset.get("ip") for asset in assets}
    inspections = []
    for path in paths:
        inspection = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(inspection, dict):
            raise ValueError(f"Inspection file must contain a JSON object: {path}")
        validate_inspection(inspection, require_complete=False)
        if inspection.get("assessment_id") != assessment_id:
            raise ValueError(f"Inspection assessment_id does not match --assessment-id: {path}")
        if inspection.get("device_ip") not in known_ips:
            raise ValueError(f"Inspection device_ip is not present in this assessment inventory: {path}")
        inspections.append(inspection)
    return inspections


def _read_inspection(path: str):
    from .inspection import validate_inspection
    inspection = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(inspection, dict):
        raise ValueError("Inspection JSON must contain an object.")
    validate_inspection(inspection, require_complete=False)
    return inspection


def _run_inspection(args) -> int:
    from .inspection import (
        CHECKLISTS, checklist_template, create_inspection, inspection_summary,
        record_check, validate_inspection, write_inspection_json,
    )
    if args.inspection_action == "template":
        templates = checklist_template()
        if args.category:
            templates = [item for item in templates if item["category_id"] == args.category]
        print(json.dumps({"checklists": templates}, indent=2))
        return 0
    if args.inspection_action == "create":
        inspection = create_inspection(
            args.assessment_id, args.asset_id, args.device_ip, args.inspector,
            inspected_at=args.inspected_at,
        )
        path = write_inspection_json(inspection, args.output)
        print(f"Inspection created: {path}")
        print(f"Inspection ID: {inspection['inspection_id']}")
        print(f"Checklist checks: {sum(len(item['checks']) for item in CHECKLISTS.values())}")
        return 0
    inspection = _read_inspection(args.input)
    if args.inspection_action == "record":
        response = record_check(
            inspection, args.category, args.check, args.status,
            notes=args.notes, evidence_refs=args.evidence_ref,
            reviewed_at=args.reviewed_at,
        )
        path = write_inspection_json(inspection, args.output or args.input)
        print(f"Recorded {response['status']} for {response['category_id']}/{response['check_id']}.")
        print(f"Inspection JSON: {path}")
        return 0
    if args.inspection_action == "validate":
        validate_inspection(inspection, require_complete=args.require_complete)
        print(json.dumps({
            "valid": True,
            "complete_required": args.require_complete,
            "summary": inspection_summary(inspection),
        }, indent=2))
        return 0
    raise ValueError("Unknown inspection action.")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "inspection":
            return _run_inspection(args)
        if args.command == "scan":
            result = scan_network(args.cidr, args.authorized, args.timeout, args.workers)
            result["inspections"] = _load_attached_inspections(args.inspection, result["assets"], args.assessment_id)
            apply_risk_scores(result)
            _write_all(result, args.output_dir)
            print(f"Assessment complete: {len(result['assets'])} responsive assets, {len(result['findings'])} findings.")
            return 0
        if args.command == "metadata":
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
            from .advisory_review import export_reviewed_approvals
            count = export_reviewed_approvals(args.approvals, args.inbox, args.output, args.audit)
            print(f"Exported {count} inbox-verified analyst-approved advisories: {args.output}")
            return 0
        if args.command == "review-advisories":
            from .advisory_review import list_pending, record_decision, verify_audit
            if args.review_action == "list":
                rows = list_pending(args.inbox, query=args.query, kev_only=args.kev_only,
                                    limit=args.limit, offset=args.offset,
                                    approvals_path=args.approvals)
                print(json.dumps({"count": len(rows), "offset": args.offset, "items": rows}, indent=2))
                return 0
            if args.review_action == "verify-audit":
                print(json.dumps(verify_audit(args.audit), indent=2))
                return 0
            event = record_decision(
                args.inbox, args.approvals, args.audit, args.cve, args.decision,
                args.reviewed_by, args.rationale, args.evidence_url,
                cpe=args.cpe or "", affected_versions=args.affected_version,
                cvss_score=args.cvss_score,
            )
            print(f"Recorded {event['decision']} decision for {event['cve']}.")
            print(f"Audit record: {event['record_hash']}")
            return 0
        if args.command == "normalize-device":
            print(json.dumps(normalize_device_identity(args.vendor, args.product), indent=2))
            return 0
        if args.command == "manufacturer-catalog":
            print(json.dumps({"manufacturers": supported_manufacturers()}, indent=2))
            return 0
        if args.command == "assess":
            inventory = load_inventory(args.inventory)
            approval_inputs = (args.approvals, args.inbox, args.audit)
            if any(approval_inputs) and not all(approval_inputs):
                raise ValueError("--approvals, --inbox and --audit must be supplied together.")

            advisories = []
            if all(approval_inputs):
                from .advisory_review import export_reviewed_approvals
                with tempfile.TemporaryDirectory(prefix="camguard-approved-") as temporary:
                    approved_path = Path(temporary) / "approved-advisories.json"
                    export_reviewed_approvals(
                        args.approvals, args.inbox, approved_path, args.audit
                    )
                    advisories = load_advisories(str(approved_path))

            result = {
                "tool": "TrinTech CamGuard", "version": __version__,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scope": {"cidr": "operator-supplied inventory", "addresses_considered": len(inventory), "authorization_attested": False},
                "scan_type": "offline inventory enrichment and audit-verified advisory matching; no network probes",
                "assets": [{"ip": ip, "open_ports": [], "observed_at": None} for ip in sorted(inventory)],
                "findings": [], "limitations": [
                    "Identity and firmware values are only as reliable as the operator-supplied source.",
                    "CVE matches require verified inventory, exact CPE equality and exact firmware-version equality.",
                    "Only advisories validated against the current inbox and hash-chained analyst audit are eligible for CVE matching.",
                    "No device login, HTTP fingerprinting, external lookup, or configuration change is performed.",
                ],
            }
            result = enrich_assets(result, inventory, advisories)
            result["inspections"] = _load_attached_inspections(args.inspection, result["assets"], args.assessment_id)
            apply_risk_scores(result)
            _write_all(result, args.output_dir)
            print(f"Assessment complete: {len(result['assets'])} inventory records, {len(result['findings'])} matched findings.")
            return 0
    except (ScopeError, AdvisoryIngestionError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"CamGuard error: {exc}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
