"""JSON and Markdown report writers."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any


def write_reports(result: dict[str, Any], output_dir: str) -> tuple[Path, Path]:
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = result["generated_at"].replace(":", "").replace("-", "").replace(".", "")
    json_path = folder / f"camguard-{stamp}.json"
    md_path = folder / f"camguard-{stamp}.md"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    lines = [
        "# TrinTech CamGuard Assessment", "",
        f"- Generated: {result['generated_at']}",
        f"- CamGuard version: {result.get('version', 'unknown')}",
        f"- Authorized scope: {result['scope']['cidr']}",
        f"- Addresses considered: {result['scope']['addresses_considered']}",
        f"- Method: {result['scan_type']}", "",
        "## Executive summary",
        f"- Responsive assets: {len(result['assets'])}",
        f"- Findings: {len(result['findings'])}",
        f"- Service observations: {len(result.get('service_observations', []))}",
        "", "## Asset inventory",
    ]
    if not result["assets"]:
        lines.append("No hosts responded on the assessed TCP ports.")
    for asset in result["assets"]:
        ports = ", ".join(f"{p['port']} ({p['service']})" for p in asset["open_ports"])
        lines.append(f"- **{asset['ip']}** — {ports}; risk **{asset.get('risk_rating', 'unscored')} {asset.get('risk_score', 0)}/100** (confidence: {asset.get('risk_confidence', 'unknown')})")
        for reason in asset.get("risk_explanation", []):
            lines.append(f"  - Risk rationale: {reason}")
    lines += ["", "## Service exposure observations"]
    observations = result.get("service_observations", [])
    if not observations:
        lines.append("No service-level protocol observations were recorded.")
    for obs in observations:
        lines += [
            f"### {obs.get('device_ip', 'Unknown IP')} — {obs.get('port', 'unknown')}/{obs.get('transport', 'tcp').upper()}",
            f"- Reachability: {obs.get('reachability', 'unknown')}",
            f"- Service: {obs.get('service_name') or 'Unknown'} ({obs.get('service_identification', 'unknown')})",
            f"- Service evidence: {obs.get('service_evidence', 'Not recorded')}",
            f"- Encryption: {obs.get('encryption_status', 'unknown')}",
            f"- Encryption evidence: {obs.get('encryption_evidence', 'Not recorded')}",
            f"- Evidence confidence: {obs.get('evidence_confidence', 'unknown')}",
            f"- Why it matters: {obs.get('business_significance', 'Not assessed')}",
            f"- Recommended action: {obs.get('recommended_action', 'Verify with the administrator.')}",
            *[f"- Limitation: {item}" for item in obs.get("limitations", [])], "",
        ]
    lines += ["", "## Technician-assisted inspections"]
    inspections = result.get("inspections", [])
    if not inspections:
        lines.append("No technician-assisted inspection records were attached.")
    for inspection in inspections:
        from .inspection import inspection_summary, validate_inspection
        validate_inspection(inspection, require_complete=False)
        summary = inspection_summary(inspection)
        lines += [
            f"### {inspection.get('device_ip', 'Unknown device')} — {inspection.get('asset_id', 'Unlinked asset')}",
            f"- Inspector: {inspection.get('inspector', 'Not recorded')}",
            f"- Inspected at: {inspection.get('inspected_at', 'Not recorded')}",
            f"- Checklist completion: {summary['completed_checks']}/{summary['total_checks']}",
            f"- Pass: {summary['pass']}; Fail: {summary['fail']}; Needs attention: {summary['needs_attention']}; Not verified: {summary['not_verified']}; Not applicable: {summary['not_applicable']}",
        ]
        for response in inspection.get("responses", []):
            lines += [
                f"- **{response['category']} / {response['check_id']} — {response['status'].replace('_', ' ').title()}**",
                f"  - {response['question']}",
                *([f"  - Notes: {response['notes']}"] if response.get("notes") else []),
                *([f"  - Evidence references: {', '.join(response['evidence_refs'])}"] if response.get("evidence_refs") else []),
            ]
        lines += [f"- Limitation: {item}" for item in inspection.get("limitations", [])]
        lines.append("")
    lines += ["", "## Findings"]
    if not result["findings"]:
        lines.append("No findings were generated from the supplied evidence.")
    for i, finding in enumerate(result["findings"], 1):
        lines += [
            f"### {i}. {finding['title']} — {finding['severity'].upper()}",
            f"- Asset: {finding['asset_ip']}",
            f"- Evidence: {finding['evidence']}",
            f"- Recommendation: {finding['recommendation']}",
            f"- Risk: {finding.get('risk_rating', 'unscored')} {finding.get('risk_score', 0)}/100; evidence confidence: {finding.get('evidence_confidence', 'unknown')}",
            f"- Risk components: {finding.get('risk_components', {})}",
            *[f"- Why this score: {reason}" for reason in finding.get("risk_explanation", [])], "",
        ]
    method = result.get("risk_methodology", {})
    if method:
        lines += [
            "", "## Risk prioritization methodology",
            f"- Formula: {method.get('formula', 'See per-finding rationale.')}",
            f"- Aggregation: {method.get('aggregation', 'Highest finding per asset.')}",
            f"- Exposure policy: {method.get('exposure_policy', 'Unverified exposure is not scored.')}",
            f"- Confidence: {method.get('confidence', 'Reported separately from score.')}",
        ]
        lines += [f"- Limitation: {item}" for item in method.get("limitations", [])]
    lines += ["", "## Limitations"] + [f"- {item}" for item in result["limitations"]]
    lines += ["", "> This report reflects only the assessment method and evidence described above. It is not proof of compromise, exploitability, or safety.", ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path
