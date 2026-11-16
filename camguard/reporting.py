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
        "# TrinTech CamGuard Assessment",
        "",
        f"- Generated: {result['generated_at']}",
        f"- Authorized scope: {result['scope']['cidr']}",
        f"- Addresses considered: {result['scope']['addresses_considered']}",
        f"- Method: {result['scan_type']}",
        "",
        "## Executive summary",
        f"- Responsive assets: {len(result['assets'])}",
        f"- Findings: {len(result['findings'])}",
        "",
        "## Asset inventory",
    ]
    if not result["assets"]:
        lines.append("No hosts responded on the assessed TCP ports.")
    for asset in result["assets"]:
        ports = ", ".join(f"{p['port']} ({p['service']})" for p in asset["open_ports"])
        lines.append(f"- **{asset['ip']}** — {ports}; risk **{asset.get('risk_rating', 'unscored')} {asset.get('risk_score', 0)}/100** (confidence: {asset.get('risk_confidence', 'unknown')})")
        for reason in asset.get("risk_explanation", []):
            lines.append(f"  - Risk rationale: {reason}")
    lines += ["", "## Findings"]
    if not result["findings"]:
        lines.append("No listed services were detected.")
    for i, finding in enumerate(result["findings"], 1):
        lines += [
            f"### {i}. {finding['title']} — {finding['severity'].upper()}",
            f"- Asset: {finding['asset_ip']}",
            f"- Evidence: {finding['evidence']}",
            f"- Recommendation: {finding['recommendation']}",
            f"- Risk: {finding.get('risk_rating', 'unscored')} {finding.get('risk_score', 0)}/100; evidence confidence: {finding.get('evidence_confidence', 'unknown')}",
            f"- Risk components: {finding.get('risk_components', {})}",
            *[f"- Why this score: {reason}" for reason in finding.get("risk_explanation", [])],
            "",
        ]
    method = result.get("risk_methodology", {})
    if method:
        lines += ["", "## Risk prioritization methodology",
                  f"- Formula: {method.get('formula', 'See per-finding rationale.')}",
                  f"- Aggregation: {method.get('aggregation', 'Highest finding per asset.')}",
                  f"- Exposure policy: {method.get('exposure_policy', 'Unverified exposure is not scored.')}",
                  f"- Confidence: {method.get('confidence', 'Reported separately from score.')}"]
        lines += [f"- Limitation: {item}" for item in method.get("limitations", [])]
    lines += ["", "## Limitations"] + [f"- {item}" for item in result["limitations"]]
    lines += ["", "> This report reflects only the assessment method and evidence described above. It is not proof of compromise, exploitability, or safety.", ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path
