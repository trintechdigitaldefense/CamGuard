"""JSON and Markdown report writers."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "token", "accesstoken", "refreshtoken",
    "apikey", "secret", "clientsecret", "authorization", "privatekey",
    "cookie", "setcookie",
}
_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)\b(password|passwd|pwd|access[_-]?token|refresh[_-]?token|"
    r"api[_-]?key|client[_-]?secret|private[_-]?key|set-cookie|"
    r"token|secret|authorization|cookie)\b(\s*[:=]\s*)"
    r'(?:"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|'
    r"(?:Bearer|Basic)\s+[^\s,;]+|[^\s,;]+)"
)
_MARKDOWN_SPECIAL = set("\\\`*_{}[]()#+!|><")


def _is_sensitive_key(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    return normalized in _SENSITIVE_KEYS


def redact_sensitive(value: Any) -> str:
    """Redact common secret-like key/value pairs, including quoted and auth values."""
    return _SENSITIVE_KEY_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        str(value),
    )


def sanitize_sensitive_data(value: Any) -> Any:
    """Recursively redact sensitive mapping values and embedded secret patterns."""
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _is_sensitive_key(key)
            else sanitize_sensitive_data(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_sensitive_data(item) for item in value]
    if isinstance(value, str):
        return redact_sensitive(value)
    return value

def _safe_markdown(value: Any) -> str:
    """Redact common key/value secrets and escape untrusted Markdown text."""
    text = redact_sensitive(value).replace("\r", " ").replace("\n", " ")
    text = text.replace("[REDACTED]", "CAMGUARDREDACTEDTOKEN")
    escaped = "".join(("\\" + char) if char in _MARKDOWN_SPECIAL else char for char in text)
    return escaped.replace("CAMGUARDREDACTEDTOKEN", "[REDACTED]")


def write_reports(result: dict[str, Any], output_dir: str) -> tuple[Path, Path]:
    folder = Path(output_dir)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = result["generated_at"].replace(":", "").replace("-", "").replace(".", "")
    json_path = folder / f"camguard-{stamp}.json"
    md_path = folder / f"camguard-{stamp}.md"
    json_path.write_text(json.dumps(sanitize_sensitive_data(result), indent=2), encoding="utf-8")
    lines = [
        "# TrinTech CamGuard Assessment", "",
        f"- Generated: {_safe_markdown(result['generated_at'])}",
        f"- CamGuard version: {_safe_markdown(result.get('version', 'unknown'))}",
        f"- Authorized scope: {_safe_markdown(result['scope']['cidr'])}",
        f"- Addresses considered: {result['scope']['addresses_considered']}",
        f"- Method: {_safe_markdown(result['scan_type'])}", "",
        "## Executive summary",
        f"- Responsive assets: {len(result['assets'])}",
        f"- Findings: {len(result['findings'])}",
        f"- Service observations: {len(result.get('service_observations', []))}",
        "", "## Asset inventory",
    ]
    if not result["assets"]:
        lines.append("No hosts responded on the assessed TCP ports.")
    for asset in result["assets"]:
        ports = ", ".join(f"{p['port']} ({_safe_markdown(p['service'])})" for p in asset["open_ports"])
        lines.append(f"- **{_safe_markdown(asset['ip'])}** — {ports}; risk **{_safe_markdown(asset.get('risk_rating', 'unscored'))} {asset.get('risk_score', 0)}/100** (confidence: {_safe_markdown(asset.get('risk_confidence', 'unknown'))})")
        for reason in asset.get("risk_explanation", []):
            lines.append(f"  - Risk rationale: {_safe_markdown(reason)}")
    lines += ["", "## Service exposure observations"]
    observations = result.get("service_observations", [])
    if not observations:
        lines.append("No service-level protocol observations were recorded.")
    for obs in observations:
        lines += [
            f"### {_safe_markdown(obs.get('device_ip', 'Unknown IP'))} — {_safe_markdown(obs.get('port', 'unknown'))}/{_safe_markdown(obs.get('transport', 'tcp')).upper()}",
            f"- Reachability: {_safe_markdown(obs.get('reachability', 'unknown'))}",
            f"- Service: {_safe_markdown(obs.get('service_name') or 'Unknown')} ({_safe_markdown(obs.get('service_identification', 'unknown'))})",
            f"- Service evidence: {_safe_markdown(obs.get('service_evidence', 'Not recorded'))}",
            f"- Encryption: {_safe_markdown(obs.get('encryption_status', 'unknown'))}",
            f"- Encryption evidence: {_safe_markdown(obs.get('encryption_evidence', 'Not recorded'))}",
            f"- Evidence confidence: {_safe_markdown(obs.get('evidence_confidence', 'unknown'))}",
            f"- Why it matters: {_safe_markdown(obs.get('business_significance', 'Not assessed'))}",
            f"- Recommended action: {_safe_markdown(obs.get('recommended_action', 'Verify with the administrator.'))}",
            *[f"- Limitation: {_safe_markdown(item)}" for item in obs.get("limitations", [])], "",
        ]
    lines += ["", "## Findings"]
    if not result["findings"]:
        lines.append("No findings were generated from the supplied evidence.")
    for i, finding in enumerate(result["findings"], 1):
        lines += [
            f"### {i}. {_safe_markdown(finding['title'])} — {_safe_markdown(finding['severity']).upper()}",
            f"- Asset: {_safe_markdown(finding['asset_ip'])}",
            f"- Evidence: {_safe_markdown(finding['evidence'])}",
            f"- Recommendation: {_safe_markdown(finding['recommendation'])}",
            f"- Risk: {_safe_markdown(finding.get('risk_rating', 'unscored'))} {finding.get('risk_score', 0)}/100; evidence confidence: {_safe_markdown(finding.get('evidence_confidence', 'unknown'))}",
            f"- Risk components: {_safe_markdown(finding.get('risk_components', {}))}",
            *[f"- Why this score: {_safe_markdown(reason)}" for reason in finding.get("risk_explanation", [])], "",
        ]
    method = result.get("risk_methodology", {})
    if method:
        lines += [
            "", "## Risk prioritization methodology",
            f"- Formula: {_safe_markdown(method.get('formula', 'See per-finding rationale.'))}",
            f"- Aggregation: {_safe_markdown(method.get('aggregation', 'Highest finding per asset.'))}",
            f"- Exposure policy: {_safe_markdown(method.get('exposure_policy', 'Unverified exposure is not scored.'))}",
            f"- Confidence: {_safe_markdown(method.get('confidence', 'Reported separately from score.'))}",
        ]
        lines += [f"- Limitation: {_safe_markdown(item)}" for item in method.get("limitations", [])]
    lines += ["", "## Limitations"] + [f"- {_safe_markdown(item)}" for item in result["limitations"]]
    lines += ["", "> This report reflects only the assessment method and evidence described above. It is not proof of compromise, exploitability, or safety.", ""]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path
