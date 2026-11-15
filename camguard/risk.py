"""Transparent prioritization scores; not a prediction of compromise probability."""
from __future__ import annotations

from typing import Any

SEVERITY_POINTS = {"critical": 95, "high": 80, "medium": 55, "low": 30, "info": 10}


def apply_risk_scores(result: dict[str, Any]) -> dict[str, Any]:
    scored = []
    by_ip: dict[str, list[int]] = {}
    for finding in result.get("findings", []):
        if "cvss_base_score" in finding:
            # CVSS is a technical severity input, scaled to 0-100, not a likelihood.
            score = round(float(finding["cvss_base_score"]) * 10)
            basis = "CVSS base score × 10"
        else:
            score = SEVERITY_POINTS.get(str(finding.get("severity", "info")).lower(), 10)
            basis = "CamGuard service-exposure heuristic"
        finding["risk_score"] = max(0, min(100, score))
        finding["risk_basis"] = basis
        scored.append(finding)
        by_ip.setdefault(finding.get("asset_ip", "unknown"), []).append(finding["risk_score"])
    for asset in result.get("assets", []):
        scores = by_ip.get(asset["ip"], [])
        asset["risk_score"] = max(scores, default=0)
        asset["risk_rating"] = _rating(asset["risk_score"])
    result["risk_methodology"] = {
        "range": "0-100",
        "aggregation": "Highest finding score per asset; no additive stacking.",
        "cvss": "CVSS base score multiplied by 10. CVSS describes technical severity, not exploit likelihood.",
        "heuristics": "Service reachability scores are triage indicators only, not vulnerability claims.",
        "ratings": {"critical": "90-100", "high": "70-89", "medium": "40-69", "low": "1-39", "informational": "0"},
        "not_assessed": ["internet exposure", "exploitability in the client environment", "business impact", "compensating controls"],
    }
    return result


def _rating(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "informational"
