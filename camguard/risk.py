"""Explainable, deterministic risk prioritization for authorized CCTV assessments.

Scores are prioritization aids, not probabilities of compromise. CVE scoring is
only enhanced when an advisory has been analyst-approved and exact verified
device CPE/firmware applicability has already been established by enrichment.
"""
from __future__ import annotations

from typing import Any

SEVERITY_POINTS = {"critical": 95, "high": 80, "medium": 55, "low": 30, "info": 10}
EXPOSURE_UPLIFT = {"internet_exposed": 15, "internal_segment": 5, "isolated": 0, "unknown": 0}
CONFIDENCE_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3}


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


def _confidence(finding: dict[str, Any]) -> tuple[str, list[str]]:
    if finding.get("cvss_base_score") is not None:
        if not finding.get("exact_verified_match"):
            return "low", ["A CVE finding without an exact verified inventory match is not eligible for device-level vulnerability scoring."]
        if finding.get("reviewed_by") and finding.get("reviewed_at") and str(finding.get("source") or "").startswith("https://"):
            return "high", ["Device identity and firmware matched exactly; advisory carries analyst review metadata and an HTTPS evidence source."]
        return "medium", ["Device identity and firmware matched exactly, but complete analyst-review provenance was not present in this advisory record."]
    if finding.get("evidence"):
        return "low", ["Evidence is a bounded network observation; it does not establish vulnerability or device identity."]
    return "unknown", ["No supporting evidence was supplied."]


def _score_finding(finding: dict[str, Any]) -> dict[str, Any]:
    if finding.get("cvss_base_score") is not None:
        if not finding.get("exact_verified_match"):
            base = kev_uplift = exposure_uplift = 0
            reasons = ["No device-level CVE score: exact verified CPE and firmware applicability is absent."]
        else:
            score = float(finding["cvss_base_score"])
            if not 0 <= score <= 10:
                raise ValueError("CVSS base score must be between 0 and 10.")
            base = round(score * 10)
            kev_uplift = 10 if finding.get("cisa_kev") else 0
            exposure = str(finding.get("network_exposure", "unknown"))
            verified_exposure = finding.get("network_exposure_verified") is True
            exposure_uplift = EXPOSURE_UPLIFT.get(exposure, 0) if verified_exposure else 0
            reasons = [f"CVSS base score {score:.1f} contributes {base} points."]
            reasons.append("CISA KEV membership adds 10 urgency points because the CVE is listed as known exploited." if kev_uplift else "No CISA KEV uplift: this advisory is not marked as known exploited.")
            reasons.append(f"Verified network exposure '{exposure}' contributes {exposure_uplift} points." if verified_exposure else "Network exposure is unknown or unverified; no exposure uplift is applied.")
        total = min(100, base + kev_uplift + exposure_uplift)
        confidence, confidence_reasons = _confidence(finding)
        finding["risk_components"] = {"cvss_points": base, "kev_uplift": kev_uplift, "exposure_uplift": exposure_uplift, "uncapped_total": base + kev_uplift + exposure_uplift, "cap": 100}
        finding["risk_explanation"] = reasons + confidence_reasons
        finding["risk_score"] = total
        finding["risk_rating"] = _rating(total)
        finding["evidence_confidence"] = confidence
        finding["risk_basis"] = "CVSS × 10 + KEV urgency uplift + verified exposure uplift; capped at 100"
        return finding

    score = SEVERITY_POINTS.get(str(finding.get("severity", "info")).lower(), 10)
    confidence, confidence_reasons = _confidence(finding)
    finding["risk_components"] = {"service_heuristic_points": score, "kev_uplift": 0, "exposure_uplift": 0, "uncapped_total": score, "cap": 100}
    finding["risk_score"] = score
    finding["risk_rating"] = _rating(score)
    finding["evidence_confidence"] = confidence
    finding["risk_explanation"] = [
        f"Service observation heuristic for severity '{finding.get('severity', 'info')}' contributes {score} points.",
        "This is a reachability triage indicator, not a CVE or exploitability claim.",
        *confidence_reasons,
    ]
    finding["risk_basis"] = "CamGuard service-reachability heuristic; no CVE uplift"
    return finding


def apply_risk_scores(result: dict[str, Any]) -> dict[str, Any]:
    """Score findings and aggregate each asset using its highest-scoring finding."""
    by_ip: dict[str, list[dict[str, Any]]] = {}
    for finding in result.get("findings", []):
        _score_finding(finding)
        by_ip.setdefault(str(finding.get("asset_ip", "unknown")), []).append(finding)

    for asset in result.get("assets", []):
        findings = by_ip.get(str(asset.get("ip", "")), [])
        if not findings:
            asset["risk_score"] = 0
            asset["risk_rating"] = "informational"
            asset["risk_confidence"] = "unknown"
            asset["risk_explanation"] = ["No findings were associated with this asset; zero means no scored findings, not proof of safety."]
            asset["risk_components"] = {"finding_count": 0, "aggregation": "highest finding"}
            continue
        highest = max(findings, key=lambda item: (item["risk_score"], CONFIDENCE_RANK.get(item["evidence_confidence"], 0)))
        asset["risk_score"] = highest["risk_score"]
        asset["risk_rating"] = highest["risk_rating"]
        asset["risk_confidence"] = highest["evidence_confidence"]
        asset["risk_components"] = dict(highest["risk_components"])
        asset["risk_explanation"] = list(highest["risk_explanation"])
        asset["risk_basis"] = highest["risk_basis"]
        asset["risk_driver"] = highest.get("cve") or highest.get("title") or "Highest-scoring finding"

    result["risk_methodology"] = {
        "version": "1.0",
        "range": "0-100",
        "aggregation": "Highest-scoring finding per asset; findings are not added together.",
        "formula": "For exact verified CVE matches: min(100, round(CVSS × 10) + KEV uplift + verified exposure uplift).",
        "kev_uplift": "10 points when the analyst-approved advisory is marked as present in CISA KEV.",
        "exposure_uplifts": {"internet_exposed": 15, "internal_segment": 5, "isolated": 0, "unknown": 0},
        "exposure_policy": "Exposure uplift applies only when network_exposure_verified is true; unknown or unverified exposure adds zero.",
        "service_findings": "Use conservative severity heuristics; never receive CVE, KEV or exposure uplifts.",
        "confidence": "Reported separately from score. Exact verified identity/firmware plus review provenance is high; exact match without complete provenance is medium; network observations are low.",
        "ratings": {"critical": "90-100", "high": "70-89", "medium": "40-69", "low": "1-39", "informational": "0"},
        "limitations": [
            "A score is a prioritization aid, not probability of compromise.",
            "CISA KEV status does not independently prove that a specific device is affected.",
            "Internet exposure must be explicitly verified from client network evidence; CamGuard does not infer it from a private-scope scan.",
            "Business criticality, compensating controls, exploitability in the client environment and active compromise are not scored.",
        ],
    }
    return result
