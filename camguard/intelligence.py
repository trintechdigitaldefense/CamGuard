"""Enrich scanned assets using verified inventory and analyst-approved advisories.

No device login, fingerprint probing, or external API calls are performed here.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
EXPOSURE_VALUES = {"internet_exposed", "internal_segment", "isolated", "unknown"}


def _clean(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes"}


def load_inventory(path: str) -> dict[str, dict[str, Any]]:
    """Load JSON list or CSV keyed by IP; verification is an explicit operator attestation."""
    file = Path(path)
    if file.suffix.lower() == ".csv":
        with file.open(newline="", encoding="utf-8-sig") as handle:
            rows = list(csv.DictReader(handle))
    else:
        payload = json.loads(file.read_text(encoding="utf-8"))
        rows = payload.get("devices", payload) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ValueError("Inventory must be a JSON array/object with devices or a CSV file.")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not row.get("ip"):
            raise ValueError("Every inventory record must be an object with an ip field.")
        ip = str(row["ip"]).strip()
        if ip in result:
            raise ValueError(f"Duplicate inventory IP: {ip}")
        exposure = _clean(row.get("network_exposure")).lower() or "unknown"
        if exposure not in EXPOSURE_VALUES:
            raise ValueError(f"Invalid network_exposure for {ip}; choose one of {sorted(EXPOSURE_VALUES)}.")
        result[ip] = {
            "vendor": _clean(row.get("vendor")),
            "model": _clean(row.get("model")),
            "firmware": _clean(row.get("firmware")),
            "cpe": _clean(row.get("cpe")),
            "source": _clean(row.get("source")) or "operator-supplied inventory",
            "verified": _as_bool(row.get("verified", False)),
            "network_exposure": exposure,
            "network_exposure_verified": _as_bool(row.get("network_exposure_verified", False)),
            "network_exposure_source": _clean(row.get("network_exposure_source")),
        }
    return result


def load_advisories(path: str) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = payload.get("advisories", payload) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise ValueError("Advisories must be a JSON array/object with advisories.")
    clean = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Every advisory must be an object.")
        cve = str(row.get("cve", "")).upper()
        cpe = _clean(row.get("cpe"))
        versions = row.get("affected_versions", [])
        if not CVE_ID.fullmatch(cve) or not cpe or not isinstance(versions, list):
            raise ValueError("Each advisory requires a CVE ID, exact CPE, and affected_versions array.")
        score = float(row.get("cvss_base_score", 0))
        if not 0 <= score <= 10:
            raise ValueError(f"Invalid CVSS score for {cve}.")
        clean.append({
            "cve": cve, "cpe": cpe, "affected_versions": [str(v) for v in versions],
            "cvss_base_score": score, "source": _clean(row.get("source")) or "unspecified advisory source",
            "summary": _clean(row.get("summary")) or "No summary supplied.",
            "kev": _as_bool(row.get("kev", False)),
            "reviewed_by": _clean(row.get("reviewed_by")),
            "reviewed_at": _clean(row.get("reviewed_at")),
            "rationale": _clean(row.get("rationale")),
        })
    return clean


def enrich_assets(result: dict[str, Any], inventory: dict[str, dict[str, Any]],
                  advisories: list[dict[str, Any]]) -> dict[str, Any]:
    """Attach identity and exact-match CVEs; never infer device or exposure context."""
    enriched = []
    cve_findings = []
    for asset in result.get("assets", []):
        record = inventory.get(asset["ip"], {})
        identity_source = record.get("source", "")
        device = {
            **asset,
            "identity": record,
            "identity_status": (
                "operator-verified" if record.get("verified") else
                "operator-supplied-unverified" if record else "unknown"
            ),
            "network_exposure": record.get("network_exposure", "unknown"),
            "network_exposure_verified": bool(record.get("network_exposure_verified")),
            "network_exposure_source": record.get("network_exposure_source", ""),
        }
        matches = []
        if record.get("verified") and record.get("cpe") and record.get("firmware"):
            for advisory in advisories:
                if advisory["cpe"] == record["cpe"] and record["firmware"] in advisory["affected_versions"]:
                    matches.append(advisory)
                    cve_findings.append({
                        "asset_ip": asset["ip"], "cve": advisory["cve"],
                        "cvss_base_score": advisory["cvss_base_score"],
                        "source": advisory["source"], "summary": advisory["summary"],
                        "evidence": f"Verified inventory exact-match: CPE {record['cpe']}, firmware {record['firmware']}.",
                        "severity": _cvss_severity(advisory["cvss_base_score"]),
                        "cisa_kev": bool(advisory.get("kev", False)),
                        "exact_verified_match": True,
                        "applicability": "exact CPE and exact firmware version",
                        "identity_confidence": "high" if identity_source and identity_source != "operator-supplied inventory" else "medium",
                        "identity_evidence_source": identity_source,
                        "network_exposure": record.get("network_exposure", "unknown"),
                        "network_exposure_verified": bool(record.get("network_exposure_verified")),
                        "network_exposure_source": record.get("network_exposure_source", ""),
                        "reviewed_by": advisory.get("reviewed_by"),
                        "reviewed_at": advisory.get("reviewed_at"),
                        "review_rationale": advisory.get("rationale"),
                    })
        device["matched_cves"] = [item["cve"] for item in matches]
        enriched.append(device)
    result["assets"] = enriched
    result.setdefault("findings", []).extend(cve_findings)
    result["intelligence"] = {
        "inventory_records_loaded": len(inventory),
        "advisories_loaded": len(advisories),
        "matching_policy": "Exact CPE and exact firmware version only; requires verified inventory.",
        "identity_note": "Manufacturer/model/firmware are not inferred from open ports. Supply verified records.",
        "exposure_note": "Network exposure is operator-supplied context and affects scoring only when explicitly marked verified with a source.",
    }
    return result


def _cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"
