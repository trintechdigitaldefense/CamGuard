"""Maintained NVD + CISA KEV ingestion with analyst-gated publication.

Downloads create a review inbox only. They never create deployable CVE matches.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlsplit
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
PAGE_SIZE = 2000
MAX_WINDOW_DAYS = 120


class AdvisoryIngestionError(RuntimeError):
    """Raised when a source cannot be safely retrieved or validated."""


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _get_json(url: str, headers: dict[str, str], timeout: float = 30.0,
              opener: Callable[..., Any] = urllib.request.urlopen) -> dict[str, Any]:
    request = urllib.request.Request(url, headers=headers, method="GET")
    last_error = None
    for attempt in range(4):
        try:
            with opener(request, timeout=timeout) as response:
                if getattr(response, "status", 200) != 200:
                    raise AdvisoryIngestionError(f"Unexpected HTTP status: {response.status}")
                raw = response.read(50 * 1024 * 1024 + 1)
                if len(raw) > 50 * 1024 * 1024:
                    raise AdvisoryIngestionError("Source response exceeded the 50 MiB safety limit.")
                payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise AdvisoryIngestionError("Source returned a non-object JSON document.")
            return payload
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in (429, 500, 502, 503, 504) or attempt == 3:
                raise AdvisoryIngestionError(f"Source HTTP error {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt == 3:
                raise AdvisoryIngestionError(f"Source retrieval/JSON validation failed: {type(exc).__name__}") from exc
        time.sleep(min(2 ** attempt, 8))
    raise AdvisoryIngestionError("Source retrieval failed.") from last_error


def _cvss(cve: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData") or {}
        score = data.get("baseScore")
        if isinstance(score, (int, float)) and 0 <= score <= 10:
            return float(score), str(data.get("version") or key), str(data.get("vectorString") or "")
    return None, None, None


def _configurations(cve: dict[str, Any]) -> list[dict[str, Any]]:
    """Preserve CPE criteria and version bounds for human review; do not interpret ranges."""
    found = []
    def walk(node: dict[str, Any]) -> None:
        for match in node.get("cpeMatch", []) or []:
            criteria = match.get("criteria")
            if isinstance(criteria, str) and criteria.startswith("cpe:2.3:"):
                found.append({
                    "criteria": criteria,
                    "vulnerable": bool(match.get("vulnerable", False)),
                    "versionStartIncluding": match.get("versionStartIncluding"),
                    "versionStartExcluding": match.get("versionStartExcluding"),
                    "versionEndIncluding": match.get("versionEndIncluding"),
                    "versionEndExcluding": match.get("versionEndExcluding"),
                    "matchCriteriaId": match.get("matchCriteriaId"),
                })
        for child in node.get("children", []) or []:
            walk(child)
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            walk(node)
    return found


def ingest_sources(output_dir: str, days: int = 7, api_key: str | None = None,
                   now: datetime | None = None,
                   opener: Callable[..., Any] = urllib.request.urlopen) -> dict[str, str]:
    if not 1 <= days <= MAX_WINDOW_DAYS:
        raise ValueError(f"days must be between 1 and {MAX_WINDOW_DAYS}.")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware.")
    end = now.astimezone(timezone.utc)
    start = end - timedelta(days=days)
    retrieved = _utc(end)
    nvd_headers = {"User-Agent": "TrinTech-CamGuard-AdvisoryIngestion/0.4", "Accept": "application/json"}
    kev_headers = {"User-Agent": "TrinTech-CamGuard-AdvisoryIngestion/0.4", "Accept": "application/json"}
    if api_key:
        nvd_headers["apiKey"] = api_key

    nvd_by_id: dict[str, dict[str, Any]] = {}
    start_index = 0
    while True:
        params = urllib.parse.urlencode({
            "lastModStartDate": _utc(start), "lastModEndDate": _utc(end),
            "resultsPerPage": PAGE_SIZE, "startIndex": start_index,
        })
        page = _get_json(f"{NVD_URL}?{params}", nvd_headers, opener=opener)
        vulnerabilities = page.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise AdvisoryIngestionError("NVD response is missing vulnerabilities array.")
        for wrapper in vulnerabilities:
            cve = wrapper.get("cve", {}) if isinstance(wrapper, dict) else {}
            cve_id = str(cve.get("id", "")).upper()
            if not CVE_RE.fullmatch(cve_id):
                continue
            score, cvss_version, vector = _cvss(cve)
            descriptions = cve.get("descriptions") or []
            description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
            nvd_by_id[cve_id] = {
                "cve": cve_id, "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "vuln_status": cve.get("vulnStatus"),
                "description": description[:4000],
                "cvss_base_score": score, "cvss_version": cvss_version,
                "cvss_vector": vector, "cpe_applicability": _configurations(cve),
                "references": [r.get("url") for r in (cve.get("references") or []) if isinstance(r, dict) and r.get("url")][:50],
                "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        total = int(page.get("totalResults", len(nvd_by_id)))
        start_index += len(vulnerabilities)
        if not vulnerabilities or start_index >= total:
            break
        # NVD documents tighter request rates without an API key; conservative pacing.
        time.sleep(0.7 if api_key else 6.1)

    nvd_items = list(nvd_by_id.values())
    kev = _get_json(KEV_URL, kev_headers, opener=opener)
    vulnerabilities = kev.get("vulnerabilities")
    if not isinstance(vulnerabilities, list) or not isinstance(kev.get("count"), int) or kev.get("count") != len(vulnerabilities):
        raise AdvisoryIngestionError("CISA KEV response failed required schema checks.")
    kev_by_id = {}
    for row in vulnerabilities:
        if not isinstance(row, dict) or not CVE_RE.fullmatch(str(row.get("cveID", ""))) or not all(row.get(k) for k in ("vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription", "requiredAction", "dueDate")):
            raise AdvisoryIngestionError("CISA KEV contains an invalid CVE identifier.")
        kev_id = row["cveID"].upper()
        if kev_id in kev_by_id:
            raise AdvisoryIngestionError(f"CISA KEV contains duplicate CVE ID: {kev_id}")
        kev_by_id[kev_id] = {
            "vendor_project": row.get("vendorProject"),
            "product": row.get("product"),
            "vulnerability_name": row.get("vulnerabilityName"),
            "date_added": row.get("dateAdded"),
            "short_description": row.get("shortDescription"),
            "required_action": row.get("requiredAction"),
            "due_date": row.get("dueDate"),
            "known_ransomware_campaign_use": row.get("knownRansomwareCampaignUse"),
            "cwes": row.get("cwes", []),
            "notes": row.get("notes"),
        }

    candidates = []
    for item in nvd_items:
        kev_data = kev_by_id.get(item["cve"])
        item["cisa_kev"] = kev_data is not None
        item["kev_details"] = kev_data
        item["review_status"] = "pending"
        item["approval_note"] = (
            "NVD applicability is evidence for analyst review, not a confirmed device/version match. "
            "Enter exact CPE and explicit affected versions only after checking the vendor advisory."
        )
        candidates.append(item)

    # KEV entries are also retained even if absent from the recent NVD modification window.
    nvd_ids = {item["cve"] for item in candidates}
    kev_only = [{"cve": cve, "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                 "cisa_kev": True, "kev_details": data,
                 "nvd_record_in_window": False, "review_status": "pending",
                 "approval_note": "KEV presence alone does not establish affected product/version."}
                for cve, data in kev_by_id.items() if cve not in nvd_ids]

    manifest = {
        "generated_at": retrieved,
        "sources": [
            {"name": "NVD CVE API 2.0", "url": NVD_URL,
             "modified_window_start": _utc(start), "modified_window_end": _utc(end),
             "records": len(nvd_items)},
            {"name": "CISA Known Exploited Vulnerabilities", "url": KEV_URL,
             "catalog_version": kev.get("catalogVersion"), "date_released": kev.get("dateReleased"),
             "declared_count": kev.get("count"), "validated_count": len(kev_by_id)},
        ],
        "policy": "Ingestion creates pending analyst candidates only; it never publishes matching advisories.",
    }
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    files = {
        "pending": destination / "pending-review.json",
        "kev": destination / "kev-catalog.json",
        "manifest": destination / "manifest.json",
    }
    _atomic_json(files["pending"], {"generated_at": retrieved, "candidates": candidates, "kev_only": kev_only})
    _atomic_json(files["kev"], kev)
    _atomic_json(files["manifest"], manifest)
    return {key: str(path) for key, path in files.items()}


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def export_approved(approvals_path: str, output_path: str) -> int:
    payload = json.loads(Path(approvals_path).read_text(encoding="utf-8"))
    rows = payload.get("approvals") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise ValueError("Approval file must contain an approvals array.")
    approved = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Every approval must be an object.")
        if row.get("decision") != "approved":
            continue
        cve = str(row.get("cve", "")).upper()
        cpe = row.get("cpe")
        versions = row.get("affected_versions")
        reviewer = str(row.get("reviewed_by", "")).strip()
        reviewed_at = str(row.get("reviewed_at", "")).strip()
        score = row.get("cvss_base_score")
        if not CVE_RE.fullmatch(cve) or cve in seen:
            raise ValueError(f"Invalid or duplicate approved CVE: {cve}")
        if not isinstance(cpe, str) or not cpe.startswith("cpe:2.3:"):
            raise ValueError(f"{cve}: analyst must supply an exact CPE 2.3 identifier.")
        if not isinstance(versions, list) or not versions or any(not isinstance(v, str) or not v.strip() for v in versions):
            raise ValueError(f"{cve}: explicit affected_versions list is required.")
        if not reviewer or not reviewed_at:
            raise ValueError(f"{cve}: reviewed_by and reviewed_at are required.")
        try:
            parsed_reviewed_at = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
            if parsed_reviewed_at.tzinfo is None:
                raise ValueError("timezone is required")
        except ValueError as exc:
            raise ValueError(f"{cve}: reviewed_at must be ISO-8601.") from exc
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10:
            raise ValueError(f"{cve}: valid CVSS base score is required.")
        source = str(row.get("source", "")).strip()
        summary = str(row.get("summary", "")).strip()
        if urlsplit(source).scheme != "https" or not urlsplit(source).netloc or not summary:
            raise ValueError(f"{cve}: HTTPS source and summary are required.")
        if not isinstance(row.get("kev", False), bool):
            raise ValueError(f"{cve}: kev must be a JSON boolean.")
        approved.append({
            "cve": cve, "cpe": cpe, "affected_versions": sorted(set(versions)),
            "cvss_base_score": float(score), "source": source, "summary": summary,
            "kev": bool(row.get("kev", False)), "reviewed_by": reviewer,
            "reviewed_at": reviewed_at,
        })
        seen.add(cve)
    _atomic_json(Path(output_path), {"advisories": approved, "generated_at": _utc(datetime.now(timezone.utc)),
                                     "publication_policy": "Only analyst-approved exact CPE and version entries."})
    return len(approved)
