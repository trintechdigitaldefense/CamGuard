"""Local analyst review queue and tamper-evident decision log.

Feed data is treated as untrusted input. Approval requires a matching pending
record, an exact CPE compatible with the source applicability, explicit
firmware versions, vendor evidence, reviewer identity, and rationale.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .advisory_ingest import CVE_RE, _valid_cpe23

CPE_PREFIX = "cpe:2.3:"
ALLOWED_DECISIONS = {"approved", "rejected", "pending"}


class ReviewError(ValueError):
    """Raised when a review decision or review data is unsafe."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def load_inbox(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReviewError(f"Cannot read pending inbox: {exc}") from exc
    if not isinstance(payload, dict):
        raise ReviewError("Pending inbox must be a JSON object.")
    candidates = payload.get("candidates")
    kev_only = payload.get("kev_only")
    if not isinstance(candidates, list) or not isinstance(kev_only, list):
        raise ReviewError("Pending inbox must contain candidates and kev_only arrays.")
    return payload


def _candidate_map(inbox: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for group in ("candidates", "kev_only"):
        for item in inbox[group]:
            if not isinstance(item, dict):
                raise ReviewError(f"Invalid record in {group}.")
            cve = str(item.get("cve", "")).upper()
            if not CVE_RE.fullmatch(cve) or cve in result:
                raise ReviewError(f"Invalid or duplicate CVE in inbox: {cve}")
            result[cve] = item
    return result


def list_pending(inbox_path: str | Path, query: str = "", kev_only: bool = False,
                 limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    """Return a bounded page of pending items; query matches CVE/vendor/product/description."""
    if not 1 <= limit <= 500 or offset < 0:
        raise ReviewError("limit must be 1–500 and offset cannot be negative.")
    inbox = load_inbox(inbox_path)
    groups = ("kev_only",) if kev_only else ("candidates", "kev_only")
    needle = query.casefold().strip()
    rows = []
    for group in groups:
        for item in inbox[group]:
            if item.get("review_status", "pending") != "pending":
                continue
            kev = item.get("kev_details") or {}
            haystack = " ".join(str(value) for value in (
                item.get("cve", ""), item.get("description", ""),
                kev.get("vendor_project", ""), kev.get("product", ""),
                kev.get("short_description", ""),
            )).casefold()
            if needle and needle not in haystack:
                continue
            rows.append({
                "cve": item.get("cve"),
                "source_group": group,
                "kev": bool(item.get("cisa_kev")),
                "cvss_base_score": item.get("cvss_base_score"),
                "description": item.get("description") or kev.get("short_description", ""),
                "vendor": kev.get("vendor_project"),
                "product": kev.get("product"),
                "published": item.get("published"),
                "last_modified": item.get("last_modified"),
            })
    rows.sort(key=lambda row: (not row["kev"], row["cve"]))
    return rows[offset:offset + limit]


def _cpe_matches_source(approved_cpe: str, candidate: dict[str, Any]) -> bool:
    """Require the analyst CPE to satisfy one NVD criterion, wildcarding source fields only."""
    if not _valid_cpe23(approved_cpe):
        return False
    approved = approved_cpe.split(":")[2:]
    # An approved CPE must identify a concrete version, not a wildcard or NA value.
    if approved[3] in {"*", "-"}:
        return False
    criteria = candidate.get("cpe_applicability") or []
    if not criteria:
        # KEV-only items have no NVD CPE; independent vendor evidence is mandatory.
        return candidate.get("nvd_record_in_window") is False
    for entry in criteria:
        source_cpe = entry.get("criteria", "")
        if not isinstance(source_cpe, str) or not source_cpe.startswith(CPE_PREFIX):
            continue
        source = source_cpe.split(":")[2:]
        if len(source) != 11:
            continue
        if all(expected in {"*", "-"} or expected == actual
               for index, (expected, actual) in enumerate(zip(source, approved))
               if index != 3):
            return True
    return False


def _read_audit(path: Path) -> tuple[list[dict[str, Any]], str]:
    if not path.exists():
        return [], "0" * 64
    entries: list[dict[str, Any]] = []
    previous = "0" * 64
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, 1):
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise ValueError("entry is not an object")
            supplied = entry.pop("record_hash", None)
            if entry.get("previous_hash") != previous:
                raise ValueError("previous hash mismatch")
            calculated = hashlib.sha256(_canonical(entry)).hexdigest()
            if supplied != calculated:
                raise ValueError("record hash mismatch")
            entry["record_hash"] = supplied
            entries.append(entry)
            previous = supplied
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise ReviewError(f"Audit log integrity check failed: {exc}") from exc
    return entries, previous


def record_decision(
    inbox_path: str | Path,
    approvals_path: str | Path,
    audit_path: str | Path,
    cve: str,
    decision: str,
    reviewed_by: str,
    rationale: str,
    evidence_url: str,
    cpe: str = "",
    affected_versions: list[str] | None = None,
) -> dict[str, Any]:
    """Record a review decision; append audit first and atomically update approvals."""
    cve = str(cve).upper().strip()
    decision = decision.lower().strip()
    reviewer = reviewed_by.strip()
    rationale = rationale.strip()
    evidence_url = evidence_url.strip()
    if not CVE_RE.fullmatch(cve):
        raise ReviewError("A valid CVE identifier is required.")
    if decision not in ALLOWED_DECISIONS:
        raise ReviewError("decision must be approved, rejected, or pending.")
    if not reviewer or len(reviewer) > 200:
        raise ReviewError("A reviewer identifier (1–200 characters) is required.")
    if not rationale or len(rationale) > 4000:
        raise ReviewError("A decision rationale (1–4000 characters) is required.")
    parsed = urlsplit(evidence_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ReviewError("Vendor evidence must be an HTTPS URL.")

    inbox = load_inbox(inbox_path)
    candidates = _candidate_map(inbox)
    candidate = candidates.get(cve)
    if candidate is None:
        raise ReviewError(f"{cve} is not present in the current pending inbox.")
    if candidate.get("review_status", "pending") != "pending":
        raise ReviewError(f"{cve} is not pending in the source inbox.")

    versions = affected_versions or []
    if decision == "approved":
        if not _valid_cpe23(cpe):
            raise ReviewError("Approval requires a structurally valid exact CPE 2.3.")
        if not _cpe_matches_source(cpe, candidate):
            raise ReviewError("The approval CPE does not match the NVD applicability evidence.")
        if not isinstance(versions, list) or not versions:
            raise ReviewError("Approval requires explicit affected firmware versions.")
        if any(not isinstance(v, str) or not v.strip() or v.strip() in {"*", "-"} for v in versions):
            raise ReviewError("Affected versions must be explicit non-wildcard strings.")
        versions = sorted(set(v.strip() for v in versions))
        score = candidate.get("cvss_base_score")
        if score is None:
            raise ReviewError("No NVD CVSS score is available; do not invent one for this workflow.")
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10:
            raise ReviewError("The source CVSS score is invalid.")
    else:
        cpe, versions, score = "", [], candidate.get("cvss_base_score")

    reviewed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    approval = {
        "cve": cve, "decision": decision, "cpe": cpe,
        "affected_versions": versions, "cvss_base_score": score if score is not None else 0.0,
        "source": evidence_url, "summary": str(candidate.get("description") or
            (candidate.get("kev_details") or {}).get("short_description") or "Analyst-reviewed advisory"),
        "kev": bool(candidate.get("cisa_kev")), "reviewed_by": reviewer,
        "reviewed_at": reviewed_at, "rationale": rationale,
    }

    audit_file = Path(audit_path)
    audit_file.parent.mkdir(parents=True, exist_ok=True)
    entries, previous_hash = _read_audit(audit_file)
    event = {
        "schema_version": 1, "cve": cve, "decision": decision,
        "reviewed_by": reviewer, "reviewed_at": reviewed_at,
        "rationale": rationale, "evidence_url": evidence_url,
        "source_group": "candidates" if candidate.get("nvd_record_in_window") else "kev_only",
        "previous_hash": previous_hash,
    }
    event["record_hash"] = hashlib.sha256(_canonical(event)).hexdigest()
    # Append and fsync before changing the materialized approvals file.
    with audit_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())

    approvals_file = Path(approvals_path)
    if approvals_file.exists():
        try:
            payload = json.loads(approvals_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ReviewError("Existing approvals file is invalid JSON; refusing to overwrite it.") from exc
        rows = payload.get("approvals") if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            raise ReviewError("Existing approvals file must contain an approvals array.")
    else:
        rows = []
    rows = [row for row in rows if not (isinstance(row, dict) and str(row.get("cve", "")).upper() == cve)]
    rows.append(approval)
    _atomic_json(approvals_file, {"approvals": sorted(rows, key=lambda row: row["cve"])})
    return event


def verify_audit(path: str | Path) -> dict[str, Any]:
    entries, last_hash = _read_audit(Path(path))
    return {"valid": True, "entries": len(entries), "last_hash": last_hash}
