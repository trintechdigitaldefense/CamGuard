"""Technician-assisted CCTV security inspection data model.

This module records operator-confirmed observations only. It never connects to
camera/NVR devices, tests credentials, or stores raw evidence attachments.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any

SCHEMA_VERSION = "1.0"
STATUSES = {"pass", "fail", "not_verified", "not_applicable", "needs_attention"}
SENSITIVE_TEXT = re.compile(r"(?i)(password|passwd|bearer)\s*[:=]\s*\S+|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")

CHECKLISTS: dict[str, dict[str, Any]] = {
    "account_permissions": {"title": "Account permissions", "checks": [
        ("unique_accounts", "Each person has an individually assigned account."),
        ("least_privilege", "User permissions follow least-privilege principles."),
        ("admin_restricted", "Administrator privileges are limited to approved personnel."),
        ("former_users_removed", "Former staff and third-party accounts have been removed or disabled."),
        ("mfa", "Multi-factor authentication is enabled where supported for remote or privileged access."),
    ]},
    "default_credential_policy": {"title": "Default-credential policy", "checks": [
        ("defaults_changed", "Vendor-default credentials were changed during commissioning."),
        ("unique_device_secrets", "Devices do not share predictable or reused administrative credentials."),
        ("password_policy", "A documented password policy is applied to supported accounts."),
        ("lockout_controls", "Rate limiting or account lockout protections are configured where supported."),
        ("secret_handling", "Credentials are stored and shared through an approved secure process."),
    ]},
    "nvr_configuration": {"title": "NVR configuration", "checks": [
        ("firmware_supported", "NVR firmware is supported and its update status is documented."),
        ("services_minimized", "Unneeded services, interfaces and protocols are disabled."),
        ("management_restricted", "Management interfaces are restricted to approved networks."),
        ("time_sync", "Time synchronization and timezone settings are accurate."),
        ("config_backup", "A protected, current configuration backup is maintained."),
    ]},
    "remote_access": {"title": "Remote access", "checks": [
        ("approved_method", "Remote access uses an organization-approved method."),
        ("no_unapproved_forwarding", "Unnecessary direct internet exposure and port forwarding are absent."),
        ("vpn_or_zero_trust", "Remote administration is protected by an approved VPN or equivalent access control."),
        ("third_party_access", "Vendor and third-party access is approved, time-bounded and reviewed."),
        ("remote_logging", "Remote access activity is logged and periodically reviewed."),
    ]},
    "physical_security": {"title": "Physical security", "checks": [
        ("camera_tamper", "Cameras are mounted to reduce tampering, obstruction and unauthorized removal."),
        ("nvr_room", "NVRs and network equipment are held in access-controlled locations."),
        ("cable_protection", "Exposed cabling and network outlets are physically protected."),
        ("power_protection", "Critical equipment has appropriate power protection."),
        ("physical_access_log", "Physical access to sensitive equipment is controlled or recorded."),
    ]},
    "recording_retention": {"title": "Recording retention", "checks": [
        ("retention_defined", "A documented retention period is approved and configured."),
        ("storage_health", "Recording storage capacity and disk health are monitored."),
        ("recording_continuity", "Recording continuity and time accuracy are periodically verified."),
        ("backup_recovery", "Required recordings and configurations have a tested recovery process."),
        ("privacy_controls", "Retention, access and deletion practices meet applicable privacy requirements."),
    ]},
}


def checklist_template() -> list[dict[str, Any]]:
    return [{"category_id": category, "title": data["title"],
             "checks": [{"check_id": check_id, "question": question}
                        for check_id, question in data["checks"]]}
            for category, data in CHECKLISTS.items()]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_text(value: Any, field: str, *, required: bool = False, limit: int = 2000) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text.")
    value = value.strip()
    if required and not value:
        raise ValueError(f"{field} is required.")
    if len(value) > limit:
        raise ValueError(f"{field} exceeds {limit} characters.")
    if SENSITIVE_TEXT.search(value):
        raise ValueError(f"{field} appears to contain a secret; store evidence references, never credentials.")
    return value


def create_inspection(assessment_id: str, asset_id: str, device_ip: str,
                      inspector: str, *, inspected_at: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "inspection_id": f"inspection-{_utc_now()}",
        "assessment_id": _safe_text(assessment_id, "assessment_id", required=True, limit=128),
        "asset_id": _safe_text(asset_id, "asset_id", required=True, limit=128),
        "device_ip": _safe_text(device_ip, "device_ip", required=True, limit=64),
        "inspector": _safe_text(inspector, "inspector", required=True, limit=128),
        "inspected_at": _safe_text(inspected_at or _utc_now(), "inspected_at", required=True, limit=64),
        "checklist_version": SCHEMA_VERSION, "responses": [],
        "limitations": [
            "Inspection results are technician-supplied and are not independently verified by CamGuard.",
            "CamGuard does not log in to devices, test passwords, or retrieve configuration or video.",
            "Evidence attachments are not embedded; evidence_refs are operator-managed references only.",
        ],
    }


def record_check(inspection: dict[str, Any], category_id: str, check_id: str,
                 status: str, *, notes: str = "", evidence_refs: list[str] | None = None,
                 reviewed_at: str | None = None) -> dict[str, Any]:
    validate_inspection(inspection, require_complete=False)
    if category_id not in CHECKLISTS:
        raise ValueError(f"Unknown inspection category: {category_id}")
    known = dict(CHECKLISTS[category_id]["checks"])
    if check_id not in known:
        raise ValueError(f"Unknown check_id for {category_id}: {check_id}")
    if status not in STATUSES:
        raise ValueError(f"status must be one of: {', '.join(sorted(STATUSES))}")
    clean_notes = _safe_text(notes, "notes")
    refs = evidence_refs or []
    if not isinstance(refs, list) or len(refs) > 20:
        raise ValueError("evidence_refs must be a list containing at most 20 references.")
    clean_refs = [_safe_text(ref, "evidence reference", required=True, limit=512) for ref in refs]
    if status in {"pass", "fail"} and not clean_refs:
        raise ValueError("Pass and Fail require at least one evidence reference.")
    if status in {"not_applicable", "needs_attention"} and not clean_notes:
        raise ValueError(f"{status} requires explanatory notes.")
    response = {
        "category_id": category_id, "category": CHECKLISTS[category_id]["title"],
        "check_id": check_id, "question": known[check_id], "status": status,
        "notes": clean_notes, "evidence_refs": clean_refs,
        "reviewed_at": _safe_text(reviewed_at or _utc_now(), "reviewed_at", required=True, limit=64),
    }
    inspection["responses"] = [r for r in inspection["responses"]
                               if not (r["category_id"] == category_id and r["check_id"] == check_id)]
    inspection["responses"].append(response)
    inspection["responses"].sort(key=lambda r: (r["category_id"], r["check_id"]))
    validate_inspection(inspection, require_complete=False)
    return response


def validate_inspection(inspection: dict[str, Any], *, require_complete: bool = False) -> None:
    if not isinstance(inspection, dict) or inspection.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported or missing inspection schema_version.")
    for field in ("inspection_id", "assessment_id", "asset_id", "device_ip", "inspector", "inspected_at"):
        _safe_text(inspection.get(field), field, required=True, limit=512)
    responses = inspection.get("responses")
    if not isinstance(responses, list):
        raise ValueError("responses must be a list.")
    seen: set[tuple[str, str]] = set()
    for response in responses:
        if not isinstance(response, dict):
            raise ValueError("Each response must be an object.")
        key = (response.get("category_id"), response.get("check_id"))
        if key in seen:
            raise ValueError("Duplicate checklist response.")
        seen.add(key)
        if key[0] not in CHECKLISTS or key[1] not in dict(CHECKLISTS[key[0]]["checks"]):
            raise ValueError("Response references an unknown checklist item.")
        if response.get("status") not in STATUSES:
            raise ValueError("Response contains an invalid status.")
        _safe_text(response.get("notes", ""), "notes")
        refs = response.get("evidence_refs", [])
        if not isinstance(refs, list):
            raise ValueError("evidence_refs must be a list.")
        for ref in refs:
            _safe_text(ref, "evidence reference", required=True, limit=512)
        if response["status"] in {"pass", "fail"} and not refs:
            raise ValueError("Pass and Fail responses require evidence references.")
        if response["status"] in {"not_applicable", "needs_attention"} and not response.get("notes", "").strip():
            raise ValueError(f"{response['status']} responses require explanatory notes.")
    if require_complete and len(seen) != sum(len(v["checks"]) for v in CHECKLISTS.values()):
        raise ValueError("Inspection is incomplete; every checklist item needs a response.")


def inspection_summary(inspection: dict[str, Any]) -> dict[str, int]:
    validate_inspection(inspection, require_complete=False)
    counts = {status: 0 for status in sorted(STATUSES)}
    for response in inspection["responses"]:
        counts[response["status"]] += 1
    counts["total_checks"] = sum(len(v["checks"]) for v in CHECKLISTS.values())
    counts["completed_checks"] = len(inspection["responses"])
    counts["unanswered_checks"] = counts["total_checks"] - counts["completed_checks"]
    return counts


def write_inspection_json(inspection: dict[str, Any], output_path: str | Path) -> Path:
    validate_inspection(inspection, require_complete=False)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(inspection, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
