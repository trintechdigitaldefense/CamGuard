import json
import tempfile
import unittest
from pathlib import Path

from camguard.advisory_review import (
    ReviewError, export_reviewed_approvals, list_pending, record_decision,
    verify_audit,
)


class AdvisoryReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inbox = self.root / "pending-review.json"
        self.approvals = self.root / "approvals.json"
        self.audit = self.root / "review-audit.jsonl"
        self.output = self.root / "approved.json"
        candidate = {
            "cve": "CVE-2026-1234", "review_status": "pending",
            "nvd_record_in_window": True, "cisa_kev": True,
            "cvss_base_score": 8.1, "description": "Test camera vulnerability",
            "published": "2026-01-01T00:00:00Z",
            "cpe_applicability": [{
                "criteria": "cpe:2.3:o:vendor:camera:*:*:*:*:*:*:*:*",
                "vulnerable": True,
            }],
        }
        self.inbox.write_text(json.dumps({
            "generated_at": "2026-01-02T00:00:00Z",
            "candidates": [candidate],
            "kev_only": [{
                "cve": "CVE-2026-5678", "review_status": "pending",
                "nvd_record_in_window": False, "cisa_kev": True,
                "kev_details": {"vendor_project": "Other", "product": "NVR",
                                "short_description": "KEV-only test"},
            }],
        }))

    def tearDown(self):
        self.temp.cleanup()

    def test_list_pending_search_and_pagination(self):
        rows = list_pending(self.inbox, query="camera", limit=1)
        self.assertEqual([row["cve"] for row in rows], ["CVE-2026-1234"])
        self.assertEqual(len(list_pending(self.inbox, kev_only=True)), 1)

    def test_decided_items_disappear_from_pending_queue(self):
        record_decision(
            self.inbox, self.approvals, self.audit, "CVE-2026-1234",
            "rejected", "analyst-1", "Not affected.",
            "https://vendor.example/security/CVE-2026-1234",
        )
        self.assertEqual(list_pending(self.inbox, approvals_path=self.approvals), [
            row for row in list_pending(self.inbox) if row["cve"] == "CVE-2026-5678"
        ])

    def test_approval_requires_source_candidate_and_audit(self):
        with self.assertRaisesRegex(ReviewError, "not present"):
            record_decision(
                self.inbox, self.approvals, self.audit, "CVE-2026-9999",
                "approved", "analyst", "Reviewed vendor bulletin",
                "https://vendor.example/security/CVE-2026-9999",
                "cpe:2.3:o:vendor:camera:1.2.3:*:*:*:*:*:*:*", ["1.2.3"],
            )

        event = record_decision(
            self.inbox, self.approvals, self.audit, "CVE-2026-1234",
            "approved", "analyst-1", "Confirmed exact model and firmware in vendor bulletin.",
            "https://vendor.example/security/CVE-2026-1234",
            "cpe:2.3:o:vendor:camera:1.2.3:*:*:*:*:*:*:*", ["1.2.3"],
        )
        self.assertEqual(event["decision"], "approved")
        self.assertTrue(verify_audit(self.audit)["valid"])
        self.assertEqual(export_reviewed_approvals(self.approvals, self.inbox, self.output), 1)
        exported = json.loads(self.output.read_text())
        self.assertEqual(exported["advisories"][0]["cve"], "CVE-2026-1234")
        self.assertEqual(exported["advisories"][0]["affected_versions"], ["1.2.3"])

    def test_rejects_cpe_that_does_not_match_nvd_applicability(self):
        with self.assertRaisesRegex(ReviewError, "does not match"):
            record_decision(
                self.inbox, self.approvals, self.audit, "CVE-2026-1234",
                "approved", "analyst", "Reviewed vendor bulletin",
                "https://vendor.example/security/CVE-2026-1234",
                "cpe:2.3:o:other:nvr:1.2.3:*:*:*:*:*:*:*", ["1.2.3"],
            )

    def test_audit_tampering_is_detected(self):
        record_decision(
            self.inbox, self.approvals, self.audit, "CVE-2026-1234",
            "rejected", "analyst-1", "Not the affected product.",
            "https://vendor.example/security/CVE-2026-1234",
        )
        self.audit.write_text(self.audit.read_text().replace("Not the affected product.", "changed"))
        with self.assertRaisesRegex(ReviewError, "integrity check failed"):
            verify_audit(self.audit)

    def test_kev_only_requires_and_accepts_analyst_sourced_cvss(self):
        with self.assertRaisesRegex(ReviewError, "analyst-sourced CVSS"):
            record_decision(
                self.inbox, self.approvals, self.audit, "CVE-2026-5678",
                "approved", "analyst-1", "Vendor advisory confirms exact product.",
                "https://vendor.example/security/CVE-2026-5678",
                "cpe:2.3:o:vendor:nvr:4.5.6:*:*:*:*:*:*:*", ["4.5.6"],
            )
        record_decision(
            self.inbox, self.approvals, self.audit, "CVE-2026-5678",
            "approved", "analyst-1", "Vendor advisory confirms exact product and score.",
            "https://vendor.example/security/CVE-2026-5678",
            "cpe:2.3:o:vendor:nvr:4.5.6:*:*:*:*:*:*:*", ["4.5.6"], cvss_score=7.4,
        )
        self.assertEqual(export_reviewed_approvals(self.approvals, self.inbox, self.output), 1)
        self.assertEqual(json.loads(self.output.read_text())["advisories"][0]["cvss_base_score"], 7.4)

    def test_export_rejects_modified_audit_provenance_fields(self):
        record_decision(
            self.inbox, self.approvals, self.audit, "CVE-2026-1234",
            "approved", "analyst-1", "Confirmed exact model and firmware.",
            "https://vendor.example/security/CVE-2026-1234",
            "cpe:2.3:o:vendor:camera:1.2.3:*:*:*:*:*:*:*", ["1.2.3"],
        )
        original = json.loads(self.approvals.read_text())
        for field, value in (("reviewed_by", "forged-analyst"),
                             ("reviewed_at", "2026-01-01T00:00:00Z"),
                             ("rationale", "altered rationale")):
            with self.subTest(field=field):
                altered = json.loads(json.dumps(original))
                altered["approvals"][0][field] = value
                self.approvals.write_text(json.dumps(altered))
                with self.assertRaisesRegex(ReviewError, "does not match its latest audit event"):
                    export_reviewed_approvals(self.approvals, self.inbox, self.output)
        self.approvals.write_text(json.dumps(original))
        self.assertEqual(export_reviewed_approvals(self.approvals, self.inbox, self.output), 1)
    def test_rejected_record_is_not_exported(self):
        record_decision(
            self.inbox, self.approvals, self.audit, "CVE-2026-1234",
            "rejected", "analyst-1", "Not affected.",
            "https://vendor.example/security/CVE-2026-1234",
        )
        self.assertEqual(export_reviewed_approvals(self.approvals, self.inbox, self.output), 0)
        self.assertEqual(json.loads(self.output.read_text())["advisories"], [])


if __name__ == "__main__":
    unittest.main()
