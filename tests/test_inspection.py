import tempfile
import unittest
from pathlib import Path

from camguard.inspection import (
    CHECKLISTS, checklist_template, create_inspection, inspection_summary,
    record_check, validate_inspection, write_inspection_json,
)


class TechnicianInspectionTests(unittest.TestCase):
    def setUp(self):
        self.inspection = create_inspection("assessment-1", "asset-1", "192.168.1.10", "tech-1")

    def test_six_checklists_and_thirty_checks(self):
        template = checklist_template()
        self.assertEqual(len(template), 6)
        self.assertEqual(sum(len(c["checks"]) for c in template), 30)
        self.assertEqual(len(CHECKLISTS), 6)

    def test_pass_requires_evidence_reference(self):
        with self.assertRaisesRegex(ValueError, "evidence reference"):
            record_check(self.inspection, "account_permissions", "unique_accounts", "pass")

    def test_records_evidence_reference_without_raw_attachment(self):
        record_check(self.inspection, "account_permissions", "unique_accounts", "pass",
                     evidence_refs=["client-evidence://job-42/photo-1"])
        validate_inspection(self.inspection)
        self.assertEqual(self.inspection["responses"][0]["evidence_refs"],
                         ["client-evidence://job-42/photo-1"])

    def test_not_verified_can_be_recorded_without_evidence(self):
        record_check(self.inspection, "remote_access", "remote_logging", "not_verified")
        self.assertEqual(inspection_summary(self.inspection)["not_verified"], 1)

    def test_not_applicable_requires_reason(self):
        with self.assertRaisesRegex(ValueError, "requires explanatory notes"):
            record_check(self.inspection, "physical_security", "power_protection", "not_applicable")
        record_check(self.inspection, "physical_security", "power_protection", "not_applicable",
                     notes="No battery-backed equipment is in scope.")

    def test_secret_like_notes_rejected(self):
        with self.assertRaisesRegex(ValueError, "secret"):
            record_check(self.inspection, "nvr_configuration", "config_backup", "needs_attention",
                         notes="password: Example123")

    def test_response_is_upserted(self):
        record_check(self.inspection, "account_permissions", "unique_accounts", "not_verified")
        record_check(self.inspection, "account_permissions", "unique_accounts", "pass",
                     evidence_refs=["evidence://one"])
        self.assertEqual(len(self.inspection["responses"]), 1)
        self.assertEqual(self.inspection["responses"][0]["status"], "pass")

    def test_complete_inspection_enforced(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            validate_inspection(self.inspection, require_complete=True)

    def test_json_roundtrip_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_inspection_json(self.inspection, Path(directory) / "inspection.json")
            self.assertTrue(path.exists())
            self.assertIn('"schema_version": "1.0"', path.read_text())


if __name__ == "__main__":
    unittest.main()
