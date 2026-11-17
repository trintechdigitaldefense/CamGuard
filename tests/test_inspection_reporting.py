import json
import tempfile
import unittest
from pathlib import Path

from camguard.inspection import create_inspection, record_check
from camguard.pdf_report import write_pdf_report
from camguard.reporting import write_reports


class InspectionReportIntegrationTests(unittest.TestCase):
    def _result(self):
        inspection = create_inspection("assessment-1", "asset-1", "192.168.1.10", "technician")
        record_check(inspection, "account_permissions", "unique_accounts", "pass",
                     notes="Reviewed account roster.", evidence_refs=["evidence://case-1/accounts"])
        record_check(inspection, "remote_access", "remote_logging", "not_verified",
                     notes="Log review was not available.")
        return {
            "generated_at": "2026-11-17T12:00:00+00:00", "version": "0.5.0rc1",
            "scope": {"cidr": "operator-supplied inventory", "addresses_considered": 1},
            "scan_type": "test", "assets": [], "findings": [],
            "service_observations": [], "inspections": [inspection],
            "limitations": ["Synthetic report test."],
        }

    def test_json_and_markdown_include_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            json_path, md_path = write_reports(self._result(), directory)
            payload = json.loads(json_path.read_text())
            self.assertEqual(payload["inspections"][0]["asset_id"], "asset-1")
            markdown = md_path.read_text()
            self.assertIn("Technician-assisted inspections", markdown)
            self.assertIn("evidence://case-1/accounts", markdown)
            self.assertIn("Not verified", markdown)

    def test_pdf_includes_inspection_section(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "assessment.pdf"
            write_pdf_report(self._result(), output)
            self.assertTrue(output.exists())
            self.assertGreater(output.stat().st_size, 500)


if __name__ == "__main__":
    unittest.main()
