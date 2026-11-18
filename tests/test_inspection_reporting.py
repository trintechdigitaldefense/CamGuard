import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from camguard.inspection import create_inspection, record_check
from camguard.pdf_report import write_pdf_report
from camguard.reporting import write_reports


class InspectionReportIntegrationTests(unittest.TestCase):
    def _result(self):
        inspection = create_inspection("assessment-1", "asset-1", "192.168.1.10", "technician")
        record_check(inspection, "account_permissions", "unique_accounts", "pass",
                     notes="<script>alert(1)</script> **untrusted**",
                     evidence_refs=["evidence://case-1/<img src=x onerror=alert(1)>"])
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
            self.assertIn(r"\<script\>", markdown)
            self.assertNotIn("<script>", markdown)
            self.assertNotIn("**untrusted**", markdown)
            self.assertIn(r"\<img", markdown)
            self.assertNotIn("<img", markdown)
            self.assertIn("Not verified", markdown)

    def test_pdf_escapes_untrusted_inspection_text(self):
        from camguard import pdf_report
        seen = []
        real_paragraph = pdf_report.Paragraph

        def capture(value, style, *args, **kwargs):
            seen.append(str(value))
            return real_paragraph(value, style, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "assessment.pdf"
            with patch("camguard.pdf_report.Paragraph", side_effect=capture):
                write_pdf_report(self._result(), output)
            self.assertTrue(output.exists())
            self.assertGreater(output.stat().st_size, 500)
        dynamic = "\n".join(seen)
        self.assertNotIn("<script>", dynamic)
        self.assertNotIn("<img", dynamic)
        self.assertIn("&lt;script&gt;", dynamic)
        self.assertIn("&lt;img", dynamic)


if __name__ == "__main__":
    unittest.main()
