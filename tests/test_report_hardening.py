import tempfile
import unittest
from pathlib import Path

from camguard.pdf_report import write_pdf_report
from camguard.reporting import write_reports
from camguard.risk import apply_risk_scores


class ReportHardeningTests(unittest.TestCase):
    def _result(self):
        result = {
            "generated_at": "2026-11-15T12:00:00Z",
            "scope": {"cidr": "operator-supplied inventory", "addresses_considered": 1},
            "scan_type": "offline inventory enrichment; no network probes",
            "assets": [{"ip": "192.0.2.10", "open_ports": [], "identity": {
                "vendor": "A&B <Vendor>", "model": "Camera <X>", "firmware": "1.2.3"
            }}],
            "findings": [{
                "asset_ip": "192.0.2.10", "title": "Issue <script>&", "severity": "high",
                "evidence": "Evidence <tag> & details",
                "recommendation": "Patch <firmware> & validate",
                "source": "https://vendor.example/advisory?a=1&b=2",
                "risk_explanation": ["Exact match <confirmed> & reviewed"],
            }],
            "limitations": ["Offline evidence only <not a scan> & no guarantee."],
        }
        apply_risk_scores(result)
        return result

    def test_pdf_escapes_untrusted_fields_and_renders_full_methodology(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "assessment.pdf"
            path = write_pdf_report(self._result(), output)
            self.assertTrue(path.is_file())
            self.assertGreater(path.stat().st_size, 1000)

    def test_markdown_disclaimer_matches_offline_assessment_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            _, markdown = write_reports(self._result(), folder)
            content = markdown.read_text(encoding="utf-8")
            self.assertIn("assessment method and evidence described above", content)
            self.assertNotIn("records TCP reachability only", content)


if __name__ == "__main__":
    unittest.main()
