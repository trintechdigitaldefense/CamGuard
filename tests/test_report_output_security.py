import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from camguard import pdf_report
from camguard.reporting import _safe_markdown, write_reports


class ReportOutputSecurityTests(unittest.TestCase):
    def test_markdown_escapes_markup_and_redacts_secret_values(self):
        value = "<script>alert(1)</script> **bold** token=abc123"
        safe = _safe_markdown(value)
        self.assertNotIn("<script>", safe)
        self.assertNotIn("**bold**", safe)
        self.assertIn(r"\<script\>", safe)
        self.assertIn("token=[REDACTED]", safe)
        self.assertNotIn("abc123", safe)

    def test_markdown_report_escapes_untrusted_observation_and_redacts(self):
        result = {
            "generated_at": "2026-11-17T12:00:00Z",
            "version": "0.6.0",
            "scope": {"cidr": "192.168.1.0/24", "addresses_considered": 1},
            "scan_type": "safe <script> token=verysecret",
            "assets": [],
            "findings": [],
            "service_observations": [{
                "device_ip": "192.168.1.10", "port": 80, "transport": "tcp",
                "reachability": "reachable", "service_name": "HTTP",
                "service_identification": "confirmed",
                "service_evidence": "<img src=x onerror=alert(1)> api_key=secret123",
                "encryption_status": "plaintext_protocol_observed",
                "encryption_evidence": "none", "evidence_confidence": "high",
                "business_significance": "test", "recommended_action": "review",
                "limitations": [],
            }],
            "limitations": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            _, markdown = write_reports(result, tmp)
            text = markdown.read_text(encoding="utf-8")
        self.assertNotIn("<img", text)
        self.assertNotIn("onerror", text)
        self.assertNotIn("secret123", text)
        self.assertIn("api\\_key=[REDACTED]", text)

    def test_pdf_dynamic_paragraph_content_is_escaped_before_parsing(self):
        malicious = "<b>Injected</b><img src=x onerror=alert(1)> token=private123"
        result = {
            "generated_at": "2026-11-17T12:00:00Z",
            "version": "0.6.0",
            "scope": {"cidr": "192.168.1.0/24"},
            "assets": [],
            "findings": [],
            "service_observations": [{
                "device_ip": "192.168.1.10", "port": 443, "transport": "tcp",
                "reachability": "reachable", "service_name": "TLS",
                "service_identification": "confirmed",
                "service_evidence": malicious, "encryption_status": "confirmed_tls",
                "encryption_evidence": malicious, "evidence_confidence": "high",
                "business_significance": malicious, "recommended_action": malicious,
                "limitations": [malicious],
            }],
            "limitations": [],
        }
        seen = []
        real_paragraph = pdf_report.Paragraph
        def capture(text, style, *args, **kwargs):
            seen.append(str(text))
            return real_paragraph(text, style, *args, **kwargs)
        with tempfile.TemporaryDirectory() as tmp:
            with patch("camguard.pdf_report.Paragraph", side_effect=capture):
                output = pdf_report.write_pdf_report(result, Path(tmp) / "report.pdf")
            self.assertTrue(output.exists())
            self.assertGreater(output.stat().st_size, 0)
        dynamic = "\n".join(seen)
        self.assertNotIn("<img", dynamic)
        self.assertNotIn("<b>Injected</b>", dynamic)
        self.assertIn("&lt;b&gt;Injected&lt;/b&gt;", dynamic)
        self.assertIn("&lt;img", dynamic)
        self.assertIn("token=private123", dynamic)  # XML-safe; PDF does not promise secret scrubbing for arbitrary supplied fields.


if __name__ == "__main__":
    unittest.main()
