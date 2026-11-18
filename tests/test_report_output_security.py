import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from camguard import pdf_report
from camguard.reporting import _safe_markdown, redact_sensitive, write_reports


class ReportOutputSecurityTests(unittest.TestCase):
    def test_markdown_escapes_markup_and_redacts_secret_values(self):
        value = "<script>alert(1)</script> **bold** token=abc123"
        safe = _safe_markdown(value)
        self.assertNotIn("<script>", safe)
        self.assertNotIn("**bold**", safe)
        self.assertIn(r"\<script\>", safe)
        self.assertIn("token=[REDACTED]", safe)
        self.assertNotIn("abc123", safe)
        self.assertEqual(redact_sensitive("password=hunter2 token=abc123 api_key=key456"),
                         "password=[REDACTED] token=[REDACTED] api_key=[REDACTED]")

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
        self.assertNotIn("Service evidence: <img", text)
        self.assertIn(r"\<img", text)
        self.assertNotIn("secret123", text)
        self.assertIn("api\\_key=[REDACTED]", text)

    def test_pdf_dynamic_paragraph_content_is_escaped_before_parsing(self):
        malicious = "<b>Injected</b><img src=x onerror=alert(1)> token=private123 api_key=secret123 password=hidden456"
        result = {
            "generated_at": "2026-11-17T12:00:00Z",
            "version": "0.6.0",
            "scope": {"cidr": "192.168.1.0/24"},
            "scan_type": "authorized scan token=table-secret",
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
        real_table = pdf_report.Table
        def capture(text, style, *args, **kwargs):
            seen.append(str(text))
            return real_paragraph(text, style, *args, **kwargs)
        def capture_table(data, *args, **kwargs):
            seen.extend(str(cell) for row in data for cell in row)
            return real_table(data, *args, **kwargs)
        with tempfile.TemporaryDirectory() as tmp:
            with patch("camguard.pdf_report.Paragraph", side_effect=capture), patch("camguard.pdf_report.Table", side_effect=capture_table):
                output = pdf_report.write_pdf_report(result, Path(tmp) / "report.pdf")
            self.assertTrue(output.exists())
            self.assertGreater(output.stat().st_size, 0)
        dynamic = "\n".join(seen)
        self.assertNotIn("<img", dynamic)
        self.assertNotIn("<b>Injected</b>", dynamic)
        self.assertIn("&lt;b&gt;Injected&lt;/b&gt;", dynamic)
        self.assertIn("&lt;img", dynamic)
        self.assertIn("token=[REDACTED]", dynamic)
        self.assertNotIn("private123", dynamic)
        self.assertNotIn("secret123", dynamic)
        self.assertNotIn("hidden456", dynamic)
        self.assertNotIn("table-secret", dynamic)
        self.assertIn("token=[REDACTED]", dynamic)
        self.assertIn("api_key=[REDACTED]", dynamic)
        self.assertIn("password=[REDACTED]", dynamic)



if __name__ == "__main__":
    unittest.main()
