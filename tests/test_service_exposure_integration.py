import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from camguard.pdf_report import write_pdf_report
from camguard.reporting import write_reports
from camguard.scanner import _check_host, scan_network


class ServiceExposureIntegrationTests(unittest.TestCase):
    def test_scan_schema_includes_all_checked_port_outcomes(self):
        host = {
            "ip": "192.168.1.10",
            "open_ports": [],
            "port_observations": [
                {"device_ip": "192.168.1.10", "transport": "tcp", "port": 80,
                 "reachability": "reachable", "service_name": "HTTP",
                 "service_identification": "confirmed", "service_evidence": "HTTP/1.1 200 OK",
                 "encryption_status": "plaintext_protocol_observed", "encryption_evidence": "HTTP over TCP",
                 "evidence_confidence": "high", "business_significance": "Example",
                 "recommended_action": "Prefer HTTPS"},
                {"device_ip": "192.168.1.10", "transport": "tcp", "port": 443,
                 "reachability": "not_reachable", "service_name": None,
                 "service_identification": "unknown", "service_evidence": "No TCP connection",
                 "encryption_status": "unknown", "encryption_evidence": "Not tested",
                 "evidence_confidence": "high", "business_significance": "Not reachable",
                 "recommended_action": "Verify only if expected"},
            ],
            "observed_at": "2026-11-17T00:00:00+00:00",
        }
        network = ipaddress.ip_network("192.168.1.10/32")
        with patch("camguard.scanner.validate_scope", return_value=(network, [ipaddress.ip_address("192.168.1.10")])), patch(
            "camguard.scanner._check_host", return_value=host
        ):
            result = scan_network("192.168.1.10/32", True)
        self.assertEqual(len(result["service_observations"]), 2)
        self.assertEqual(result["service_observations"][1]["reachability"], "not_reachable")
        self.assertEqual(result["service_observations"][0]["schema_version"], "1.0")
        self.assertTrue(result["assessment_id"])


    def test_scanner_reuses_single_tcp_connection_for_http_probe(self):
        class ConnectedSocket:
            def __init__(self):
                self.response = iter(b"HTTP/1.1 204 No Content\r\n")
                self.sent = b""
                self.closed = False
            def settimeout(self, timeout): pass
            def connect_ex(self, address): return 0
            def sendall(self, data): self.sent += data
            def recv(self, size):
                try: return bytes([next(self.response)])
                except StopIteration: return b""
            def close(self): self.closed = True
            def __enter__(self): return self
            def __exit__(self, *args): self.close()
        sock = ConnectedSocket()
        with patch("camguard.scanner.socket.socket", return_value=sock) as create_socket, patch(
            "camguard.service_exposure.socket.create_connection",
            side_effect=AssertionError("protocol probe must reuse the scanner socket"),
        ):
            result = _check_host("192.168.1.10", {80: "HTTP management"}, 0.8)
        create_socket.assert_called_once()
        self.assertTrue(sock.closed)
        self.assertEqual(len(result["open_ports"]), 1)
        observation = result["open_ports"][0]["service_observation"]
        self.assertEqual(observation["service_evidence"], "Received HTTP status code: 204.")

    def test_markdown_and_pdf_render_observation_evidence(self):
        result = {
            "generated_at": "2026-11-17T00:00:00+00:00", "version": "0.5.0rc1",
            "scope": {"cidr": "192.168.1.0/24", "addresses_considered": 1},
            "scan_type": "synthetic test", "assets": [], "findings": [], "limitations": [],
            "service_observations": [{
                "device_ip": "192.168.1.10", "port": 80, "transport": "tcp",
                "reachability": "reachable", "service_name": "HTTP", "service_identification": "confirmed",
                "service_evidence": "HTTP/1.1 200 OK", "encryption_status": "plaintext_protocol_observed",
                "encryption_evidence": "HTTP response over TCP", "evidence_confidence": "high",
                "business_significance": "Management traffic may be observable", "recommended_action": "Prefer HTTPS",
                "limitations": ["Authentication was not tested"],
            }],
        }
        with tempfile.TemporaryDirectory() as tmp:
            json_path, md_path = write_reports(result, tmp)
            pdf_path = write_pdf_report(result, Path(tmp) / "report.pdf")
            self.assertTrue(json_path.exists())
            self.assertIn("Service exposure observations", md_path.read_text(encoding="utf-8"))
            self.assertTrue(pdf_path.exists())
            self.assertGreater(pdf_path.stat().st_size, 100)


if __name__ == "__main__":
    unittest.main()
