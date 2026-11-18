import socket
import ssl
import unittest
from unittest.mock import patch

from camguard.service_exposure import observe_service


class FakeSocket:
    def __init__(self, response=b"HTTP/1.1 200 OK\\r\\n"):
        self.response = iter(response)
        self.sent = b""
    def settimeout(self, timeout): pass
    def sendall(self, data): self.sent += data
    def recv(self, size):
        try: return bytes([next(self.response)])
        except StopIteration: return b""
    def close(self): pass
    def __enter__(self): return self
    def __exit__(self, *args): pass


class ServiceExposureTests(unittest.TestCase):
    def test_http_records_only_validated_status_code(self):
        sock = FakeSocket(b"HTTP/1.1 200 OK SECRET_TOKEN=abc123\\r\\n")
        with patch("camguard.service_exposure.socket.create_connection", return_value=sock):
            result = observe_service("192.168.1.10", 80)
        self.assertEqual(result["service_name"], "HTTP")
        self.assertEqual(result["service_evidence"], "Received HTTP status code: 200.")
        self.assertNotIn("OK", result["service_evidence"])
        self.assertNotIn("SECRET_TOKEN", str(result))
        self.assertNotIn(b"Authorization:", sock.sent)

    def test_malformed_and_incomplete_http_lines_are_not_identified(self):
        for response in (b"HTTP/9.9 200 OK\\r\\n", b"HTTP/1.1 20 OK\\r\\n", b"HTTP/1.1 200 OK", b"HTTP/1.1 200 OK" + b"x" * 600):
            with self.subTest(response=response[:30]):
                sock = FakeSocket(response)
                with patch("camguard.service_exposure.socket.create_connection", return_value=sock):
                    result = observe_service("192.168.1.10", 8080)
                self.assertIsNone(result["service_name"])
                self.assertEqual(result["encryption_status"], "unknown")

    def test_unrelated_port_is_not_probed(self):
        with patch("camguard.service_exposure.socket.create_connection") as connect:
            result = observe_service("192.168.1.10", 554)
        connect.assert_not_called()
        self.assertEqual(result["service_identification"], "unknown")

    def test_tls_success_confirms_handshake_not_certificate_trust(self):
        raw = FakeSocket(b"")
        class Secured:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def version(self): return "TLSv1.3"
            def cipher(self): return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
        class Context:
            check_hostname = True
            verify_mode = None
            def wrap_socket(self, sock, server_hostname=None): return Secured()
        with patch("camguard.service_exposure.socket.create_connection", return_value=raw), patch("camguard.service_exposure.ssl.SSLContext", return_value=Context()):
            result = observe_service("192.168.1.10", 443)
        self.assertEqual(result["encryption_status"], "confirmed_tls")
        self.assertIn("Certificate trust was not evaluated", result["encryption_evidence"])

    def test_tls_timeout_is_inconclusive(self):
        raw = FakeSocket()
        class Context:
            check_hostname = True
            verify_mode = None
            def wrap_socket(self, sock, server_hostname=None): raise socket.timeout()
        with patch("camguard.service_exposure.socket.create_connection", return_value=raw), patch("camguard.service_exposure.ssl.SSLContext", return_value=Context()):
            result = observe_service("192.168.1.10", 443)
        self.assertEqual(result["encryption_status"], "unknown")
        self.assertIn("timed out", result["service_evidence"])

    def test_tls_refused_connection_is_error_not_tls(self):
        with patch("camguard.service_exposure.socket.create_connection", side_effect=ConnectionRefusedError):
            result = observe_service("192.168.1.10", 443)
        self.assertEqual(result["reachability"], "error")
        self.assertEqual(result["encryption_status"], "unknown")
        self.assertNotIn("TLS handshake succeeded", result["service_evidence"])

    def test_tls_handshake_failure_is_not_confirmed(self):
        raw = FakeSocket()
        class Context:
            check_hostname = True
            verify_mode = None
            def wrap_socket(self, sock, server_hostname=None): raise ssl.SSLError("password=do-not-leak")
        with patch("camguard.service_exposure.socket.create_connection", return_value=raw), patch("camguard.service_exposure.ssl.SSLContext", return_value=Context()):
            result = observe_service("192.168.1.10", 443)
        self.assertEqual(result["encryption_status"], "unknown")
        self.assertIn("handshake failed", result["service_evidence"])
        self.assertNotIn("do-not-leak", str(result))

    def test_tls_socket_timeout_during_handshake_is_distinct(self):
        raw = FakeSocket()
        class Context:
            check_hostname = True
            verify_mode = None
            def wrap_socket(self, sock, server_hostname=None): raise TimeoutError()
        with patch("camguard.service_exposure.socket.create_connection", return_value=raw), patch("camguard.service_exposure.ssl.SSLContext", return_value=Context()):
            result = observe_service("192.168.1.10", 8443)
        self.assertIn("timed out", result["service_evidence"])
        self.assertEqual(result["encryption_status"], "unknown")


if __name__ == "__main__":
    unittest.main()
