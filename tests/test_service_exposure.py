import unittest
from unittest.mock import patch
from camguard.service_exposure import observe_service


class FakeSocket:
    def __init__(self, response=b"HTTP/1.1 200 OK\r\n"):
        self.response = iter(response)
        self.sent = b""
    def settimeout(self, timeout): pass
    def sendall(self, data): self.sent += data
    def recv(self, size):
        try: return bytes([next(self.response)])
        except StopIteration: return b""
    def __enter__(self): return self
    def __exit__(self, *args): pass


class ServiceExposureTests(unittest.TestCase):
    def test_http_identification_and_plaintext(self):
        sock = FakeSocket()
        with patch("camguard.service_exposure.socket.create_connection", return_value=sock):
            result = observe_service("192.168.1.10", 80)
        self.assertEqual(result["service_name"], "HTTP")
        self.assertEqual(result["service_identification"], "confirmed")
        self.assertEqual(result["encryption_status"], "plaintext_protocol_observed")
        self.assertIn(b"HEAD / HTTP/1.0", sock.sent)
        self.assertNotIn(b"Authorization:", sock.sent)

    def test_port_number_alone_does_not_identify_service(self):
        with patch("camguard.service_exposure.socket.create_connection") as connect:
            result = observe_service("192.168.1.10", 554)
        connect.assert_not_called()
        self.assertIsNone(result["service_name"])
        self.assertEqual(result["service_identification"], "unknown")
        self.assertEqual(result["encryption_status"], "unknown")

    def test_invalid_http_response_stays_unknown(self):
        sock = FakeSocket(b"not-http\r\n")
        with patch("camguard.service_exposure.socket.create_connection", return_value=sock):
            result = observe_service("192.168.1.10", 8080)
        self.assertIsNone(result["service_name"])
        self.assertEqual(result["encryption_status"], "unknown")

    def test_probe_timeout_does_not_claim_encryption(self):
        with patch("camguard.service_exposure.socket.create_connection", side_effect=TimeoutError):
            result = observe_service("192.168.1.10", 80)
        self.assertEqual(result["service_identification"], "unknown")
        self.assertEqual(result["encryption_status"], "unknown")


if __name__ == "__main__":
    unittest.main()
