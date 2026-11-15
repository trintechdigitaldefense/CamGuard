import unittest
from camguard.metadata import MetadataScopeError, identify, validate_targets

class MetadataTests(unittest.TestCase):
    def test_requires_authorization(self):
        with self.assertRaises(MetadataScopeError):
            validate_targets(["192.168.1.20"], False)
    def test_rejects_public_and_ipv6(self):
        for ip in ("8.8.8.8", "2001:db8::1"):
            with self.subTest(ip=ip), self.assertRaises(MetadataScopeError):
                validate_targets([ip], True)
    def test_rejects_more_than_64_targets(self):
        with self.assertRaises(MetadataScopeError):
            validate_targets([f"10.0.0.{i}" for i in range(1,66)], True)
    def test_server_signature_is_medium(self):
        self.assertEqual(identify("Hikvision-Webs", None)[:2], ("Hikvision","medium"))
    def test_title_signature_is_low(self):
        self.assertEqual(identify("", "Dahua Camera")[:2], ("Dahua","low"))
    def test_unknown_stays_unknown(self):
        self.assertEqual(identify("nginx", "Welcome")[:2], (None,"none"))

if __name__ == "__main__":
    unittest.main()
