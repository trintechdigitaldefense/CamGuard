import unittest

from camguard.scanner import ScopeError, validate_scope


class ScopeValidationTests(unittest.TestCase):
    def test_requires_authorization(self):
        with self.assertRaises(ScopeError):
            validate_scope("192.168.1.0/24", False)

    def test_rejects_public_network(self):
        with self.assertRaises(ScopeError):
            validate_scope("8.8.8.0/24", True)

    def test_rejects_ipv6(self):
        with self.assertRaises(ScopeError):
            validate_scope("fd00::/120", True)

    def test_rejects_large_scope(self):
        with self.assertRaises(ScopeError):
            validate_scope("10.0.0.0/16", True)

    def test_accepts_small_private_scope(self):
        network, hosts = validate_scope("192.168.10.0/28", True)
        self.assertEqual(str(network), "192.168.10.0/28")
        self.assertEqual(len(hosts), 14)


if __name__ == "__main__":
    unittest.main()
