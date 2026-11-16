import contextlib
import io
import json
import unittest

from camguard.cli import build_parser, main


class ReviewCliHelpTests(unittest.TestCase):
    def help_for(self, arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as raised:
                build_parser().parse_args(arguments + ["--help"])
        self.assertEqual(raised.exception.code, 0)
        return output.getvalue()

    def test_list_help_only_shows_list_options(self):
        help_text = self.help_for(["review-advisories", "list"])
        self.assertIn("--query", help_text)
        self.assertIn("--limit", help_text)
        self.assertNotIn("--cve", help_text)
        self.assertNotIn("--reviewed-by", help_text)
        self.assertNotIn("--decision", help_text)

    def test_decide_help_only_shows_decision_options(self):
        help_text = self.help_for(["review-advisories", "decide"])
        self.assertIn("--cve", help_text)
        self.assertIn("--reviewed-by", help_text)
        self.assertIn("--evidence-url", help_text)
        self.assertNotIn("--query", help_text)
        self.assertNotIn("--limit", help_text)

    def test_verify_audit_help_only_shows_audit_option(self):
        help_text = self.help_for(["review-advisories", "verify-audit"])
        self.assertIn("--audit", help_text)
        self.assertNotIn("--cve", help_text)
        self.assertNotIn("--query", help_text)
        self.assertNotIn("--decision", help_text)

    def test_review_action_is_required(self):
        with self.assertRaises(SystemExit) as raised:
            build_parser().parse_args(["review-advisories"])
        self.assertEqual(raised.exception.code, 2)

    def test_normalize_device_command_outputs_machine_readable_identity(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main([
                "normalize-device", "--vendor", "Hikvision Digital Technology",
                "--product", "network video recorder",
            ]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["vendor_normalized"], "Hikvision")
        self.assertEqual(result["product_normalized"], "NVR")
        self.assertTrue(result["manufacturer_supported"])

    def test_manufacturer_catalog_command_lists_initial_scope(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["manufacturer-catalog"]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(len(result["manufacturers"]), 6)


if __name__ == "__main__":
    unittest.main()
