import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path

from camguard.cli import main
from camguard.inspection import CHECKLISTS, create_inspection, record_check, write_inspection_json


class TechnicianInspectionCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "inspection.json"
        self.inspection = create_inspection("assessment-1", "asset-1", "192.168.1.10", "tech-1")
        write_inspection_json(self.inspection, self.path)

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, args):
        output = StringIO()
        errors = StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(["inspection", *args])
        return code, output.getvalue(), errors.getvalue()

    def test_create_writes_new_inspection(self):
        output_path = self.root / "new-inspection.json"
        code, output, _ = self.run_cli([
            "create", "--assessment-id", "job-22", "--asset-id", "camera-04",
            "--device-ip", "192.168.10.4", "--inspector", "tech-a",
            "--output", str(output_path),
        ])
        self.assertEqual(code, 0)
        data = json.loads(output_path.read_text())
        self.assertEqual(data["assessment_id"], "job-22")
        self.assertEqual(data["asset_id"], "camera-04")
        self.assertIn("Inspection created", output)

    def test_template_shows_all_six_categories_and_thirty_checks(self):
        code, output, _ = self.run_cli(["template"])
        data = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(len(data["checklists"]), 6)
        self.assertEqual(sum(len(item["checks"]) for item in data["checklists"]), 30)

    def test_template_can_filter_one_category(self):
        code, output, _ = self.run_cli(["template", "--category", "remote_access"])
        data = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual([item["category_id"] for item in data["checklists"]], ["remote_access"])

    def test_record_pass_requires_evidence_and_persists(self):
        code, _, errors = self.run_cli([
            "record", "--input", str(self.path), "--category", "account_permissions",
            "--check", "unique_accounts", "--status", "pass",
        ])
        self.assertEqual(code, 2)
        self.assertIn("evidence reference", errors)
        self.assertEqual(json.loads(self.path.read_text())["responses"], [])

        code, output, _ = self.run_cli([
            "record", "--input", str(self.path), "--category", "account_permissions",
            "--check", "unique_accounts", "--status", "pass",
            "--evidence-ref", "client-evidence://job-22/photo-3",
        ])
        self.assertEqual(code, 0)
        data = json.loads(self.path.read_text())
        self.assertEqual(data["responses"][0]["status"], "pass")
        self.assertIn("Recorded pass", output)

    def test_record_replaces_existing_response_for_same_check(self):
        args = [
            "record", "--input", str(self.path), "--category", "remote_access",
            "--check", "remote_logging", "--status", "not_verified",
        ]
        self.assertEqual(self.run_cli(args)[0], 0)
        args[args.index("not_verified")] = "needs_attention"
        args.extend(["--notes", "Logging review requires follow-up."])
        self.assertEqual(self.run_cli(args)[0], 0)
        data = json.loads(self.path.read_text())
        self.assertEqual(len(data["responses"]), 1)
        self.assertEqual(data["responses"][0]["status"], "needs_attention")

    def test_validate_reports_partial_completion(self):
        code, output, _ = self.run_cli(["validate", "--input", str(self.path)])
        data = json.loads(output)
        self.assertEqual(code, 0)
        self.assertEqual(data["summary"]["completed_checks"], 0)
        self.assertEqual(data["summary"]["unanswered_checks"], 30)

    def test_validate_require_complete_rejects_incomplete_inspection(self):
        code, _, errors = self.run_cli([
            "validate", "--input", str(self.path), "--require-complete",
        ])
        self.assertEqual(code, 2)
        self.assertIn("incomplete", errors)

    def test_validate_accepts_all_thirty_responses(self):
        for category_id, category in CHECKLISTS.items():
            for check_id, _ in category["checks"]:
                record_check(self.inspection, category_id, check_id, "not_verified")
        write_inspection_json(self.inspection, self.path)
        code, output, _ = self.run_cli([
            "validate", "--input", str(self.path), "--require-complete",
        ])
        data = json.loads(output)
        self.assertEqual(code, 0)
        self.assertTrue(data["valid"])
        self.assertEqual(data["summary"]["completed_checks"], 30)


    def test_assess_attaches_matching_inspection_to_report_result(self):
        inventory = self.root / "inventory.json"
        inventory.write_text(json.dumps({"devices": [{
            "ip": "192.168.1.10", "vendor": "Vendor", "model": "Camera",
            "firmware": "1.2.3", "cpe": "cpe:2.3:o:vendor:camera:1.2.3:*:*:*:*:*:*:*",
            "source": "Client asset register", "verified": True,
        }]}))
        inspection = create_inspection("assessment-attach", "asset-1", "192.168.1.10", "tech-1")
        inspection_path = self.root / "attached-inspection.json"
        write_inspection_json(inspection, inspection_path)
        captured = []
        from unittest.mock import patch
        with patch("camguard.cli._write_all", side_effect=lambda result, output: captured.append(result)):
            code = main([
                "assess", "--inventory", str(inventory),
                "--assessment-id", "assessment-attach",
                "--inspection", str(inspection_path),
                "--output-dir", str(self.root / "reports"),
            ])
        self.assertEqual(code, 0)
        self.assertEqual(len(captured[0]["inspections"]), 1)
        self.assertEqual(captured[0]["inspections"][0]["asset_id"], "asset-1")

    def test_assess_rejects_inspection_for_different_assessment(self):
        inventory = self.root / "inventory.json"
        inventory.write_text(json.dumps({"devices": [{
            "ip": "192.168.1.10", "vendor": "Vendor", "model": "Camera",
            "firmware": "1.2.3", "cpe": "cpe:2.3:o:vendor:camera:1.2.3:*:*:*:*:*:*:*",
            "source": "Client asset register", "verified": True,
        }]}))
        inspection = create_inspection("another-assessment", "asset-1", "192.168.1.10", "tech-1")
        inspection_path = self.root / "wrong-assessment.json"
        write_inspection_json(inspection, inspection_path)
        from unittest.mock import patch
        with patch("camguard.cli._write_all") as writer:
            code = main([
                "assess", "--inventory", str(inventory),
                "--assessment-id", "assessment-attach",
                "--inspection", str(inspection_path),
                "--output-dir", str(self.root / "reports"),
            ])
            writer.assert_not_called()
        self.assertEqual(code, 2)

    def test_invalid_input_json_returns_cli_error(self):
        self.path.write_text("{broken")
        code, _, errors = self.run_cli(["validate", "--input", str(self.path)])
        self.assertEqual(code, 2)
        self.assertIn("CamGuard error", errors)


if __name__ == "__main__":
    unittest.main()
