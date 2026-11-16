import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import camguard

from camguard.advisory_review import record_decision
from camguard.cli import main


class AssessApprovalBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inventory = self.root / "inventory.json"
        self.inbox = self.root / "pending-review.json"
        self.approvals = self.root / "approvals.json"
        self.audit = self.root / "review-audit.jsonl"
        self.output = self.root / "reports"
        self.cpe = "cpe:2.3:o:vendor:camera:1.2.3:*:*:*:*:*:*:*"
        self.inventory.write_text(json.dumps({"devices": [{
            "ip": "192.168.1.10", "vendor": "Vendor", "model": "Camera",
            "firmware": "1.2.3", "cpe": self.cpe,
            "source": "Technician verified label", "verified": True
        }]}))
        candidate = {
            "cve": "CVE-2026-1234", "review_status": "pending",
            "nvd_record_in_window": True, "cisa_kev": True,
            "cvss_base_score": 8.1,
            "cpe_applicability": [{"criteria": "cpe:2.3:o:vendor:camera:*:*:*:*:*:*:*:*", "vulnerable": True}],
        }
        self.inbox.write_text(json.dumps({"candidates": [candidate], "kev_only": []}))

    def tearDown(self):
        self.temp.cleanup()

    def _approve(self):
        return record_decision(
            self.inbox, self.approvals, self.audit, "CVE-2026-1234",
            "approved", "analyst-1", "Vendor bulletin confirms exact model and firmware.",
            "https://vendor.example/security/CVE-2026-1234",
            self.cpe, ["1.2.3"],
        )

    def test_assess_without_approval_inputs_runs_without_cve_matches(self):
        captured = []
        with patch("camguard.cli._write_all", side_effect=lambda result, output: captured.append(result)):
            self.assertEqual(main(["assess", "--inventory", str(self.inventory), "--output-dir", str(self.output)]), 0)
        self.assertEqual(captured[0]["findings"], [])
        self.assertEqual(captured[0]["intelligence"]["advisories_loaded"], 0)
        self.assertEqual(captured[0]["version"], camguard.__version__)

    def test_assess_rejects_partial_approval_inputs(self):
        with patch("camguard.cli._write_all") as writer:
            self.assertEqual(main(["assess", "--inventory", str(self.inventory), "--approvals", str(self.approvals)]), 2)
            writer.assert_not_called()

    def test_assess_uses_only_audit_verified_approval_export_and_cleans_tempdir(self):
        self._approve()
        captured = []
        created = []
        real_tempdir = tempfile.TemporaryDirectory

        def make_tempdir(*args, **kwargs):
            directory = real_tempdir(*args, **kwargs)
            created.append(Path(directory.name))
            return directory

        args = ["assess", "--inventory", str(self.inventory),
                "--approvals", str(self.approvals), "--inbox", str(self.inbox),
                "--audit", str(self.audit), "--output-dir", str(self.output)]
        with patch("camguard.cli.tempfile.TemporaryDirectory", side_effect=make_tempdir):
            with patch("camguard.cli._write_all", side_effect=lambda result, output: captured.append(result)):
                self.assertEqual(main(args), 0)
        self.assertEqual([item["cve"] for item in captured[0]["findings"]], ["CVE-2026-1234"])
        self.assertEqual(len(created), 1)
        self.assertFalse(created[0].exists())

    def test_assess_cleans_tempdir_when_approval_validation_fails(self):
        self._approve()
        approvals = json.loads(self.approvals.read_text())
        approvals["approvals"][0]["affected_versions"] = ["9.9.9"]
        self.approvals.write_text(json.dumps(approvals))
        created = []
        real_tempdir = tempfile.TemporaryDirectory

        def make_tempdir(*args, **kwargs):
            directory = real_tempdir(*args, **kwargs)
            created.append(Path(directory.name))
            return directory

        args = ["assess", "--inventory", str(self.inventory),
                "--approvals", str(self.approvals), "--inbox", str(self.inbox),
                "--audit", str(self.audit), "--output-dir", str(self.output)]
        with patch("camguard.cli.tempfile.TemporaryDirectory", side_effect=make_tempdir):
            with patch("camguard.cli._write_all") as writer:
                self.assertEqual(main(args), 2)
                writer.assert_not_called()
        self.assertEqual(len(created), 1)
        self.assertFalse(created[0].exists())

    def test_assess_rejects_broken_audit_chain(self):
        self._approve()
        self.audit.write_text(self.audit.read_text().replace("Vendor bulletin confirms", "tampered bulletin confirms"))
        args = ["assess", "--inventory", str(self.inventory),
                "--approvals", str(self.approvals), "--inbox", str(self.inbox),
                "--audit", str(self.audit), "--output-dir", str(self.output)]
        with patch("camguard.cli._write_all") as writer:
            self.assertEqual(main(args), 2)
            writer.assert_not_called()

    def test_assess_no_longer_accepts_arbitrary_advisory_file_argument(self):
        with self.assertRaises(SystemExit):
            main(["assess", "--inventory", str(self.inventory), "--advisories", "untrusted.json"])


if __name__ == "__main__":
    unittest.main()
