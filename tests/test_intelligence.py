import json
import tempfile
import unittest
from pathlib import Path

from camguard.intelligence import enrich_assets, load_advisories, load_inventory
from camguard.risk import apply_risk_scores


class IntelligenceTests(unittest.TestCase):
    def test_exact_verified_cpe_and_firmware_match(self):
        result = {"assets": [{"ip": "192.168.1.10", "open_ports": []}], "findings": []}
        inventory = {"192.168.1.10": {
            "vendor": "Example", "model": "Cam X", "firmware": "1.2.3",
            "cpe": "cpe:2.3:o:example:cam_x_firmware:1.2.3:*:*:*:*:*:*:*",
            "source": "client maintenance record", "verified": True,
        }}
        advisory = [{
            "cve": "CVE-2024-12345", "cpe": inventory["192.168.1.10"]["cpe"],
            "affected_versions": ["1.2.3"], "cvss_base_score": 8.1,
            "source": "vendor advisory", "summary": "Example issue",
        }]
        enriched = enrich_assets(result, inventory, advisory)
        self.assertEqual(enriched["assets"][0]["matched_cves"], ["CVE-2024-12345"])
        self.assertEqual(enriched["findings"][0]["severity"], "high")

    def test_unverified_inventory_never_matches(self):
        result = {"assets": [{"ip": "192.168.1.10", "open_ports": []}], "findings": []}
        record = {"vendor": "Example", "model": "Cam", "firmware": "1",
                  "cpe": "cpe:x", "source": "guess", "verified": False}
        advisory = [{"cve": "CVE-2024-12345", "cpe": "cpe:x",
                     "affected_versions": ["1"], "cvss_base_score": 9.8,
                     "source": "test", "summary": "test"}]
        enrich_assets(result, {"192.168.1.10": record}, advisory)
        self.assertEqual(result["findings"], [])

    def test_risk_scoring_uses_highest_finding(self):
        result = {"assets": [{"ip": "192.168.1.10"}], "findings": [
            {"asset_ip": "192.168.1.10", "severity": "medium"},
            {"asset_ip": "192.168.1.10", "severity": "high"},
        ]}
        apply_risk_scores(result)
        self.assertEqual(result["assets"][0]["risk_score"], 80)
        self.assertEqual(result["assets"][0]["risk_rating"], "high")

    def test_inventory_file_load(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "inventory.json"
            path.write_text(json.dumps({"devices": [{"ip": "192.168.1.2", "vendor": "V",
                "model": "M", "firmware": "1.0", "cpe": "cpe:x", "verified": True}]}))
            self.assertTrue(load_inventory(str(path))["192.168.1.2"]["verified"])

    def test_invalid_cve_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "advisories.json"
            path.write_text(json.dumps([{"cve": "not-a-cve", "cpe": "cpe:x",
                "affected_versions": ["1"], "cvss_base_score": 5}]))
            with self.assertRaises(ValueError):
                load_advisories(str(path))


if __name__ == "__main__":
    unittest.main()
