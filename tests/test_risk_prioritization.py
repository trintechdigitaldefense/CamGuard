import json
import tempfile
import unittest
from pathlib import Path

from camguard.intelligence import enrich_assets, load_inventory
from camguard.risk import apply_risk_scores


class RiskPrioritizationTests(unittest.TestCase):
    def _finding(self, **overrides):
        finding = {
            "asset_ip": "192.168.1.10",
            "cve": "CVE-2024-12345",
            "cvss_base_score": 6.0,
            "severity": "medium",
            "cisa_kev": True,
            "exact_verified_match": True,
            "source": "https://vendor.example/advisory",
            "reviewed_by": "analyst-1",
            "reviewed_at": "2026-11-15T12:00:00Z",
            "network_exposure": "internet_exposed",
            "network_exposure_verified": True,
        }
        finding.update(overrides)
        return finding

    def test_score_explains_cvss_kev_and_verified_internet_exposure(self):
        result = {"assets": [{"ip": "192.168.1.10"}], "findings": [self._finding()]}
        apply_risk_scores(result)
        finding = result["findings"][0]
        self.assertEqual(finding["risk_components"]["cvss_points"], 60)
        self.assertEqual(finding["risk_components"]["kev_uplift"], 10)
        self.assertEqual(finding["risk_components"]["exposure_uplift"], 15)
        self.assertEqual(finding["risk_score"], 85)
        self.assertEqual(finding["risk_rating"], "high")
        self.assertEqual(finding["evidence_confidence"], "high")
        self.assertTrue(any("CISA KEV" in reason for reason in finding["risk_explanation"]))
        self.assertEqual(result["assets"][0]["risk_driver"], "CVE-2024-12345")

    def test_unknown_or_unverified_exposure_never_adds_points(self):
        for exposure, verified in (("unknown", False), ("internet_exposed", False)):
            with self.subTest(exposure=exposure, verified=verified):
                result = {"assets": [{"ip": "192.168.1.10"}],
                          "findings": [self._finding(network_exposure=exposure,
                                                     network_exposure_verified=verified)]}
                apply_risk_scores(result)
                self.assertEqual(result["findings"][0]["risk_components"]["exposure_uplift"], 0)
                self.assertTrue(any("no exposure uplift" in item.lower()
                                    for item in result["findings"][0]["risk_explanation"]))

    def test_unverified_cve_match_is_fail_closed(self):
        result = {"assets": [{"ip": "192.168.1.10"}],
                  "findings": [self._finding(exact_verified_match=False)]}
        apply_risk_scores(result)
        self.assertEqual(result["findings"][0]["risk_score"], 0)
        self.assertEqual(result["findings"][0]["risk_components"]["kev_uplift"], 0)

    def test_service_finding_does_not_receive_cve_or_exposure_uplifts(self):
        result = {"assets": [{"ip": "192.168.1.10"}],
                  "findings": [{"asset_ip": "192.168.1.10", "severity": "medium",
                                "evidence": "TCP connection succeeded on 80.",
                                "network_exposure": "internet_exposed",
                                "network_exposure_verified": True, "cisa_kev": True}]}
        apply_risk_scores(result)
        finding = result["findings"][0]
        self.assertEqual(finding["risk_score"], 55)
        self.assertEqual(finding["risk_components"]["kev_uplift"], 0)
        self.assertEqual(finding["risk_components"]["exposure_uplift"], 0)
        self.assertEqual(finding["evidence_confidence"], "low")

    def test_asset_uses_highest_finding_and_carries_explanation(self):
        result = {"assets": [{"ip": "192.168.1.10"}],
                  "findings": [self._finding(cvss_base_score=3.0, cisa_kev=False,
                                             network_exposure="isolated"),
                               self._finding(cvss_base_score=6.0)]}
        apply_risk_scores(result)
        self.assertEqual(result["assets"][0]["risk_score"], 85)
        self.assertEqual(result["assets"][0]["risk_rating"], "high")
        self.assertTrue(result["assets"][0]["risk_explanation"])

    def test_no_findings_is_not_described_as_proof_of_safety(self):
        result = {"assets": [{"ip": "192.168.1.10"}], "findings": []}
        apply_risk_scores(result)
        self.assertIn("not proof of safety", result["assets"][0]["risk_explanation"][0])

    def test_inventory_rejects_unknown_exposure_values(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "inventory.json"
            path.write_text(json.dumps({"devices": [{"ip": "192.168.1.10",
                "network_exposure": "probably-public"}]}))
            with self.assertRaises(ValueError):
                load_inventory(str(path))

    def test_verified_exposure_requires_evidence_source(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "inventory.json"
            path.write_text(json.dumps({"devices": [{"ip": "192.168.1.10",
                "network_exposure": "internet_exposed",
                "network_exposure_verified": True}]}))
            with self.assertRaisesRegex(ValueError, "requires network_exposure_source"):
                load_inventory(str(path))

    def test_exact_enrichment_carries_exposure_and_review_evidence(self):
        cpe = "cpe:2.3:o:example:camera:1.2.3:*:*:*:*:*:*:*"
        inventory = {"192.168.1.10": {"vendor": "Example", "model": "Cam X",
            "firmware": "1.2.3", "cpe": cpe, "source": "technician verified label",
            "verified": True, "network_exposure": "internal_segment",
            "network_exposure_verified": True, "network_exposure_source": "client firewall review"}}
        advisory = [{"cve": "CVE-2024-12345", "cpe": cpe,
            "affected_versions": ["1.2.3"], "cvss_base_score": 6.0,
            "source": "https://vendor.example/advisory", "summary": "Issue",
            "kev": True, "reviewed_by": "analyst-1", "reviewed_at": "2026-11-15T12:00:00Z"}]
        result = enrich_assets({"assets": [{"ip": "192.168.1.10"}], "findings": []},
                               inventory, advisory)
        finding = result["findings"][0]
        self.assertTrue(finding["exact_verified_match"])
        self.assertEqual(finding["network_exposure"], "internal_segment")
        self.assertEqual(finding["network_exposure_source"], "client firewall review")
        self.assertEqual(finding["reviewed_by"], "analyst-1")


if __name__ == "__main__":
    unittest.main()
