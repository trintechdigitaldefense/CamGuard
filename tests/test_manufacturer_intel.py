import unittest

from camguard.manufacturer_intel import (
    normalize_device_identity,
    normalize_manufacturer,
    normalize_product,
    supported_manufacturers,
)


class ManufacturerIntelligenceTests(unittest.TestCase):
    def test_supported_manufacturer_aliases(self):
        cases = {
            "Hikvision Digital Technology Co., Ltd.": "Hikvision",
            "Zhejiang Dahua Technology Co., Ltd.": "Dahua",
            "Axis Communications AB": "Axis Communications",
            "Hanwha Techwin Co., Ltd.": "Hanwha Vision",
            "UNV": "Uniview",
            "Bosch Building Technologies": "Bosch Security Systems",
        }
        for supplied, expected in cases.items():
            with self.subTest(supplied=supplied):
                self.assertEqual(normalize_manufacturer(supplied), expected)

    def test_manufacturer_alias_matching_is_case_and_punctuation_insensitive(self):
        self.assertEqual(normalize_manufacturer("  AXIS communications ab "), "Axis Communications")

    def test_unknown_and_ambiguous_manufacturers_are_not_fuzzy_matched(self):
        self.assertIsNone(normalize_manufacturer("Samsung"))
        self.assertIsNone(normalize_manufacturer("Hikvision-like camera"))
        self.assertIsNone(normalize_manufacturer(None))

    def test_generic_product_aliases(self):
        self.assertEqual(normalize_product("Hikvision", "network video recorder"), "NVR")
        self.assertEqual(normalize_product("Dahua", "IP cameras"), "IP Camera")
        self.assertEqual(normalize_product("Axis", "digital video recorder"), "DVR")
        self.assertEqual(normalize_product("Bosch", "video management system"), "VMS")

    def test_unknown_product_and_model_identifiers_are_preserved(self):
        self.assertEqual(normalize_product("Hikvision", "DS-2CD2043G2-I"), "DS-2CD2043G2-I")
        self.assertEqual(normalize_product("Dahua", "NVR5216-16P-I"), "NVR5216-16P-I")

    def test_identity_preserves_raw_evidence_and_marks_support(self):
        result = normalize_device_identity(
            "Hangzhou Hikvision Digital Technology Co., Ltd.",
            "network video recorder",
        )
        self.assertEqual(result["vendor_raw"], "Hangzhou Hikvision Digital Technology Co., Ltd.")
        self.assertEqual(result["vendor_normalized"], "Hikvision")
        self.assertEqual(result["product_raw"], "network video recorder")
        self.assertEqual(result["product_normalized"], "NVR")
        self.assertTrue(result["manufacturer_supported"])
        self.assertEqual(result["normalization"], "exact_alias")

    def test_catalogue_is_stable_and_complete_for_initial_scope(self):
        rows = supported_manufacturers()
        self.assertEqual(
            [row["canonical_name"] for row in rows],
            ["Axis Communications", "Bosch Security Systems", "Dahua",
             "Hanwha Vision", "Hikvision", "Uniview"],
        )
        self.assertTrue(all(row["aliases"] for row in rows))


if __name__ == "__main__":
    unittest.main()
