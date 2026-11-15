import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from camguard.advisory_ingest import (
    AdvisoryIngestionError, _configurations, _cvss, _valid_cpe23, export_approved, ingest_sources,
)


class FakeResponse:
    status = 200
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def read(self, size=-1): return self.payload if size < 0 else self.payload[:size]


class AdvisoryIngestionTests(unittest.TestCase):
    def test_cpe23_validation_checks_component_count_and_part(self):
        self.assertTrue(_valid_cpe23("cpe:2.3:o:vendor:camera:1.0:*:*:*:*:*:*:*"))
        self.assertFalse(_valid_cpe23("cpe:2.3:o:vendor:camera"))
        self.assertFalse(_valid_cpe23("cpe:2.3:x:vendor:camera:1.0:*:*:*:*:*:*:*"))
        self.assertFalse(_valid_cpe23("cpe:2.3:o:vendor::1.0:*:*:*:*:*:*:*"))

    def test_extracts_cvss_and_preserves_version_bounds(self):
        cve = {
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "version": "3.1", "vectorString": "AV:N"}}]},
            "configurations": [{"nodes": [{"cpeMatch": [{
                "criteria": "cpe:2.3:o:vendor:camera:*:*:*:*:*:*:*:*", "vulnerable": True,
                "versionStartIncluding": "1.0", "versionEndExcluding": "2.0"
            }]}]}]
        }
        self.assertEqual(_cvss(cve)[0], 8.8)
        self.assertEqual(_configurations(cve)[0]["versionEndExcluding"], "2.0")

    def test_ingestion_writes_pending_not_approved(self):
        calls = []
        def opener(request, timeout=30):
            calls.append((request.full_url, next((value for key, value in request.header_items() if key.lower() == "apikey"), None)))
            if "nvd.nist.gov" in request.full_url:
                return FakeResponse({"totalResults": 1, "vulnerabilities": [{
                    "cve": {"id": "CVE-2026-1234", "published": "2026-01-01T00:00:00.000",
                            "lastModified": "2026-01-02T00:00:00.000",
                            "descriptions": [{"lang": "en", "value": "Test"}],
                            "metrics": {}, "configurations": [], "references": []}
                }]})
            return FakeResponse({"catalogVersion": "test", "dateReleased": "2026-01-02T00:00:00Z",
                                 "count": 1, "vulnerabilities": [{
                                     "cveID": "CVE-2026-1234", "vendorProject": "V",
                                     "product": "P", "vulnerabilityName": "N", "dateAdded": "2026-01-01",
                                     "shortDescription": "D", "requiredAction": "Patch", "dueDate": "2026-02-01"
                                 }]})
        with tempfile.TemporaryDirectory() as folder:
            paths = ingest_sources(folder, days=1, api_key="test-nvd-key", now=datetime(2026,1,3,tzinfo=timezone.utc), opener=opener)
            pending = json.loads(Path(paths["pending"]).read_text())
            self.assertTrue(pending["candidates"][0]["cisa_kev"])
            self.assertEqual(pending["candidates"][0]["review_status"], "pending")
            self.assertNotIn("advisories", pending)
            self.assertEqual(len(calls), 2)
            self.assertIsNotNone(calls[0][1])
            self.assertIsNone(calls[1][1])

    def test_rejects_invalid_cisa_dates(self):
        def opener(request, timeout=30):
            if "nvd.nist.gov" in request.full_url:
                return FakeResponse({"totalResults": 0, "vulnerabilities": []})
            return FakeResponse({"catalogVersion": "test", "dateReleased": "not-a-date",
                                 "count": 1, "vulnerabilities": [{"cveID": "CVE-2026-1234",
                                 "vendorProject": "V", "product": "P", "vulnerabilityName": "N",
                                 "dateAdded": "2026-01-01", "shortDescription": "D",
                                 "requiredAction": "Patch", "dueDate": "2026-02-01"}]})
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(AdvisoryIngestionError):
            ingest_sources(folder, days=1, now=datetime(2026,1,3,tzinfo=timezone.utc), opener=opener)

    def test_rejects_bad_kev_schema(self):
        def opener(request, timeout=30):
            if "nvd.nist.gov" in request.full_url:
                return FakeResponse({"totalResults": 0, "vulnerabilities": []})
            return FakeResponse({"count": 1, "vulnerabilities": []})
        with tempfile.TemporaryDirectory() as folder, self.assertRaises(AdvisoryIngestionError):
            ingest_sources(folder, days=1, now=datetime(2026,1,3,tzinfo=timezone.utc), opener=opener)

    def test_only_explicitly_approved_records_are_exported(self):
        approval = {"approvals": [
            {"cve": "CVE-2026-1234", "decision": "pending"},
            {"cve": "CVE-2026-1235", "decision": "approved", "cpe": "cpe:2.3:o:v:p:1:*:*:*:*:*:*:*",
             "affected_versions": ["1.0"], "reviewed_by": "Analyst", "reviewed_at": "2026-01-02T00:00:00Z",
             "cvss_base_score": 7.5, "source": "https://vendor.example/advisory", "summary": "Validated issue"}
        ]}
        with tempfile.TemporaryDirectory() as folder:
            src, dst = Path(folder)/"approvals.json", Path(folder)/"approved.json"
            src.write_text(json.dumps(approval))
            self.assertEqual(export_approved(str(src), str(dst)), 1)
            self.assertEqual(json.loads(dst.read_text())["advisories"][0]["cve"], "CVE-2026-1235")

    def test_approval_requires_exact_cpe_versions_and_reviewer(self):
        with tempfile.TemporaryDirectory() as folder:
            src, dst = Path(folder)/"approvals.json", Path(folder)/"approved.json"
            src.write_text(json.dumps({"approvals": [{"cve":"CVE-2026-1234","decision":"approved"}]}))
            with self.assertRaises(ValueError):
                export_approved(str(src), str(dst))


if __name__ == "__main__":
    unittest.main()
