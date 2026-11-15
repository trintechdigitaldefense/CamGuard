# TrinTech CamGuard

**CCTV & IP Camera Cybersecurity Assessment**

CamGuard is an authorized, scope-limited network inventory and assessment tool from TrinTech Digital Defense.

## Current capabilities (0.2.0)

- Bounded TCP reachability inventory for common camera/NVR ports on explicitly authorized RFC1918 IPv4 scopes.
- Operator-supplied camera/NVR manufacturer, model, firmware and CPE inventory (JSON or CSV).
- Exact-match CVE correlation against a local advisory JSON file. Matching requires a verified inventory record, exact CPE equality and exact firmware-version equality.
- Transparent 0–100 triage scoring and asset-level highest-finding aggregation.
- JSON, Markdown and TrinTech-branded PDF reports.
- Automated unit tests and GitHub Actions workflow.

## Authorization and safety

Only assess devices and networks owned by you or covered by explicit written authorization. The `--authorized` flag is an operator attestation, not a substitute for written client consent.

- No exploitation, password guessing, brute force, authentication attempts, RTSP stream access, video collection, or configuration changes.
- No UDP scans, raw sockets, packet capture, or stealth functionality.
- Network scan scope is restricted to RFC1918 IPv4 and at most 256 addresses; concurrency and timeout are bounded.
- Device identity and firmware are **not inferred from open ports**. Enter data from client asset records, labels, vendor exports, or a technician's verified inspection.
- CVE matching is offline. CamGuard does not contact NVD or vendors automatically. Advisory data must be curated and checked against the original publisher.
- A match is a lead for analyst validation, not proof of exploitability or compromise.

## Install

Python 3.10+ is required.

```bash
git clone https://github.com/trintechdigitaldefense/CamGuard.git
cd CamGuard
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

## 1. Authorized network inventory

Replace the sample range with the exact private network in the signed scope document:

```bash
python -m camguard scan --cidr 192.168.10.0/28 --authorized --output-dir reports
```

This checks TCP reachability only. It does not log into devices or access video streams.

## 2. Device intelligence and CVE matching

Create an inventory JSON file. Manufacturer, model, firmware and CPE must be sourced from client records or verified technician inspection. Mark a record `verified: true` only after checking the source.

```json
{
  "devices": [
    {
      "ip": "192.168.10.20",
      "vendor": "Example Manufacturer",
      "model": "Camera Model X",
      "firmware": "1.2.3",
      "cpe": "cpe:2.3:o:example:camera_model_x_firmware:1.2.3:*:*:*:*:*:*:*",
      "source": "Client asset register checked against device label",
      "verified": true
    }
  ]
}
```

Create a local advisory JSON file:

```json
{
  "advisories": [
    {
      "cve": "CVE-2024-12345",
      "cpe": "cpe:2.3:o:example:camera_model_x_firmware:1.2.3:*:*:*:*:*:*:*",
      "affected_versions": ["1.2.3"],
      "cvss_base_score": 8.1,
      "source": "https://vendor.example/security-advisory",
      "summary": "Replace with the advisory publisher's verified summary."
    }
  ]
}
```

The example CVE and vendor data above are placeholders, **not a real vulnerability claim**. Replace them with validated advisory records before client use. Version matching is exact by design; ranges, aliases and vendor-specific version semantics require analyst review and are not guessed.

Run offline enrichment:

```bash
python -m camguard assess --inventory inventory.json --advisories advisories.json --output-dir reports
```

The command does not perform network probes. Manufacturer/model/firmware details are included as supplied and labelled by verification status.

## Risk scoring

- CVE findings: CVSS base score × 10.
- Reachable-service observations: conservative heuristic values (informational 10, low 30, medium 55).
- Asset score: highest finding score for that asset; scores are not added together.
- CVSS and heuristic scores are triage aids, not probability of compromise.
- Internet exposure, business impact, compensating controls and environmental exploitability are not currently assessed.

## Reports

Each run creates:
- `camguard-<timestamp>.json`
- `camguard-<timestamp>.md`
- `camguard-assessment.pdf` (TrinTech navy/cyan/emerald branding)

## Development

```bash
python -m unittest discover -s tests -v
python -m camguard --help
```

## Roadmap

1. Vendor-supported, non-invasive device metadata collection with explicit per-client approval.
2. Curated advisory ingestion with source provenance, freshness and version-range review.
3. Guided configuration hardening checklist.
4. Finding lifecycle, remediation evidence and historical comparisons.
5. Optional client-approved monitoring.

## TrinTech Digital Defense

Website: https://trintechdigitaldefense.github.io  
Phone: +1 (868) 362-0679
