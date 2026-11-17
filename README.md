# TrinTech CamGuard

**Authorized CCTV and IP-camera cybersecurity assessment**

CamGuard is a defensive assessment tool from **TrinTech Digital Defense**. It helps authorized security teams inventory reachable CCTV/NVR services, organize verified device information, correlate exact device and firmware identities with analyst-approved vulnerability intelligence, and produce explainable assessment reports.

<blockquote>
<strong>Current release:</strong> <code>0.5.0rc1</code> — public GitHub prerelease, not a stable 0.5.0 release.
</blockquote>

- **Release and wheel:** [CamGuard 0.5.0rc1](https://github.com/trintechdigitaldefense/CamGuard/releases/tag/0.5.0rc1)
- **Source code:** [GitHub repository](https://github.com/trintechdigitaldefense/CamGuard)
- **Business:** [TrinTech Digital Defense](https://trintechdigitaldefense.github.io)

## What CamGuard does

- Performs bounded TCP reachability checks and evidence-based service observations for common camera/NVR ports on explicitly authorized private IPv4 scopes.
- Accepts operator-supplied manufacturer, model, firmware and CPE inventory in JSON or CSV.
- Collects limited, unauthenticated HTTPS landing-page metadata when explicitly requested for approved private IP addresses.
- Retrieves public vulnerability intelligence from the NVD CVE API and CISA Known Exploited Vulnerabilities (KEV) catalogue into a review-only inbox.
- Requires analyst decisions, provenance and an integrity-checked audit trail before advisory records can be used for assessment.
- Correlates advisories only when device identity, CPE and firmware applicability meet strict exact-match requirements.
- Produces explainable 0–100 finding scores, asset priorities and separate evidence-confidence ratings.
- Generates JSON, Markdown and PDF reports.

CamGuard is an assessment and triage aid. It does not prove exploitability, compromise, or that a device is secure.

## Safety, authorization and limitations

Use CamGuard only on devices and networks you own or are explicitly authorized in writing to assess. The `--authorized` option is an operator attestation; it is not a replacement for written client permission or an agreed scope.

CamGuard is deliberately conservative:

- No exploitation, password guessing, brute force, authentication attempts, RTSP stream access, video collection or configuration changes.
- No UDP scanning, raw sockets, packet capture or stealth functionality.
- Network scan scope is restricted to RFC1918 IPv4 and at most 256 addresses; concurrency and timeouts are bounded.
- Metadata collection is a separate opt-in operation, restricted to at most 64 explicitly listed RFC1918 IPv4 addresses. It makes a limited unauthenticated HTTPS request, verifies TLS and does not follow redirects.
- Open ports and HTTP headers are not treated as proof of device identity. Manufacturer, model, firmware and CPE must come from client records, vendor exports, device labels or verified technician inspection.
- Assessment is offline. It does not call external APIs or probe devices while matching approved advisories.
- Feed ingestion downloads public NVD/CISA data, but candidates remain pending. Ingestion never automatically approves advisories or changes client assessment results.
- Vulnerability matching requires verified inventory and exact CPE plus firmware equality against analyst-approved records.
- A CVE match is a lead for analyst validation, not proof of exploitability or compromise.

## Install CamGuard 0.5.0rc1

**Recommended: install the published wheel.** Download `trintech_camguard-0.5.0rc1-py3-none-any.whl` from the [GitHub release](https://github.com/trintechdigitaldefense/CamGuard/releases/tag/0.5.0rc1), then run:

```bash
python -m pip install ./trintech_camguard-0.5.0rc1-py3-none-any.whl
camguard --help
```

Python 3.10 or newer is required. The release workflow built the wheel, checked it for private advisory/client data, installed it in a clean virtual environment, and verified the main, assessment and advisory-review CLI help commands.

To install from a source checkout instead:

```bash
git clone https://github.com/trintechdigitaldefense/CamGuard.git
cd CamGuard
python -m venv .venv
source .venv/bin/activate
python -m pip install .
python -m camguard --help
```

## Quick start

### 1. Authorized network inventory

Replace the example range with the exact private network in the written scope document:

```bash
camguard scan --cidr 192.168.10.0/28 --authorized --output-dir reports
```

The scan records reachability for each checked port. It makes a minimal unauthenticated HTTP HEAD request on ports 80/8080 and a TLS handshake attempt on 443/8443 to identify protocol evidence. Other ports remain unidentified unless positively confirmed. It does not log in to devices, access RTSP/video streams, or change configuration. Certificate trust is not evaluated by the TLS handshake observation.

### 2. Prepare verified device inventory

Create an inventory JSON file using values from client asset records or verified technician inspection. Do not mark a device verified unless its identity and firmware have been checked.

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

### 3. Run an offline assessment

Without advisory approvals:

```bash
camguard assess --inventory inventory.json --output-dir reports
```

To enable CVE matching, provide all three review inputs together:

```bash
camguard assess \
  --inventory inventory.json \
  --approvals data/advisories/approvals.json \
  --inbox data/advisories/inbox/pending-review.json \
  --audit data/advisories/review-audit.jsonl \
  --output-dir reports
```

CamGuard validates analyst decisions against the current pending inbox and hash-chained audit log, then loads a temporary validated advisory export. Supplying only one or two of the three review inputs is rejected. Assessment itself makes no external API calls or network probes.

## Vulnerability intelligence and analyst review

CamGuard ingests from two public sources:

- [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0)
- [CISA Known Exploited Vulnerabilities catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

Run a manual refresh (NVD lookback: 1–120 days; default 7):

```bash
camguard ingest-advisories --days 7 --output-dir data/advisories/inbox
```

An optional NVD API key may be supplied through the `NVD_API_KEY` environment variable. Do not put API keys in command-line arguments, source files, logs or pull requests. Retrieval is paginated, paced, retried on transient errors and validated before publication. Failed retrieval or validation does not replace the previous inbox.

The ingestion workflow can also run through GitHub Actions and opens or updates a review pull request. It does not commit directly to `main` or approve candidates.

### Review candidates

```bash
camguard review-advisories list --limit 50
camguard review-advisories list --query "Hikvision" --limit 25
camguard review-advisories list --kev-only --limit 50
```

Record a decision only after checking the original vendor advisory and confirming the exact product and firmware. Example rejection:

```bash
camguard review-advisories decide \
  --cve CVE-2026-12345 --decision rejected \
  --reviewed-by "analyst-id" \
  --evidence-url "https://vendor.example/security/advisory" \
  --rationale "Vendor bulletin does not list this camera model."
```

Example approval (replace all example values with verified evidence):

```bash
camguard review-advisories decide \
  --cve CVE-2026-12345 --decision approved \
  --reviewed-by "analyst-id" \
  --evidence-url "https://vendor.example/security/advisory" \
  --rationale "Vendor bulletin confirms this exact model and firmware." \
  --cpe "cpe:2.3:o:vendor:camera:1.2.3:*:*:*:*:*:*:*" \
  --affected-version "1.2.3"
```

Every decision is appended to `data/advisories/review-audit.jsonl`. Verify its integrity:

```bash
camguard review-advisories verify-audit
```

The SHA-256 audit chain is **tamper-evident, not immutable**. Protect the approvals and audit files with appropriate access controls and independent backups. Do not discard historical audit records.

Export validated approvals:

```bash
camguard export-approved \
  --approvals data/advisories/approvals.json \
  --inbox data/advisories/inbox/pending-review.json \
  --audit data/advisories/review-audit.jsonl \
  --output data/advisories/approved-advisories.json
```

The exporter rejects stale or altered approvals, mismatched CPE applicability, missing reviewer/rationale metadata, invalid source evidence and approvals without a matching latest audit event. NVD approval requires source CPE criteria explicitly marked `vulnerable: true`. The approved CPE must identify a concrete version, and affected firmware versions cannot be wildcards. KEV-only entries require independent vendor evidence. NVD CVSS values must be retained from NVD; KEV-only CVSS values require a cited source.

Approvals created before complete-record digest binding was introduced must be re-reviewed before export. Preserve the historical audit chain and re-review still-valid decisions to create new digest-bound events.

**Keep all client inventories, advisory inboxes, approvals, audit logs and other private review data out of public commits.** The repository includes an example approval template; it is not a place to store client records.

## Risk prioritization

For an exact, verified device CPE and firmware match against an analyst-approved advisory, CamGuard calculates:

- CVSS base score × 10, rounded to an integer.
- CISA KEV uplift: +10 when the approved advisory is listed in the current CISA KEV catalogue.
- Verified network exposure uplift: internet-exposed +15; internal segment +5; isolated +0; unknown +0.
- Final score: sum of components, capped at 100.
- Asset priority: highest-scoring finding; findings are not added together.

Exposure is optional operator-supplied inventory context. Use `network_exposure` with `internet_exposed`, `internal_segment`, `isolated` or `unknown`; set `network_exposure_verified: true` only when supported by current client network evidence, and include `network_exposure_source`. CamGuard never infers internet exposure from a private-scope scan. Unverified or unknown exposure receives no uplift.

Severity bands are Critical (90–100), High (70–89), Medium (40–69), Low (1–39) and Informational (0). Evidence confidence is reported separately from severity. A zero score does not prove an asset is safe. The model does not currently score business criticality, compensating controls, exploitability in the client environment or active compromise.

## Reports

Assessment runs produce timestamped JSON and Markdown reports and a PDF report:

- `camguard-<timestamp>.json`
- `camguard-<timestamp>.md`
- `camguard-assessment.pdf`

Reports include finding/asset scores, score components, evidence confidence, explanations and limitations. Treat reports as client-confidential information.

## Additional commands

### Controlled HTTPS metadata collection

Metadata collection is opt-in and separate from the TCP scanner. Create a text file with one explicitly approved RFC1918 IPv4 address per line:

```bash
camguard metadata --targets targets.txt --authorized --output metadata.json
```

The initial signature set covers Axis, Hikvision, Dahua, Hanwha Vision and Uniview. It makes one unauthenticated HTTPS `GET /` request per approved IP, disables redirects, caps the response body and verifies TLS certificates. It does not access vendor APIs, ONVIF actions, RTSP streams, configuration endpoints or authentication pages intentionally. Server-header and page-title signatures are weak indicators, not proof of identity; model and firmware are never inferred.

### Manufacturer normalization

```bash
camguard manufacturer-catalog
camguard normalize-device --vendor "Hikvision Digital Technology Co., Ltd." --product "network video recorder"
```

Normalization uses exact aliases after case and punctuation normalization. Unknown names are not fuzzy-matched, and model identifiers are preserved. This local aid makes no network requests and does not modify inventory or approvals.

## Development and tests

From the source checkout with the development environment active:

```bash
python -m unittest discover -s tests -v
python -m camguard --help
python -m camguard assess --help
python -m camguard review-advisories --help
```

The project targets Python 3.10+. Run tests with synthetic data; never use real client inventories or private analyst records as public test fixtures.

## Roadmap

- **0.6.0 development:** initial evidence-based service exposure observations are implemented on the [development pull request](https://github.com/trintechdigitaldefense/CamGuard/pull/10). See the [design and implementation notes](docs/roadmap/0.6.0-service-exposure-assessment.md). This work is not included in the published 0.5.0rc1 release.
- **0.7.0 development:** technician-assisted inspection data model, six CCTV security checklists, evidence-reference handling and inspection report integration are being developed on a separate feature branch. See [the 0.7.0 inspection specification](docs/roadmap/0.7.0-technician-assisted-inspection.md). Not part of the published 0.5.0rc1 release.
- Guided camera/NVR configuration-hardening checklist.
- Finding lifecycle, remediation evidence and historical comparisons.
- Optional client-approved monitoring and alerting.

## TrinTech Digital Defense

Website: https://trintechdigitaldefense.github.io  
Phone: +1 (868) 362-0679

CamGuard is proprietary software. Use is limited to authorized defensive assessment and the terms agreed with TrinTech Digital Defense.
