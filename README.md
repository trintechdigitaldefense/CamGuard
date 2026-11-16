# TrinTech CamGuard

**CCTV & IP Camera Cybersecurity Assessment**

CamGuard is an authorized, scope-limited network inventory and assessment tool from TrinTech Digital Defense.

## Current capabilities (0.4.0)

- Bounded TCP reachability inventory for common camera/NVR ports on explicitly authorized RFC1918 IPv4 scopes.
- Operator-supplied camera/NVR manufacturer, model, firmware and CPE inventory (JSON or CSV).
- Exact-match CVE correlation against analyst-approved advisory records, requiring verified inventory, exact CPE equality and exact firmware-version equality.
- Evidence-backed read-only HTTPS metadata indicators for five camera manufacturers, with explicit confidence levels.
- Daily NVD CVE API 2.0 and CISA KEV ingestion into a review-only pull request; analyst-gated approvals and provenance.
- Transparent 0–100 triage scoring and asset-level highest-finding aggregation.
- JSON, Markdown and TrinTech-branded PDF reports.
- Automated unit tests and GitHub Actions workflow.

## Authorization and safety

Only assess devices and networks owned by you or covered by explicit written authorization. The `--authorized` flag is an operator attestation, not a substitute for written client consent.

- No exploitation, password guessing, brute force, authentication attempts, RTSP stream access, video collection, or configuration changes.
- No UDP scans, raw sockets, packet capture, or stealth functionality.
- Network scan scope is restricted to RFC1918 IPv4 and at most 256 addresses; concurrency and timeout are bounded.
- Device identity and firmware are **not inferred from open ports**. Enter data from client asset records, labels, vendor exports, or a technician's verified inspection.
- CVE matching remains offline and only uses analyst-approved advisory records. The ingestion workflow retrieves public NVD and CISA KEV data into a review inbox; it never promotes candidates automatically.
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


## Controlled read-only metadata collection (0.3.0)

Metadata collection is opt-in and separate from the TCP scanner. Create a text file with one explicitly approved RFC1918 IPv4 address per line, then run:

```bash
python -m camguard metadata --targets targets.txt --authorized --output metadata.json
```

The initial signature set covers Axis, Hikvision, Dahua, Hanwha Vision and Uniview. It makes exactly one unauthenticated HTTPS `GET /` request per approved IP, disables redirects, caps the response body, and verifies TLS certificates. Cleartext HTTP is not supported. It does not access vendor APIs, ONVIF actions, RTSP streams, configuration endpoints, or authentication pages intentionally.

Each result records the request, timestamp, HTTP status, limited Server header, page title, evidence and confidence. A vendor signature in the Server header is **medium** confidence; a signature only in the HTML title is **low**; no signature is **none**. These are weak fingerprint indicators, not proof of device identity. Model and firmware are never inferred. Corroborate manufacturer/model/firmware against labels, vendor exports or client asset records before CVE matching. TLS failures and access-denied responses are not bypassed.

The command requires `--authorized`, accepts at most 64 explicit IPs, and restricts targets to RFC1918 IPv4. The flag is an attestation, not a substitute for written client permission.

## Maintained CVE advisory ingestion (0.4.0)

CamGuard ingests from two authoritative sources:
- NVD CVE API 2.0: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- CISA KEV JSON catalogue: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

Run a manual refresh (NVD lookback is 1–120 days; default 7):

```bash
python -m camguard ingest-advisories --days 7 --output-dir data/advisories/inbox
```

An optional NVD API key can be supplied through the `NVD_API_KEY` environment variable. Do not put API keys in command-line arguments, source files, logs or pull requests. Requests are paginated, paced conservatively, retried on transient errors and validated before files are replaced. The previous inbox remains intact if retrieval or validation fails before publication.

The ingestion produces:
- `pending-review.json`: NVD records in the modified window, CVSS metadata, source references and raw CPE applicability/version bounds for analyst review; KEV status is attached where available.
- `kev-catalog.json`: validated CISA KEV catalogue snapshot.
- `manifest.json`: source URLs, retrieval time, NVD query window, CISA catalog version and record counts.

CISA KEV entries outside the NVD modified window are retained separately in the pending file. KEV membership means CISA lists the CVE as known exploited; it does **not** prove a particular camera model or firmware is affected.

### Analyst approval gate

The scheduled GitHub Actions workflow runs daily at 07:17 UTC and can also be started manually. It opens or updates a pull request containing pending feed data. It does not commit directly to `main`, publish approved advisories, or change client assessment results.

#### Local analyst review CLI

Review data stays on the operator's machine by default. List a page of pending candidates, search by CVE/vendor/product/description, or focus on KEV-only entries:

```bash
python -m camguard review-advisories list --limit 50
python -m camguard review-advisories list --query "Hikvision" --limit 25
python -m camguard review-advisories list --kev-only --limit 50
```

Record a rejection or return an item to pending with a reviewer identity, HTTPS evidence URL and rationale:

```bash
python -m camguard review-advisories decide \
  --cve CVE-2026-12345 --decision rejected \
  --reviewed-by "analyst-id" \
  --evidence-url "https://vendor.example/security/advisory" \
  --rationale "Vendor advisory does not list this camera model."
```

Approve only after confirming the exact product and firmware against the vendor advisory. Supply the exact CPE and repeat `--affected-version` for each explicitly affected firmware version:

```bash
python -m camguard review-advisories decide \
  --cve CVE-2026-12345 --decision approved \
  --reviewed-by "analyst-id" \
  --evidence-url "https://vendor.example/security/advisory" \
  --rationale "Vendor bulletin confirms this exact model and firmware." \
  --cpe "cpe:2.3:o:vendor:camera:1.2.3:*:*:*:*:*:*:*" \
  --affected-version "1.2.3"
```

Every decision is appended to `data/advisories/review-audit.jsonl`, a SHA-256 hash-chained log. Verify its integrity before export:

```bash
python -m camguard review-advisories verify-audit
```

The log is tamper-evident, not an immutable external archive; protect and back it up with the approvals file. Decisions are checked against the current pending inbox. For NVD candidates, the approved CPE must satisfy the source CPE applicability (all non-version source attributes must match; source wildcards may be resolved by the analyst). The approved CPE must contain a concrete version, and affected firmware versions cannot be wildcards. KEV-only entries have no NVD CPE applicability and therefore rely on independent vendor evidence; a CVSS score must still be available before approval.

Export requires the matching inbox and audit log:

```bash
python -m camguard export-approved \
  --approvals data/advisories/approvals.json \
  --inbox data/advisories/inbox/pending-review.json \
  --audit data/advisories/review-audit.jsonl \
  --output data/advisories/approved-advisories.json
```

The exporter rejects approvals absent from the inbox, mismatched CPE applicability, altered CVSS scores, missing rationale/reviewer metadata, or decisions without a matching latest approved audit event. Rejected and pending decisions are never exported. Keep generated inboxes, approvals, audit logs and client-specific review data out of public commits unless a deliberate, access-controlled review process requires them.

1. Analyst opens each candidate's NVD record and original vendor advisory.
2. Confirm the exact product/model and interpret the vendor's affected-version statement. Do not copy an NVD version range into an exact-version list without reviewing its meaning.
3. Add a decision to `data/advisories/approvals.json`. The template is `data/advisories/approvals.example.json`. Use `decision: "approved"` only after review; otherwise leave it pending or mark it rejected.
4. For approved records, provide an exact CPE, explicit affected firmware versions, CVSS base score, HTTPS source, summary, reviewer identifier and ISO-8601 review timestamp. Set `kev: true` only when the CVE appears in the current CISA catalogue.
5. Validate and export:

```bash
python -m camguard export-approved --approvals data/advisories/approvals.json --output data/advisories/approved-advisories.json
```

6. Have a second authorized reviewer inspect the approval change in GitHub before merging. Configure repository branch protection to require at least one independent review and passing status checks; do not allow self-approval for production advisory changes.

Only records with `decision: "approved"` are exported. The exporter rejects missing reviewer metadata, invalid CVE IDs, missing exact CPEs, empty affected-version lists, invalid CVSS scores, and non-HTTPS source references. The existing assessment matcher still requires verified device inventory and exact CPE plus firmware equality. Pending feed candidates are not accepted as the approved `advisories` dataset.

The scheduled job needs no secrets for public feeds. An optional repository Actions secret named `NVD_API_KEY` improves NVD request allowance. GitHub Actions uses the repository's `GITHUB_TOKEN` to open the review pull request with only the permissions declared in the workflow. Feed failures fail the job and do not replace the previous inbox.

## Development

```bash
python -m unittest discover -s tests -v
python -m camguard --help
```

## Roadmap

1. Guided camera/NVR configuration hardening checklist.
2. Finding lifecycle, remediation evidence and historical comparisons.
3. Optional client-approved monitoring and alerting.

## TrinTech Digital Defense

Website: https://trintechdigitaldefense.github.io  
Phone: +1 (868) 362-0679
