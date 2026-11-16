# Changelog

All notable changes to TrinTech CamGuard are documented here.

## 0.5.0rc1 — Release candidate

This release candidate consolidates the advisory workflow with manufacturer normalization, explainable CCTV risk prioritization, and subsequent security-hardening changes.

### Added
- Explainable 0–100 finding and asset risk prioritization, with separate evidence confidence.
- Conservative manufacturer and product-family normalization for supported CCTV vendors.
- Audit-bound analyst approval records with complete-record SHA-256 digests.
- Validation that only NVD CPE criteria explicitly marked `vulnerable: true` support approval.
- Assessment CLI approval boundary requiring the approvals file, current inbox and audit log together.
- Regression coverage for approval tampering, audit integrity, PDF escaping and temporary-file cleanup.

### Security and operational notes
- CVE matching remains offline and requires exact verified device CPE and firmware applicability.
- Advisory candidates remain pending until analyst review; ingestion never auto-approves records.
- The audit chain is tamper-evident, not immutable. Protect audit files and independent backups.
- Approvals created before complete-record digest binding must be re-reviewed before export. Preserve the historical audit chain.
- Network exposure uplifts apply only to verified, operator-supplied context. CamGuard does not infer internet exposure from a private scan.

### Release-candidate validation still required
- Clean-environment installation and package build.
- Full unit-test suite and CLI smoke tests on the release-candidate branch.
- JSON, Markdown and PDF report smoke tests using synthetic fixtures.
- Confirmation that no customer inventory, advisory inbox, approvals or audit data is included in the release.
- Final review of README procedures and release artifacts.

This is a release candidate, not a production release.
