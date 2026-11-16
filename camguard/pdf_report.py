"""Branded PDF report generation using ReportLab."""
from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether,
)


NAVY = colors.HexColor("#071426")
CYAN = colors.HexColor("#00CFE8")
GREEN = colors.HexColor("#00C58E")
PALE = colors.HexColor("#EAF3F8")


def write_pdf_report(result: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="BrandTitle", parent=styles["Title"], textColor=NAVY, fontSize=23, leading=27, alignment=TA_LEFT, spaceAfter=5))
    styles.add(ParagraphStyle(name="BrandSub", parent=styles["Normal"], textColor=CYAN, fontSize=10, leading=14, spaceAfter=12))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], textColor=NAVY, fontSize=14, leading=18, spaceBefore=12, spaceAfter=7))
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=11))
    styles.add(ParagraphStyle(name="Tiny", parent=styles["BodyText"], fontSize=7, leading=9, textColor=colors.HexColor("#526273")))
    safe = lambda value: escape(str(value))
    story = [
        Paragraph("TRINTECH DIGITAL DEFENSE", styles["BrandSub"]),
        Paragraph("CamGuard Security Assessment", styles["BrandTitle"]),
        Paragraph("DEFEND. DETECT. DOMINATE.", styles["BrandSub"]),
        Paragraph("Assessment overview", styles["Section"]),
    ]
    summary = [
        ["Assessment date (UTC)", result.get("generated_at", "Not recorded")],
        ["Authorized scope", result.get("scope", {}).get("cidr", "Inventory-only assessment")],
        ["Responsive assets", str(len(result.get("assets", [])))],
        ["Findings", str(len(result.get("findings", [])))],
        ["Assessment method", result.get("scan_type", "Inventory and advisory correlation")],
    ]
    table = Table(summary, colWidths=[48*mm, 118*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), PALE), ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"), ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#CBD7E1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story += [table, Paragraph("Asset inventory", styles["Section"])]
    asset_rows = [["IP address", "Manufacturer / model", "Firmware", "Risk"]]
    for asset in result.get("assets", []):
        ident = asset.get("identity", {})
        maker = " ".join(x for x in (ident.get("vendor"), ident.get("model")) if x) or "Not verified"
        asset_rows.append([asset.get("ip", ""), maker, ident.get("firmware") or "Unknown", f"{asset.get('risk_score', 0)} / 100"])
    if len(asset_rows) == 1:
        asset_rows.append(["No assets", "No inventory records", "—", "—"])
    at = Table(asset_rows, colWidths=[32*mm, 60*mm, 42*mm, 32*mm], repeatRows=1)
    at.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, -1), colors.white), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD7E1")),
        ("FONTSIZE", (0, 0), (-1, -1), 7), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(at)
    story.append(Paragraph("Findings and recommended actions", styles["Section"]))
    findings = result.get("findings", [])
    if not findings:
        story.append(Paragraph("No findings were generated from the supplied evidence.", styles["BodyText"]))
    for index, finding in enumerate(findings, 1):
        title = f"{index}. {finding.get('title', finding.get('cve', 'Finding'))} — {str(finding.get('severity', 'info')).upper()}"
        if finding.get("cve"):
            title = f"{index}. {finding['cve']} — {str(finding.get('severity', 'info')).upper()}"
        body = [
            f"<b>Asset:</b> {finding.get('asset_ip', 'N/A')}",
            f"<b>Risk score:</b> {finding.get('risk_score', 0)} / 100 — {finding.get('risk_rating', 'unscored')} (confidence: {finding.get('evidence_confidence', 'unknown')})",
            f"<b>Score components:</b> {finding.get('risk_components', {})}",
            f"<b>Why this score:</b> {escape('; '.join(finding.get('risk_explanation', [])))}",
            f"<b>Evidence:</b> {finding.get('evidence', finding.get('summary', 'Not supplied'))}",
            f"<b>Recommendation:</b> {finding.get('recommendation', 'Review vendor advisory and plan remediation.')}",
            f"<b>Source:</b> {finding.get('source', 'CamGuard observation')}",
        ]
        story.append(KeepTogether([Paragraph(title, styles["Heading4"]), Paragraph("<br/>".join(body), styles["Small"]), Spacer(1, 5)]))
    story.append(Paragraph("Scoring methodology and limitations", styles["Section"]))
    method = result.get("risk_methodology", {})
    methodology = [
        "<b>Formula:</b> " + safe(method.get("formula", "Risk scores are triage aids.")),
        "<b>Aggregation:</b> " + safe(method.get("aggregation", "Highest-scoring finding per asset.")),
        "<b>KEV uplift:</b> " + safe(method.get("kev_uplift", "Not specified.")),
        "<b>Exposure uplifts:</b> " + safe(method.get("exposure_uplifts", {})),
        "<b>Exposure policy:</b> " + safe(method.get("exposure_policy", "Unverified exposure is not scored.")),
        "<b>Service findings:</b> " + safe(method.get("service_findings", "Not specified.")),
        "<b>Evidence confidence:</b> " + safe(method.get("confidence", "Reported separately from score.")),
        "<b>Rating bands:</b> " + safe(method.get("ratings", {})),
    ]
    story.append(Paragraph("<br/>".join(methodology), styles["Small"]))
    for limitation in method.get("limitations", []):
        story.append(Paragraph("• " + safe(limitation), styles["Tiny"]))
    for limitation in result.get("limitations", []):
        story.append(Paragraph("• " + safe(limitation), styles["Tiny"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "CONFIDENTIAL CLIENT REPORT — Prepared by TrinTech Digital Defense. "
        "Findings depend on the supplied inventory, advisory data and authorized assessment scope. "
        "A score is a prioritization aid, not a guarantee of compromise or safety.",
        styles["Tiny"],
    ))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(CYAN)
        canvas.setLineWidth(1.2)
        canvas.line(18*mm, 15*mm, 192*mm, 15*mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(NAVY)
        canvas.drawString(18*mm, 10*mm, "TrinTech Digital Defense | CamGuard")
        canvas.drawRightString(192*mm, 10*mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=17*mm, bottomMargin=22*mm, title="TrinTech CamGuard Security Assessment", author="TrinTech Digital Defense")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return path
