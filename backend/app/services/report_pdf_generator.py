import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

REPORTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

class ReportCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Top Header (on pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 11 * inch - 36, "ThreatLens Cyber Threat Intelligence Analysis Report")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Footer
        footer_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 36, footer_text)
        self.drawString(54, 36, "CONFIDENTIAL // CYBER DEFENSE INTELLIGENCE ASSESSMENT")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 48, 8.5 * inch - 54, 48)
        self.restoreState()

def get_report_styles():
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "RptTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0B1739"),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        "RptSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748B"),
        spaceAfter=14
    )
    h1_style = ParagraphStyle(
        "RptH1",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0B1739"),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "RptBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=6
    )
    callout_style = ParagraphStyle(
        "RptCallout",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#334155"),
        backColor=colors.HexColor("#F8FAFC"),
        borderPadding=6,
        spaceAfter=8
    )
    return {
        "title": title_style,
        "subtitle": subtitle_style,
        "h1": h1_style,
        "body": body_style,
        "callout": callout_style
    }

class ReportPdfGenerator:
    """Generates official downloadable PDF threat analysis reports using ReportLab."""

    @classmethod
    def generate_scan_report(cls, scan_data: Dict[str, Any]) -> str:
        scan_id = scan_data.get("id", "UNKNOWN")
        filename = f"ThreatLens_Report_{scan_id[:8].upper()}.pdf"
        filepath = REPORTS_DIR / filename

        s = get_report_styles()
        story = []

        sev = scan_data.get("severity", "Informational")
        sev_color = colors.HexColor("#059669")
        if sev == "Critical":
            sev_color = colors.HexColor("#DC2626")
        elif sev == "High":
            sev_color = colors.HexColor("#EA580C")
        elif sev == "Medium":
            sev_color = colors.HexColor("#D97706")
        elif sev == "Low":
            sev_color = colors.HexColor("#2563EB")

        # Header Title
        story.append(Paragraph("ThreatLens — Intelligence & Threat Detection Report", s["title"]))
        meta_sub = f"Scan ID: {scan_id} | Document: {scan_data.get('filename')} | Timestamp: {scan_data.get('scan_timestamp', datetime.now(timezone.utc).isoformat())}"
        story.append(Paragraph(meta_sub, s["subtitle"]))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=12))

        # Executive Metadata Summary Table
        meta_table_data = [
            ["Metric / Attribute", "Evaluation Value", "Severity Level", "Triage Assessment"],
            ["Target Document", scan_data.get("filename", "N/A"), "Overall Threat Tier", sev.upper()],
            ["Document Format", f"{scan_data.get('file_type')} ({scan_data.get('page_count', 1)} pages, {scan_data.get('word_count', 0)} words)", "Predicted Category", scan_data.get("predicted_category", "Unknown")],
            ["Detection Engine", scan_data.get("detection_method", "Hybrid Engine"), "Confidence Score", f"{float(scan_data.get('confidence', 0.0)):.2%}"],
            ["Analysis Runtime", f"{float(scan_data.get('processing_duration', 0.0)):.2f} seconds", "Findings Identified", str(scan_data.get("finding_count", 0))]
        ]
        story.append(Table(meta_table_data, colWidths=[130, 160, 100, 114], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0B1739")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#F8FAFC")),
            ('TEXTCOLOR', (3,1), (3,1), sev_color),
            ('FONTNAME', (3,1), (3,1), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('TOPPADDING', (0,0), (-1,-1), 4),
        ]), spaceAfter=14))

        # 1. Executive Summary
        story.append(Paragraph("1. Executive Summary", s["h1"]))
        exec_text = (
            f"ThreatLens conducted multi-stage automated natural language processing and heuristic rule inspection "
            f"on document '{scan_data.get('filename')}'. The analysis resulted in an assessed overall threat severity of "
            f"<b>{sev}</b> with {scan_data.get('finding_count', 0)} discrete indicator(s) identified. "
            f"Classification model attributed the content to <b>{scan_data.get('predicted_category')}</b>."
        )
        story.append(Paragraph(exec_text, s["body"]))

        # 2. Findings Table
        findings = scan_data.get("findings", [])
        story.append(Paragraph("2. Detailed Findings & Suspicious Passages", s["h1"]))
        if findings:
            find_rows = [["Type", "Page", "Severity", "Evidence Snippet", "Recommended Action"]]
            for f in findings[:10]:  # limit to top 10 in PDF
                evidence_clean = str(f.get("evidence", ""))[:65] + ("..." if len(str(f.get("evidence", ""))) > 65 else "")
                rec_clean = str(f.get("recommended_action", ""))[:55] + ("..." if len(str(f.get("recommended_action", ""))) > 55 else "")
                find_rows.append([
                    f.get("finding_type", "Finding"),
                    f"Pg {f.get('page_number', 1)}",
                    f.get("severity", "Medium"),
                    evidence_clean,
                    rec_clean
                ])
            story.append(Table(find_rows, colWidths=[100, 35, 55, 160, 154], style=TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2563EB")),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
                ('BACKGROUND', (0,1), (-1,-1), colors.white),
                ('FONTSIZE', (0,0), (-1,-1), 7.5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                ('TOPPADDING', (0,0), (-1,-1), 3),
            ]), spaceAfter=12))
        else:
            story.append(Paragraph("No significant suspicious indicators or malicious patterns were observed across the document text.", s["callout"]))

        # 3. Recommended Actions
        story.append(Paragraph("3. Recommended Containment & Remediation Playbook", s["h1"]))
        recs = scan_data.get("recommended_actions", [])
        if recs:
            for r in recs:
                story.append(Paragraph(f"• {r}", s["body"]))
        else:
            story.append(Paragraph("• Standard corporate security baseline monitoring applies. No urgent containment required.", s["body"]))

        # 4. Limitations of Automated Detection
        story.append(Paragraph("4. Automated Analysis Disclosures & Limitations", s["h1"]))
        story.append(Paragraph(
            "• Assessments are derived from natural language tokenization, statistical machine learning models, and heuristic rule matching.\n"
            "• Absence of threat indicators does not guarantee that a document is completely benign, particularly in cases of steganography or password-protected content.\n"
            "• High-severity determinations should be corroborated by SOC analysts through organizational telemetry and SIEM/EDR logs.",
            s["callout"]
        ))

        # Build document
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )
        doc.build(story, canvasmaker=ReportCanvas)
        return str(filepath)
