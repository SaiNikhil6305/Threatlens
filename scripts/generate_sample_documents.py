import os
import json
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_documents"
SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

class NumberedCanvas(canvas.Canvas):
    """Canvas that adds running header and 'Page X of Y' footer."""
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
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 11 * inch - 36, "ThreatLens Test Document Suite — Verification Artifact")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Footer
        footer_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 36, footer_text)
        self.drawString(54, 36, "CONFIDENTIAL / INTERNAL VERIFICATION")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 48, 8.5 * inch - 54, 48)
        self.restoreState()

def get_styles():
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=30,
        textColor=colors.HexColor("#0B1739"),
        spaceAfter=12
    )
    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#64748B"),
        spaceAfter=24
    )
    h1_style = ParagraphStyle(
        "DocH1",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#0B1739"),
        spaceBefore=14,
        spaceAfter=8
    )
    h2_style = ParagraphStyle(
        "DocH2",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#2563EB"),
        spaceBefore=10,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        "DocBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=8
    )
    callout_style = ParagraphStyle(
        "DocCallout",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#334155"),
        backColor=colors.HexColor("#F1F5F9"),
        borderPadding=8,
        spaceAfter=10
    )
    return {
        "title": title_style,
        "subtitle": subtitle_style,
        "h1": h1_style,
        "h2": h2_style,
        "body": body_style,
        "callout": callout_style
    }

def build_pdf(filepath: Path, elements: list):
    doc = SimpleDocTemplate(
        str(filepath),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    doc.build(elements, canvasmaker=NumberedCanvas)
    print(f"[+] Generated: {filepath.name}")

def generate_safe_company_policy(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Global Enterprise Information Security Policy", s["title"]),
        Paragraph("Version 4.2 | Classification: Internal | Annual Review Cycle", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=18),
        Paragraph("Executive Overview", s["h1"]),
        Paragraph(
            "This corporate security policy establishes mandatory controls, operational boundaries, and governance "
            "standards for safeguarding enterprise information assets, customer privacy, and distributed infrastructure. "
            "All full-time employees, contractors, and third-party vendors are required to adhere to these mandates without exception.",
            s["body"]
        ),
        Paragraph("Scope and Applicability", s["h2"]),
        Paragraph(
            "The controls documented herein apply across all cloud tenants, physical branch offices, remote developer workstations, "
            "and production Kubernetes clusters. Compliance audits are performed biannually in accordance with ISO/IEC 27001 "
            "and SOC 2 Type II assurance criteria.",
            s["body"]
        ),
        Spacer(1, 15),
        Table([
            ["Standard", "Governance Framework", "Status", "Audit Cycle"],
            ["ISO/IEC 27001:2022", "Information Security Management", "Certified", "Annual Recertification"],
            ["AICPA SOC 2 Type II", "Trust Services Criteria", "Compliant", "Continuous Monitoring"],
            ["NIST CSF 2.0", "Core Security Profiles", "Aligned", "Quarterly Self-Assessment"],
            ["GDPR / CCPA", "Data Privacy & Data Residency", "Enforced", "Ongoing DPO Oversight"]
        ], colWidths=[120, 180, 80, 120], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0B1739")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 9),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#F8FAFC")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,1), (-1,-1), 8.5),
        ])),
        PageBreak(),

        # Page 2
        Paragraph("Section 2: Credential & Password Management Standards", s["h1"]),
        Paragraph(
            "Password complexity and authentication safety are foundational pillars of our Zero-Trust architecture. "
            "To mitigate credential spraying, rainbow table attacks, and unauthorized token reuse, all accounts must satisfy the following:",
            s["body"]
        ),
        Paragraph("1. Multi-Factor Authentication (MFA)", s["h2"]),
        Paragraph(
            "Hardware-backed FIDO2/WebAuthn security keys or enterprise Authenticator apps with number-matching prompts are strictly mandatory "
            "for accessing single sign-on (SSO) portals. SMS and voice call verification are deprecated and prohibited due to SIM-swapping vulnerabilities.",
            s["body"]
        ),
        Paragraph("2. Password Hygiene & Passphrase Guidelines", s["h2"]),
        Paragraph(
            "Master passphrases must comprise a minimum of 16 characters including alphanumeric and approved symbol sets. "
            "Employees must utilize the corporate password manager to generate distinct, pseudo-random credentials for every external service. "
            "Under no circumstances will IT staff or administrators request your plaintext password via email, ticket, or phone.",
            s["callout"]
        ),
        Paragraph("3. Session Inactivity and Token Expiration", s["h2"]),
        Paragraph(
            "Interactive web sessions expire automatically after 8 hours of inactivity. Mobile device management (MDM) profiles enforce "
            "workstation screen locking after 5 minutes of idle time with biometric re-authentication required.",
            s["body"]
        ),
        PageBreak(),

        # Page 3
        Paragraph("Section 3: Incident Reporting & Responsibilities", s["h1"]),
        Paragraph(
            "Prompt incident notification enables the Security Operations Center (SOC) to isolate compromised endpoints, revoke active tokens, "
            "and prevent lateral movement across enterprise subnets.",
            s["body"]
        ),
        Paragraph("Reporting Procedures", s["h2"]),
        Paragraph(
            "If you suspect that your endpoint has encountered suspicious behavior, unsolicited prompts, or potential data loss:",
            s["body"]
        ),
        Paragraph("• Immediately use the 'Report Phish' button in your corporate mail client.", s["body"]),
        Paragraph("• Contact the 24/7 SOC Hotline via internal chat `#security-ops` or phone extension `4433`.", s["body"]),
        Paragraph("• Do not power off the machine; disconnect Wi-Fi or Ethernet cable to preserve memory artifacts for forensics.", s["body"]),
        Spacer(1, 10),
        Paragraph("Sanctions for Non-Compliance", s["h2"]),
        Paragraph(
            "Intentional circumvention of security controls, disabling endpoint detection agents, or sharing enterprise credentials "
            "subjects personnel to disciplinary review up to and including termination of employment and legal escalation.",
            s["body"]
        ),
        Paragraph("Policy Sign-off & Revision Record", s["h2"]),
        Paragraph("Approved by: Chief Information Security Officer (CISO) | Effective Date: January 15, 2026", s["callout"])
    ]
    build_pdf(filepath, story)

def generate_safe_project_report(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Project Apollo: Modern Threat Intelligence Pipeline", s["title"]),
        Paragraph("Engineering Architecture & Technical Delivery Report | Q1 Milestone", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=18),
        Paragraph("Executive Summary", s["h1"]),
        Paragraph(
            "Project Apollo delivers an asynchronous, low-latency microservices pipeline designed to ingest, normalize, and score "
            "external threat telemetry feeds. This engineering report outlines the architectural choices, benchmarking metrics, "
            "and production readiness findings gathered during the Phase II performance testing cycles.",
            s["body"]
        ),
        Paragraph("Core Architectural Components", s["h2"]),
        Paragraph(
            "The architecture consists of three containerized subsystems deployed across a high-availability AWS EKS cluster: "
            "an Apache Kafka event ingestion bus, a Python FastAPI stream processor with spaCy NLP pipelines, and a TimescaleDB analytical warehouse.",
            s["body"]
        ),
        Spacer(1, 15),
        Table([
            ["Component", "Technology", "Replica Count", "Target Latency SLA"],
            ["Ingestion Gateway", "Go / Fiber", "4 Pods", "< 15 ms"],
            ["NLP Parser", "Python / spaCy 3.8", "8 Pods", "< 120 ms"],
            ["Storage Tier", "PostgreSQL / Timescale", "Primary + 2 Read", "< 45 ms"],
            ["Cache / Queue", "Redis Enterprise", "3-node Cluster", "< 5 ms"]
        ], colWidths=[120, 160, 100, 120], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0B1739")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor("#F8FAFC")),
            ('FONTSIZE', (0,0), (-1,-1), 8.5)
        ])),
        PageBreak(),

        # Page 2
        Paragraph("Methodology and Implementation Details", s["h1"]),
        Paragraph(
            "Data ingestion adheres to the STIX 2.1 JSON standard. Inbound telemetry is validated against JSON schema definitions, "
            "sanitized for illegal control characters, and pushed to partitioned Kafka topics organized by source feed.",
            s["body"]
        ),
        Paragraph("Stream Processing & Parsing Efficiency", s["h2"]),
        Paragraph(
            "Text tokenization benchmarks achieved 1,450 documents per second per worker utilizing multi-process worker pools. "
            "Memory utilization remained stable below 750 MB per container under simulated peak volumetric loads of 10,000 requests/sec.",
            s["body"]
        ),
        Paragraph("Database Partitioning Strategy", s["h2"]),
        Paragraph(
            "Telemetry indicators are partitioned by weekly intervals with automated tiering to Amazon S3 Glacier after 90 days. "
            "B-tree indices on normalized indicator hashes ensure sub-50ms lookup times for active SOC analyst triage queries.",
            s["body"]
        ),
        PageBreak(),

        # Page 3
        Paragraph("Verification Results & Production Sign-off", s["h1"]),
        Paragraph(
            "Automated integration tests executed over 500 simulated scenarios with zero unhandled exceptions. "
            "Chaos engineering experiments validated automated pod self-healing within 12 seconds of forced node termination.",
            s["body"]
        ),
        Paragraph("Testing Metrics Table", s["h2"]),
        Table([
            ["Test Scenario", "Iterations", "Pass Rate", "Mean Response"],
            ["Volumetric Burst (10k req/s)", "5 Runs", "100.0%", "38 ms"],
            ["Malformed Payload Rejection", "1,200 Cases", "100.0%", "4 ms"],
            ["Database Failover Simulation", "3 Drills", "100.0%", "8.2 s recovery"],
            ["End-to-End Ingestion Pipeline", "50,000 Msgs", "99.98%", "112 ms"]
        ], colWidths=[160, 100, 100, 140], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2563EB")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8.5)
        ]), spaceAfter=15),
        Paragraph("Conclusion & Rollout Approval", s["h2"]),
        Paragraph(
            "Project Apollo has passed all security, resilience, and performance criteria. Production rollout is scheduled for Tuesday, "
            "October 20, 2026, during the standard enterprise maintenance window.",
            s["callout"]
        )
    ]
    build_pdf(filepath, story)

def generate_safe_security_awareness(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Security Awareness Training: Recognizing Modern Phishing", s["title"]),
        Paragraph("Course ID: SEC-101 | Department of Cyber Defense & Employee Education", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=18),
        Paragraph("Module 1: The Anatomy of Social Engineering", s["h1"]),
        Paragraph(
            "Phishing remains the primary vector utilized by adversaries to initiate unauthorized entry into enterprise systems. "
            "This educational training document breaks down common manipulation tactics so team members can safely recognize, "
            "defend against, and report suspicious lures without panic.",
            s["body"]
        ),
        Paragraph("What is Phishing?", s["h2"]),
        Paragraph(
            "Phishing is a deceptive social engineering technique where attackers impersonate trusted institutions—such as IT support, "
            "HR representatives, or executive leadership—to manipulate recipients into revealing credentials, downloading malicious attachments, "
            "or authorizing fraudulent financial wire transfers.",
            s["body"]
        ),
        Paragraph("The Four Hallmarks of Deception", s["h2"]),
        Paragraph("1. **Manufactured Urgency**: Threats of account suspension within 24 hours.", s["body"]),
        Paragraph("2. **Artificial Authority**: Impersonation of C-level executives or legal counsel.", s["body"]),
        Paragraph("3. **Generic Salutations**: Greeting recipients with 'Dear Customer' rather than personalized details.", s["body"]),
        Paragraph("4. **Mismatched Domains**: Display names indicating IT Support while sender address is a free public webmail domain.", s["body"]),
        PageBreak(),

        # Page 2
        Paragraph("Module 2: Dissecting Simulated Lures (Educational Case Study)", s["h1"]),
        Paragraph(
            "To understand attacker methods, consider the following sanitized example often utilized in training simulations:",
            s["body"]
        ),
        Paragraph(
            "[EDUCATIONAL EXAMPLE — FOR TRAINING PURPOSES ONLY]\n"
            "Subject: Immediate Action Required: Payroll System Migration\n"
            "Body: 'Dear Colleague, Please log in immediately to verify your direct deposit profile before Friday.'",
            s["callout"]
        ),
        Paragraph("Why This Example is Suspicious:", s["h2"]),
        Paragraph(
            "• Corporate HR communicates payroll updates through formal announcements with weeks of advance notice.\n"
            "• Official payroll updates are accessed via the company intranet bookmarks, never unverified email links.\n"
            "• Legitimate corporate emails never require emergency credential re-verification over email.",
            s["body"]
        ),
        Paragraph("Inspecting Embedded Links Safely", s["h2"]),
        Paragraph(
            "Hover your mouse cursor over hyperlinks before clicking. Inspect the real destination address. "
            "For instance, an anchor text claiming to link to `https://company.internal` might secretly route to an external typo-squatted domain. "
            "When in doubt, open your browser and navigate directly to the trusted bookmark.",
            s["body"]
        ),
        PageBreak(),

        # Page 3
        Paragraph("Module 3: Best Practices for Secure Browsing", s["h1"]),
        Paragraph(
            "Maintaining vigilant cybersecurity hygiene protects the entire organization. Follow these fundamental practices:",
            s["body"]
        ),
        Paragraph("Key Employee Defense Principles", s["h2"]),
        Table([
            ["Habit", "Recommended Action", "Action to Avoid"],
            ["Software Updates", "Apply browser & OS patches promptly", "Postponing security reboot prompts"],
            ["Password Reuse", "Use dedicated unique passwords per system", "Reusing corporate passwords on personal apps"],
            ["Unsolicited Attachments", "Report to SOC via PhishAlarm tool", "Opening macros in unverified Word/Excel files"],
            ["Public Wi-Fi", "Always activate corporate VPN first", "Accessing company portals over open airport Wi-Fi"]
        ], colWidths=[130, 180, 190], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0B1739")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8.5)
        ]), spaceAfter=15),
        Paragraph("How to Report Suspicious Communications", s["h2"]),
        Paragraph(
            "Remember: You will never be penalized for reporting a suspicious email, even if it turns out to be legitimate. "
            "Direct all inquiries to security-awareness@internal.example.org. Thank you for keeping our community safe!",
            s["callout"]
        )
    ]
    build_pdf(filepath, story)

def generate_safe_financial_report(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Apex Holdings Inc. — Annual Financial Performance Report", s["title"]),
        Paragraph("Fiscal Year 2025 | Audited Financial Statements & Operational Review", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=18),
        Paragraph("1. Executive Financial Overview", s["h1"]),
        Paragraph(
            "Apex Holdings Inc. concluded Fiscal Year 2025 with strong revenue growth, improved operational margins, and accelerated "
            "expansion across international software-as-a-service markets. Total consolidated revenues reached $412.5M, representing a 22.4% "
            "year-over-year increase compared to FY2024.",
            s["body"]
        ),
        Paragraph("Key Financial Highlights", s["h2"]),
        Paragraph("• Annual Recurring Revenue (ARR) grew to $328.0M (+28.1% YoY).", s["body"]),
        Paragraph("• Gross Profit Margin expanded 180 basis points to 78.4%.", s["body"]),
        Paragraph("• Operating Cash Flow generated $84.2M, supporting strategic R&D investments.", s["body"]),
        Paragraph("• Cash and cash equivalents totaled $165.8M as of December 31, 2025.", s["body"]),
        Spacer(1, 10),
        Table([
            ["Metric (in $ Millions)", "FY 2023", "FY 2024", "FY 2025", "YoY Change"],
            ["Subscription Revenue", "$210.4", "$256.0", "$328.0", "+28.1%"],
            ["Professional Services", "$42.1", "$54.2", "$84.5", "+55.9%"],
            ["Total Revenue", "$252.5", "$310.2", "$412.5", "+33.0%"],
            ["Operating Expenses", "$178.0", "$215.4", "$280.1", "+30.0%"],
            ["Net Income", "$28.4", "$42.8", "$62.3", "+45.5%"]
        ], colWidths=[150, 80, 80, 80, 110], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0B1739")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8.5)
        ])),
        PageBreak(),

        # Page 2
        Paragraph("2. Operational Expenses & Capital Expenditure", s["h1"]),
        Paragraph(
            "Operating expenditures for FY2025 were aligned with long-term strategic milestones. Research and development accounted "
            "for 32% of total operational spend, focusing on cloud scalability, enterprise machine learning integrations, and automated compliance.",
            s["body"]
        ),
        Paragraph("Departmental Breakdown", s["h2"]),
        Table([
            ["Department", "Budget Allocated", "Actual Spend", "Variance"],
            ["Engineering & R&D", "$95.0M", "$92.4M", "-2.7%"],
            ["Sales & Marketing", "$120.0M", "$118.6M", "-1.2%"],
            ["General & Administrative", "$45.0M", "$44.1M", "-2.0%"],
            ["Information Technology", "$28.0M", "$25.0M", "-10.7%"]
        ], colWidths=[150, 110, 110, 130], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2563EB")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8.5)
        ]), spaceAfter=15),
        Paragraph("Capital Investments in Enterprise Resilience", s["h2"]),
        Paragraph(
            "Capital expenditures included $14.2M dedicated to infrastructure modernization, cloud disaster recovery multi-region replication, "
            "and SOC 2 automated audit infrastructure.",
            s["body"]
        ),
        PageBreak(),

        # Page 3
        Paragraph("3. FY2026 Guidance & Auditor Affirmation", s["h1"]),
        Paragraph(
            "Management issues the following guidance for the fiscal year ending December 31, 2026:",
            s["body"]
        ),
        Paragraph("• Projected Revenue: $500.0M – $520.0M (21% to 26% growth).", s["body"]),
        Paragraph("• Adjusted EBITDA Margin: 24.0% to 26.0%.", s["body"]),
        Paragraph("• Free Cash Flow conversion exceeding 85% of Net Income.", s["body"]),
        Spacer(1, 10),
        Paragraph("Independent Auditor Affirmation", s["h2"]),
        Paragraph(
            "The consolidated financial statements of Apex Holdings Inc. were examined by Deloitte & Touche LLP. "
            "In our opinion, the financial statements present fairly, in all material respects, the financial position of the Company.",
            s["callout"]
        )
    ]
    build_pdf(filepath, story)

def generate_threat_phishing_email(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("URGENT: Microsoft 365 Account Suspension Notice", s["title"]),
        Paragraph("Simulated Threat Scenario: Phishing / Credential Harvesting Incident", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#DC2626"), spaceAfter=18),
        Paragraph("Incident Overview & Intercepted Communication", s["h1"]),
        Paragraph(
            "The following communication was intercepted by enterprise perimeter mail filters targeting multiple finance team members. "
            "It exhibits classic high-confidence indicators of malicious credential harvesting and typo-squatted phishing redirection.",
            s["body"]
        ),
        Paragraph("Intercepted Email Headers & Payload", s["h2"]),
        Paragraph(
            "From: IT Helpdesk Support <admin-support@mail-verify365[.]example[.]com>\n"
            "To: payroll-team@enterprise.example.org\n"
            "Date: October 13, 2026 08:14:22 UTC\n"
            "Subject: FINAL WARNING: Immediate verification required for your corporate account",
            s["callout"]
        ),
        Paragraph("Message Body Content", s["h2"]),
        Paragraph(
            "Dear Valued Employee,\n\n"
            "Our automated identity protection monitoring has detected multiple irregular sign-in attempts from unrecognized location "
            "IP address 198.51.100.45 attempting to access your corporate workstation and email mailbox.\n\n"
            "Due to critical security policy violations, your single sign-on access will be PERMANENTLY DISABLED within 2 hours "
            "unless you authenticate your identity immediately.\n\n"
            "Please click the secure validation portal link below to confirm your password and multi-factor authentication code:\n\n"
            "hxxp://login-verify-account[.]example[.]com/auth/login.php?user=payroll-team\n\n"
            "Failure to complete verification prior to the deadline will result in total revocation of email access and file shares.\n\n"
            "Sincerely,\nCorporate Systems Administration Desk",
            s["body"]
        ),
        PageBreak(),

        # Page 2
        Paragraph("Technical Indicator Breakdown", s["h1"]),
        Paragraph(
            "Automated inspection identified multiple distinct Indicators of Compromise (IoCs) and deceptive manipulation heuristics:",
            s["body"]
        ),
        Table([
            ["Indicator", "Type", "Assessed Threat Level", "Context Offset"],
            ["login-verify-account[.]example[.]com", "Domain", "Critical Malicious", "URL Hostname"],
            ["198.51.100.45", "IPv4", "Suspicious Remote Host", "Header Claim"],
            ["admin-support@mail-verify365[.]example[.]com", "Email", "Phishing Sender", "Return Path"],
            ["hxxp://login-verify-account[.]example[.]com/auth/login.php", "URL", "Credential Harvesting", "Payload Link"]
        ], colWidths=[180, 80, 130, 110], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#7F1D1D")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8.5)
        ]), spaceAfter=15),
        Paragraph("Identified MITRE ATT&CK Techniques", s["h2"]),
        Paragraph("• **T1566.002 (Phishing: Spearphishing Link)**: Utilizes deceptive link to harvest enterprise credentials.", s["body"]),
        Paragraph("• **T1078 (Valid Accounts)**: Intended adversary objective to compromise corporate SSO accounts.", s["body"]),
        PageBreak(),

        # Page 3
        Paragraph("Recommended Incident Response Containment Actions", s["h1"]),
        Paragraph(
            "Security Operations Center (SOC) containment playbook for credential phishing incidents:",
            s["body"]
        ),
        Paragraph("1. **Perimeter DNS Sinkhole**: Immediately blackhole domain `login-verify-account[.]example[.]com` on internal resolvers.", s["body"]),
        Paragraph("2. **Email Purge**: Issue global Microsoft 365 Exchange purge for message ID to remove all delivered instances.", s["body"]),
        Paragraph("3. **Token Revocation**: Force session logout and password reset for any employee who clicked the landing link.", s["body"]),
        Paragraph("4. **Endpoint Telemetry Query**: Check EDR logs for outbound web socket connections to `198.51.100.45`.", s["body"]),
        Spacer(1, 10),
        Paragraph("Assessed Triage Severity: HIGH (8.8 / 10.0)", s["callout"])
    ]
    build_pdf(filepath, story)

def generate_threat_credential_theft(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Security Incident Brief: Internal Administrator Impersonation", s["title"]),
        Paragraph("Threat Actor TTP: Credential Harvesting & Unauthorized MFA Interception", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#DC2626"), spaceAfter=18),
        Paragraph("Incident Narrative", s["h1"]),
        Paragraph(
            "An adversary masquerading as Senior Enterprise Identity Administrator 'Alex Turner' sent direct urgent prompts "
            "instructing engineering personnel to enter their root Active Directory credentials and submit authenticator one-time passwords.",
            s["body"]
        ),
        Paragraph("Captured Attack Communication", s["h2"]),
        Paragraph(
            "FROM: Global IT Identity Support <it-identity-support@sso-internal-portal[.]example[.]org>\n"
            "TO: devops-core@enterprise.example.org\n"
            "SUBJECT: CRITICAL: Mandatory Okta MFA Re-Enrollment Protocol",
            s["callout"]
        ),
        Paragraph("Message Transcript", s["h2"]),
        Paragraph(
            "URGENT ATTENTION REQUIRED:\n\n"
            "Due to an active database patch failure, your corporate identity profile has become desynchronized. "
            "You are required to submit your current domain password, username, and temporary MFA token immediately "
            "to prevent system lockout.\n\n"
            "Navigate to the identity synchronization gateway:\n"
            "hxxp://sso-auth-reset[.]example[.]org/login.php?session=938210\n\n"
            "Enter your enterprise username, password, and approve the Duo push request that appears on your mobile device. "
            "Do not contact the helpdesk as phone lines are undergoing emergency maintenance.\n\n"
            "Technical Support Operations | IP Gateway: 203.0.113.88",
            s["body"]
        ),
        PageBreak(),

        # Page 2
        Paragraph("Technical IOCs & Threat Analysis", s["h1"]),
        Paragraph(
            "This communication matches explicit credential theft behavioral rules, including asking for passwords, "
            "authenticator tokens, and instructing victims not to verify the request through secondary channels.",
            s["body"]
        ),
        Table([
            ["IOC Value", "Type", "Confidence", "Classification"],
            ["sso-auth-reset[.]example[.]org", "Domain", "0.99", "Phishing Landing Page"],
            ["203.0.113.88", "IPv4", "0.95", "Adversary Infrastructure"],
            ["it-identity-support@sso-internal-portal[.]example[.]org", "Email", "0.98", "Spoofed Identity"],
            ["hxxp://sso-auth-reset[.]example[.]org/login.php", "URL", "0.99", "Credential Collector"]
        ], colWidths=[180, 80, 90, 150], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#7F1D1D")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8.5)
        ]), spaceAfter=15),
        Paragraph("Correlated ATT&CK Framework Techniques", s["h2"]),
        Paragraph("• **T1056.003 (Input Capture: Web Portal Capture)**: Harvesting credentials via spoofed login.", s["body"]),
        Paragraph("• **T1110 (Brute Force / Password Spraying)**: Subsequent phase targeting related systems.", s["body"]),
        Paragraph("• **T1621 (Multi-Factor Authentication Request Generation)**: MFA push bombing attack vector.", s["body"]),
        PageBreak(),

        # Page 3
        Paragraph("Incident Response Playbook", s["h1"]),
        Paragraph(
            "Recommended containment sequence for Active Directory credential compromises:",
            s["body"]
        ),
        Paragraph("• Invalidate all Kerberos Ticket Granting Tickets (TGT) for affected user accounts.", s["body"]),
        Paragraph("• Reset FIDO2 and authenticator token bindings.", s["body"]),
        Paragraph("• Inspect Azure AD / Okta sign-in logs for connections originating from `203.0.113.88`.", s["body"]),
        Paragraph("• Terminate active VPN tunnels associated with targeted engineer profiles.", s["body"]),
        Spacer(1, 10),
        Paragraph("Severity Assessment: CRITICAL (9.4 / 10.0)", s["callout"])
    ]
    build_pdf(filepath, story)

def generate_threat_suspicious_download(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Threat Advisory: Malicious Binary Dropper & EDR Bypass", s["title"]),
        Paragraph("Incident Classification: Trojan Dropper / Malware Distribution Attempt", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#DC2626"), spaceAfter=18),
        Paragraph("Summary of Adversary Activity", s["h1"]),
        Paragraph(
            "Security monitoring detected an inbound communication instructing system administrators to download and execute "
            "an unverified software package named `security_patch_critical.exe` under the pretense of an urgent zero-day remediation.",
            s["body"]
        ),
        Paragraph("Intercepted Instructions to Bypass Endpoint Security", s["h2"]),
        Paragraph(
            "INSTRUCTIONS RECEIVED BY SYSADMINS:\n\n"
            "'URGENT MICROSOFT PATCH ADVISORY:\n"
            "A zero-day remote code execution vulnerability (CVE-2026-44112) is actively spreading. "
            "Standard Windows Update channels are delayed. Download and execute the emergency hotfix patch directly:\n\n"
            "hxxp://update-cdn-patch2026[.]example[.]com/binaries/security_patch_critical.exe\n\n"
            "IMPORTANT: Because this patch modifies protected kernel drivers, Windows Defender and CrowdStrike Falcon "
            "will display a false-positive warning. You MUST disable Real-Time Protection and execute the file as Administrator "
            "to ensure proper installation.'",
            s["callout"]
        ),
        PageBreak(),

        # Page 2
        Paragraph("Malware Analysis & Indicators", s["h1"]),
        Paragraph(
            "Static analysis of the referenced binary demonstrates high-confidence indicators of malicious executable behavior, "
            "including persistence registry key installation and unauthorized shell spawning.",
            s["body"]
        ),
        Table([
            ["Artifact / IoC", "Type", "Threat Designation"],
            ["security_patch_critical.exe", "Filename", "Trojan Dropper Payload"],
            ["update-cdn-patch2026[.]example[.]com", "Domain", "Malicious C2 Distribution"],
            ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA-256", "Known Info-Stealer Hash"],
            ["CVE-2026-44112", "CVE", "Lure Vulnerability Reference"]
        ], colWidths=[200, 80, 220], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#7F1D1D")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8.5)
        ]), spaceAfter=15),
        Paragraph("Defense Evasion & Execution MITRE Tactics", s["h2"]),
        Paragraph("• **T1204.002 (User Execution: Malicious File)**: Lures administrative user into running untrusted binary.", s["body"]),
        Paragraph("• **T1562.001 (Impair Defenses: Disable or Modify Tools)**: Instructs victim to turn off antivirus protections.", s["body"]),
        Paragraph("• **T1059.001 (Command and Scripting Interpreter: PowerShell)**: Spawns covert background process.", s["body"]),
        PageBreak(),

        # Page 3
        Paragraph("Remediation & Hardening Steps", s["h1"]),
        Paragraph(
            "Immediate containment protocol:",
            s["body"]
        ),
        Paragraph("1. Add hash `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` to EDR global blocklist.", s["body"]),
        Paragraph("2. Block outbound connections to domain `update-cdn-patch2026[.]example[.]com` on perimeter web proxy.", s["body"]),
        Paragraph("3. Verify that AppLocker / Software Restriction Policies prevent binary execution from `%APPDATA%` and `%TEMP%` folders.", s["body"]),
        Spacer(1, 10),
        Paragraph("Assessed Severity: HIGH (8.6 / 10.0)", s["callout"])
    ]
    build_pdf(filepath, story)

def generate_threat_social_engineering(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Threat Narrative: Business Email Compromise & Wire Fraud", s["title"]),
        Paragraph("Adversary TTP: Executive Impersonation / Social Engineering Manipulation", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#DC2626"), spaceAfter=18),
        Paragraph("Incident Chronology", s["h1"]),
        Paragraph(
            "An advanced Business Email Compromise (BEC) attempt targeted the corporate treasury department. "
            "The attacker spoofed the Chief Executive Officer's identity to pressure finance managers into executing "
            "an urgent, out-of-band wire transfer for an alleged confidential acquisition.",
            s["body"]
        ),
        Paragraph("Transcript of Spoofed Communication", s["h2"]),
        Paragraph(
            "FROM: Richard Vance <ceo-office@exec-confidential-board[.]example[.]org>\n"
            "TO: accounts-payable@enterprise.example.org\n"
            "SUBJECT: CONFIDENTIAL: Project Titan Settlement — Immediate Wire Required",
            s["callout"]
        ),
        Paragraph("Body Text", s["h2"]),
        Paragraph(
            "'Sarah,\n\n"
            "I am currently in closed-door board negotiations regarding our strategic acquisition of Horizon Analytics. "
            "Due to strict NDA stipulations, you must NOT discuss this transaction with anyone, including the CFO or legal team.\n\n"
            "We have reached a binding agreement requiring an immediate earnest deposit of $480,000 to escrow account details below:\n"
            "Bank: Apex Commercial Escrow (Offshore Clearing)\n"
            "Routing Number: 021000089\n"
            "Account Number: 8839-4412-9901\n"
            "Beneficiary: Horizon Holdings Ltd.\n\n"
            "Please bypass standard dual-authorization protocols just this once to prevent the deal from falling through. "
            "Send the wire confirmation receipt directly to my private assistant address: exec-ops@exec-confidential-board[.]example[.]org.\n\n"
            "I am relying on your discretion.\nRichard Vance, CEO'",
            s["body"]
        ),
        PageBreak(),

        # Page 2
        Paragraph("Behavioral & Technical Indicators", s["h1"]),
        Paragraph(
            "This communication triggers multiple behavioral social engineering indicators:",
            s["body"]
        ),
        Paragraph("1. **Out-of-Band Process Bypass**: Requesting the recipient to bypass dual-authorization financial controls.", s["body"]),
        Paragraph("2. **Artificial Secrecy Mandate**: Instructing the victim not to consult standard internal stakeholders.", s["body"]),
        Paragraph("3. **Spoofed Executive Sender**: Registering typo-squatted domain `exec-confidential-board[.]example[.]org`.", s["body"]),
        Spacer(1, 10),
        Table([
            ["Indicator", "Type", "Threat Assessment"],
            ["exec-confidential-board[.]example[.]org", "Domain", "Impersonation Infrastructure"],
            ["exec-ops@exec-confidential-board[.]example[.]org", "Email", "Adversary Exfiltration Mailbox"],
            ["ceo-office@exec-confidential-board[.]example[.]org", "Email", "Executive Spoof Sender"]
        ], colWidths=[200, 80, 220], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#7F1D1D")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8.5)
        ]), spaceAfter=15),
        Paragraph("Correlated ATT&CK Framework Mapping", s["h2"]),
        Paragraph("• **T1566.001 (Phishing: Spearphishing Attachment / Communication)**", s["body"]),
        Paragraph("• **T1656 (Impersonation)**: Deceptive masquerading as senior enterprise leadership.", s["body"]),
        PageBreak(),

        # Page 3
        Paragraph("Defensive Controls & Financial Safeguards", s["h1"]),
        Paragraph(
            "Controls required to eliminate wire fraud risks:",
            s["body"]
        ),
        Paragraph("• Mandatory phone call back verification using verified intranet contact directory for any wire exceeding $10,000.", s["body"]),
        Paragraph("• Enforce DMARC `p=reject` policy on all corporate domains.", s["body"]),
        Paragraph("• Flag incoming emails containing external sender warnings and executive display name mismatches.", s["body"]),
        Spacer(1, 10),
        Paragraph("Severity Assessment: HIGH (8.2 / 10.0)", s["callout"])
    ]
    build_pdf(filepath, story)

def generate_manifest():
    """Generates sample_documents/test_manifest.json and README.md."""
    manifest = {
        "generated_at": "2026-10-13T16:00:00Z",
        "description": "ThreatLens 8-Document Multi-Page Verification Suite for Presentation and Testing",
        "documents": [
            {
                "filename": "safe_company_policy.pdf",
                "category": "Safe Documents",
                "intended_classification": "Safe / Benign",
                "pages": 3,
                "description": "Corporate information security policy outlining employee responsibilities, password management, and incident response.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_project_report.pdf",
                "category": "Safe Documents",
                "intended_classification": "Safe / Benign",
                "pages": 3,
                "description": "Software engineering architecture report detailing microservices, database schemas, and performance benchmarks.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_security_awareness.pdf",
                "category": "Educational Security Documents",
                "intended_classification": "Safe / Context-Aware Educational",
                "pages": 3,
                "description": "Educational training material explaining phishing indicators and safe browsing without being classified as malicious.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_financial_report.pdf",
                "category": "Safe Documents",
                "intended_classification": "Safe / Benign",
                "pages": 3,
                "description": "Audited corporate financial statement with revenue metrics, operational expenditures, and auditor notes.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "threat_phishing_email.pdf",
                "category": "Phishing Examples",
                "intended_classification": "Phishing",
                "pages": 3,
                "description": "Deceptive Microsoft 365 account suspension notice demanding urgent credential verification via spoofed domain.",
                "expected_severity": "High",
                "expected_indicators": 4
            },
            {
                "filename": "threat_credential_theft.pdf",
                "category": "Credential Theft Examples",
                "intended_classification": "Credential Theft",
                "pages": 3,
                "description": "Impersonation of internal IT administrator requesting domain password and MFA authenticator tokens.",
                "expected_severity": "High",
                "expected_indicators": 4
            },
            {
                "filename": "threat_suspicious_download.pdf",
                "category": "Suspicious Documents",
                "intended_classification": "Malware",
                "pages": 3,
                "description": "Fake critical patch advisory instructing sysadmins to download executable and disable antivirus protections.",
                "expected_severity": "High",
                "expected_indicators": 4
            },
            {
                "filename": "threat_social_engineering.pdf",
                "category": "Social Engineering Examples",
                "intended_classification": "Social Engineering",
                "pages": 3,
                "description": "Executive CEO impersonation message pressuring finance staff into an out-of-band urgent wire transfer.",
                "expected_severity": "High",
                "expected_indicators": 3
            }
        ]
    }
    with open(SAMPLE_DIR / "test_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    readme_content = """# ThreatLens Sample Documents Test Suite

This directory contains eight realistic, multi-page (3-page) PDF test documents generated via ReportLab to demonstrate the ThreatLens Document Scanning & Threat Detection pipeline.

## Document Manifest

### Safe Documents (4 Files)
1. **`safe_company_policy.pdf`**: Enterprise security governance policy covering ISO 27001, password complexity, FIDO2 MFA, and incident reporting. Expected triage: *No significant indicators detected*.
2. **`safe_project_report.pdf`**: Technical engineering milestone report detailing Kafka, FastAPI, and TimescaleDB architectures. Expected triage: *No significant indicators detected*.
3. **`safe_security_awareness.pdf`**: Educational training module explaining phishing mechanics, safe link inspection, and reporting workflows. Expected triage: *No significant indicators detected* (context-aware educational handling).
4. **`safe_financial_report.pdf`**: Audited annual financial performance report detailing revenues, balance sheets, and guidance. Expected triage: *No significant indicators detected*.

### Suspicious Documents (4 Files)
5. **`threat_phishing_email.pdf`**: Urgent Microsoft 365 account suspension lure directing users to `login-verify-account[.]example[.]com`. Expected triage: *High*.
6. **`threat_credential_theft.pdf`**: IT administrator impersonation prompt requesting Active Directory passwords and MFA tokens via `sso-auth-reset[.]example[.]org`. Expected triage: *High*.
7. **`threat_suspicious_download.pdf`**: Deceptive zero-day patch advisory instructing recipients to download `security_patch_critical.exe` and disable antivirus protections. Expected triage: *High*.
8. **`threat_social_engineering.pdf`**: CEO wire transfer BEC fraud demanding out-of-band wire authorization and secrecy. Expected triage: *High*.

## Notes & Attribution
All network indicators use RFC 5737 documentation IP ranges (`198.51.100.0/24`, `203.0.113.0/24`) and RFC 2606 reserved domains (`example.com`, `example.org`).
"""
    with open(SAMPLE_DIR / "README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)
    print("[+] Created test_manifest.json and sample_documents/README.md")

def main():
    print("[*] Generating 8 multi-page sample PDF documents for ThreatLens...")
    generate_safe_company_policy(SAMPLE_DIR / "safe_company_policy.pdf")
    generate_safe_project_report(SAMPLE_DIR / "safe_project_report.pdf")
    generate_safe_security_awareness(SAMPLE_DIR / "safe_security_awareness.pdf")
    generate_safe_financial_report(SAMPLE_DIR / "safe_financial_report.pdf")
    generate_threat_phishing_email(SAMPLE_DIR / "threat_phishing_email.pdf")
    generate_threat_credential_theft(SAMPLE_DIR / "threat_credential_theft.pdf")
    generate_threat_suspicious_download(SAMPLE_DIR / "threat_suspicious_download.pdf")
    generate_threat_social_engineering(SAMPLE_DIR / "threat_social_engineering.pdf")
    generate_manifest()
    print("[+] All 8 sample documents generated successfully in sample_documents/!")

if __name__ == "__main__":
    main()
