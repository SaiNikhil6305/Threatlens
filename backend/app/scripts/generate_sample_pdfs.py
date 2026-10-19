import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "sample_reports"))
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ThreatLens Corporate Cybersecurity Palette
COLOR_DEEP_NAVY = colors.HexColor("#102B4E")
COLOR_PRIMARY_NAVY = colors.HexColor("#153B66")
COLOR_BRAND_BLUE = colors.HexColor("#2563A6")
COLOR_LIGHT_BG = colors.HexColor("#F0F6FC")
COLOR_BORDER = colors.HexColor("#D7E3F0")
COLOR_TEXT_DARK = colors.HexColor("#172B45")
COLOR_TEXT_MUTED = colors.HexColor("#5B6B80")

COLOR_CRITICAL = colors.HexColor("#DC2626")
COLOR_HIGH = colors.HexColor("#EA580C")
COLOR_MEDIUM = colors.HexColor("#D97706")
COLOR_LOW = colors.HexColor("#16A34A")

def create_header(canvas, doc, title_text, doc_id, classification):
    canvas.saveState()
    # Top primary banner
    canvas.setFillColor(COLOR_DEEP_NAVY)
    canvas.rect(0, 755, 612, 45, fill=1, stroke=0)
    
    # ThreatLens Logo & Title
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(36, 772, "ThreatLens")
    
    canvas.setFont("Helvetica", 9)
    canvas.drawString(108, 772, "•  Cyber Threat Intelligence Assistant")
    
    # Classification badge right
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawRightString(576, 772, f"{classification} | {doc_id}")
    
    # Footer
    canvas.setStrokeColor(COLOR_BORDER)
    canvas.setLineWidth(0.8)
    canvas.line(36, 35, 576, 35)
    
    canvas.setFillColor(COLOR_TEXT_MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(36, 24, "ThreatLens CTI Platform • Natural Language Processing & Machine Learning Intelligence")
    canvas.drawRightString(576, 24, f"Page {doc.page}  |  CONFIDENTIAL")
    canvas.restoreState()

def generate_pdf(filename, doc_id, classification, title, severity_label, severity_score, severity_color,
                 category, date_str, exec_summary, narrative, iocs, techniques, recommendations):
    filepath = os.path.join(OUTPUT_DIR, filename)
    doc = SimpleDocTemplate(
        filepath,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=54,
        bottomMargin=45
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=18,
        textColor=COLOR_TEXT_DARK
    )
    
    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=COLOR_PRIMARY_NAVY,
        spaceBefore=8,
        spaceAfter=4
    )
    
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=COLOR_TEXT_DARK
    )
    
    meta_label = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9.5,
        textColor=COLOR_TEXT_MUTED
    )
    
    meta_val = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=COLOR_TEXT_DARK
    )
    
    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=9.5,
        textColor=COLOR_TEXT_DARK
    )
    
    table_mono = ParagraphStyle(
        'TableMono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=9.5,
        textColor=COLOR_TEXT_DARK
    )

    story = []
    story.append(Spacer(1, 10))
    
    # Document Header Title
    story.append(Paragraph(title, title_style))
    story.append(Spacer(1, 6))
    
    # Metadata Box
    meta_data = [
        [
            Paragraph("REPORT IDENTIFIER", meta_label),
            Paragraph("CLASSIFICATION", meta_label),
            Paragraph("THREAT CATEGORY", meta_label),
            Paragraph("ASSESSED SEVERITY", meta_label)
        ],
        [
            Paragraph(f"<b>{doc_id}</b>", meta_val),
            Paragraph(f"<b>{classification}</b>", meta_val),
            Paragraph(f"<b>{category}</b>", meta_val),
            Paragraph(f"<font color='{severity_color.hexval()}'><b>{severity_label} ({severity_score}/10.0)</b></font>", meta_val)
        ],
        [
            Paragraph("PUBLICATION DATE", meta_label),
            Paragraph("AUTHOR / SOURCE", meta_label),
            Paragraph("NLP ENGINE STATUS", meta_label),
            Paragraph("VERIFICATION STATE", meta_label)
        ],
        [
            Paragraph(date_str, meta_val),
            Paragraph("SOC Incident Response", meta_val),
            Paragraph("Analyzed (TF-IDF & Rule)", meta_val),
            Paragraph("Analyst Confirmed", meta_val)
        ]
    ]
    
    meta_table = Table(meta_data, colWidths=[135, 135, 135, 135])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), COLOR_LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8))
    
    # 1. Executive Summary
    story.append(Paragraph("1. EXECUTIVE INTELLIGENCE SUMMARY", h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_BORDER, spaceBefore=1, spaceAfter=4))
    story.append(Paragraph(exec_summary, body_style))
    story.append(Spacer(1, 6))
    
    # 2. Detailed Technical Narrative
    story.append(Paragraph("2. DETAILED FORENSIC INCIDENT NARRATIVE", h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_BORDER, spaceBefore=1, spaceAfter=4))
    story.append(Paragraph(narrative, body_style))
    story.append(Spacer(1, 8))
    
    # 3. Indicators of Compromise Table
    story.append(Paragraph(f"3. EXTRACTED TECHNICAL INDICATORS OF COMPROMISE ({len(iocs)} TOKENS)", h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_BORDER, spaceBefore=1, spaceAfter=4))
    
    ioc_rows = [
        [
            Paragraph("<b>INDICATOR (DEFANGED)</b>", meta_label),
            Paragraph("<b>TYPE</b>", meta_label),
            Paragraph("<b>REPUTATION</b>", meta_label),
            Paragraph("<b>CONTEXT / ATTRIBUTION</b>", meta_label)
        ]
    ]
    for ioc in iocs:
        ioc_rows.append([
            Paragraph(ioc["defanged"], table_mono),
            Paragraph(ioc["type"], table_cell),
            Paragraph(ioc["reputation"], table_cell),
            Paragraph(ioc["context"], table_cell)
        ])
        
    ioc_table = Table(ioc_rows, colWidths=[180, 70, 90, 200])
    ioc_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), COLOR_LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(ioc_table)
    story.append(Spacer(1, 8))
    
    # 4. MITRE ATT&CK Matrix Mapping
    story.append(Paragraph(f"4. MITRE ATT&CK ENTERPRISE TAXONOMY CORRELATIONS ({len(techniques)} TECHNIQUES)", h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_BORDER, spaceBefore=1, spaceAfter=4))
    
    att_rows = [
        [
            Paragraph("<b>TECHNIQUE ID</b>", meta_label),
            Paragraph("<b>TECHNIQUE NAME</b>", meta_label),
            Paragraph("<b>TACTIC</b>", meta_label),
            Paragraph("<b>OBSERVED EVIDENCE ARTIFACT</b>", meta_label)
        ]
    ]
    for tech in techniques:
        att_rows.append([
            Paragraph(f"<b>{tech['id']}</b>", table_mono),
            Paragraph(tech["name"], table_cell),
            Paragraph(tech["tactic"], table_cell),
            Paragraph(tech["evidence"], table_cell)
        ])
        
    att_table = Table(att_rows, colWidths=[90, 140, 110, 200])
    att_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), COLOR_LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(att_table)
    story.append(Spacer(1, 8))
    
    # 5. Incident Response Playbook
    story.append(Paragraph("5. ACTIONABLE INCIDENT CONTAINMENT & DEFENSIVE MITIGATION PLAYBOOK", h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=COLOR_BORDER, spaceBefore=1, spaceAfter=4))
    
    rec_rows = [
        [
            Paragraph("<b>PRIORITY</b>", meta_label),
            Paragraph("<b>REMEDIATION ACTION</b>", meta_label),
            Paragraph("<b>OPERATIONAL SPECIFICATION</b>", meta_label)
        ]
    ]
    for r in recommendations:
        rec_rows.append([
            Paragraph(f"<b>{r['priority']}</b>", table_mono),
            Paragraph(f"<b>{r['action']}</b>", table_cell),
            Paragraph(r["detail"], table_cell)
        ])
        
    rec_table = Table(rec_rows, colWidths=[60, 160, 320])
    rec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), COLOR_LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 1, COLOR_BORDER),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(rec_table)
    
    def on_page(canvas, document):
        create_header(canvas, document, title, doc_id, classification)
        
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    print(f"[OK] Generated: {filepath}")
    return filepath

def main():
    print("=== GENERATING PROFESSIONAL THREATLENS SAMPLE CYBERSECURITY PDFS ===")

    # 1. HIGH-SEVERITY CASE: LockBit 3.0 Double-Extortion Ransomware
    generate_pdf(
        filename="ThreatLens_Sample_HIGH_SEVERITY_LockBit_Ransomware.pdf",
        doc_id="TL-ADV-2026-CRIT-004",
        classification="TLP:AMBER // STRICT",
        title="ThreatLens Intelligence Bulletin: LockBit 3.0 Ransomware Outbreak with Shadow Deletion",
        severity_label="CRITICAL",
        severity_score="9.2",
        severity_color=COLOR_CRITICAL,
        category="Ransomware",
        date_str="October 13, 2026",
        exec_summary=(
            "ThreatLens identified an active high-velocity LockBit 3.0 ransomware outbreak impacting corporate workstation endpoints. "
            "The adversary gained initial foothold via spearphishing attachment exploiting WinRAR vulnerability CVE-2023-38831. "
            "Following ingress, ransomware operators executed 'vssadmin delete shadows /all /quiet' using an obfuscated PowerShell interpreter "
            "to inhibit local volume recovery, deployed double-extortion ransom notes (RESTORE-FILES.txt), and initiated encrypted C2 beaconing to 198.51.100.200. "
            "Immediate containment protocol and boundary firewall isolation must be enacted."
        ),
        narrative=(
            "Security Operations Center sensors detected automated high-rate encryption events across engineering endpoints. "
            "Malicious process lockbit_v3.exe was launched via parent process explorer.exe after staging payload dropping with MD5 hash 44d88612fea8a8f36de82e1278abb02f "
            "and SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. "
            "Adversaries executed commands to delete Volume Shadow Copies to guarantee irreversible data loss prior to extortion contact. "
            "Active command-and-control communication was verified connecting to remote server 198.51.100.200 on port 8080 and leak domain lockbit-leak-portal[.]example[.]org. "
            "Negotiation email lockbit-ops[at]decryption-service[.]example was left in dropped ransom notes."
        ),
        iocs=[
            {"defanged": "198.51.100[.]200", "type": "IPv4", "reputation": "Malicious (C2 Active)", "context": "LockBit external C2 communication server"},
            {"defanged": "lockbit-leak-portal[.]example[.]org", "type": "Domain", "reputation": "Suspicious / Extortion", "context": "TOR gateway leak portal mirror"},
            {"defanged": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "type": "SHA-256", "reputation": "Malicious Payload", "context": "LockBit 3.0 encryptor binary"},
            {"defanged": "44d88612fea8a8f36de82e1278abb02f", "type": "MD5", "reputation": "Malicious Dropper", "context": "Staging executable dropper hash"},
            {"defanged": "CVE-2023-38831", "type": "CVE", "reputation": "Known Exploited (KEV)", "context": "WinRAR code execution vector"},
            {"defanged": "lockbit-ops[at]decryption-service[.]example", "type": "Email", "reputation": "Threat Actor Contact", "context": "Operator extortion contact"}
        ],
        techniques=[
            {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "evidence": "Widespread filesystem encryption with RESTORE-FILES.txt ransom notes."},
            {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact", "evidence": "Execution of 'vssadmin delete shadows /all /quiet' to destroy volume backups."},
            {"id": "T1059.001", "name": "PowerShell Execution", "tactic": "Execution", "evidence": "PowerShell -encodedCommand invoked for privilege escalation."},
            {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command & Control", "evidence": "Encrypted HTTP beaconing to IP 198.51.100.200:8080."},
            {"id": "T1567.002", "name": "Exfiltration to Cloud Storage", "tactic": "Exfiltration", "evidence": "Staged WinRAR archives transferred to external cloud buckets."}
        ],
        recommendations=[
            {"priority": "P0 - URGENT", "action": "Network Segment Quarantine", "detail": "Immediately isolate subnet hosting affected hosts at VLAN boundary to stop lateral propagation."},
            {"priority": "P0 - URGENT", "action": "Edge IP Blocking", "detail": "Apply border firewall drop rules for C2 address 198.51.100.200 and DNS sinkhole for lockbit-leak-portal[.]example[.]org."},
            {"priority": "P1 - HIGH", "action": "EDR Hash Hunting", "detail": "Execute enterprise-wide EDR sweep for SHA256 e3b0c442... and kill spawned instances."},
            {"priority": "P2 - MEDIUM", "action": "Offline Backup Restoration", "detail": "Verify integrity of cold air-gapped immutable backups prior to initiating disaster recovery rebuilds."}
        ]
    )

    # 2. LOW-SEVERITY CASE: Routine Internal Vulnerability & Asset Scan
    generate_pdf(
        filename="ThreatLens_Sample_LOW_SEVERITY_Internal_Vulnerability_Scan.pdf",
        doc_id="TL-ADV-2026-LOW-018",
        classification="TLP:CLEAR // PUBLIC",
        title="ThreatLens Assessment: Scheduled Internal DMZ Vulnerability & Banner Audit",
        severity_label="LOW",
        severity_score="1.8",
        severity_color=COLOR_LOW,
        category="Reconnaissance",
        date_str="October 13, 2026",
        exec_summary=(
            "ThreatLens processed a routine scheduled vulnerability assessment log from internal security audit node scan-worker-02. "
            "The audit evaluated staging subnet 10.0.8.0/24. Findings indicate satisfactory patch levels across core web servers and database instances. "
            "Only non-exploitable informational disclosures were identified: verbose Apache HTTP server banner disclosures and legacy 64-bit DES ciphers. "
            "No malware droppers, credential stuffing, lateral movement, or active exploitation artifacts were identified."
        ),
        narrative=(
            "Routine monthly vulnerability scan conducted on internal subnet hosting non-production services. "
            "Scanning scanner IP 10.0.8.42 communicated with internal host dev-staging.internal.example.net on TCP ports 80, 443, and 8443. "
            "Inspection identified Apache-Coyote 1.1 software version banner disclosure and sweet32 legacy cipher support (CVE-2016-2183). "
            "All tested endpoints refused unauthenticated command injection and SQL syntax injections. "
            "The overall risk posture remains low and manageable via regular scheduled maintenance windows."
        ),
        iocs=[
            {"defanged": "10.0.8[.]42", "type": "IPv4", "reputation": "Benign (Internal Node)", "context": "Internal authorized vulnerability scanner"},
            {"defanged": "dev-staging.internal[.]example[.]net", "type": "Domain", "reputation": "Internal Asset", "context": "Staging application development cluster"},
            {"defanged": "CVE-2016-2183", "type": "CVE", "reputation": "Low Severity / Legacy", "context": "SWEET32 birthday attack on 64-bit block ciphers in TLS"},
            {"defanged": "sec-ops[at]internal-audit[.]example", "type": "Email", "reputation": "Internal Auditor", "context": "Assigned infrastructure security analyst"}
        ],
        techniques=[
            {"id": "T1595.002", "name": "Vulnerability Scanning", "tactic": "Reconnaissance", "evidence": "Automated TCP SYN service probing initiated from scanner IP 10.0.8.42."},
            {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery", "evidence": "Enumeration of open ports 80, 443, 8443 on internal staging subnet."}
        ],
        recommendations=[
            {"priority": "P3 - LOW", "action": "Server Banner Suppression", "detail": "Configure 'ServerTokens Prod' and 'ServerSignature Off' in Apache configuration to prevent version leaks."},
            {"priority": "P3 - LOW", "action": "Deprecate 64-bit TLS Ciphers", "detail": "Disable 3DES and legacy CBC cipher suites in web server SSL configuration; mandate AES-GCM and ChaCha20."},
            {"priority": "P4 - INFO", "action": "Routine Log Archival", "detail": "Archive vulnerability scan logs in SIEM compliance storage per standard retention schedules."}
        ]
    )

    # 3. MEDIUM-SEVERITY CASE: Spearphishing Credential Harvesting
    generate_pdf(
        filename="ThreatLens_Sample_MEDIUM_SEVERITY_Phishing_Credential_Harvest.pdf",
        doc_id="TL-ADV-2026-MED-009",
        classification="TLP:GREEN // ORG",
        title="ThreatLens Intelligence Bulletin: Spearphishing Credential Harvesting Portal",
        severity_label="MEDIUM",
        severity_score="5.4",
        severity_color=COLOR_MEDIUM,
        category="Phishing",
        date_str="October 13, 2026",
        exec_summary=(
            "ThreatLens analyzed a targeted spearphishing campaign impersonating corporate HR benefits administration. "
            "Employees received emails urging immediate credential verification at fake domain hxxps://secure-auth.corp-benefits.example[.]org/login. "
            "Gateway telemetry indicates email was quarantined for 94% of recipients; one user submitted credentials which were promptly revoked. "
            "No endpoint persistence or follow-on malware execution observed."
        ),
        narrative=(
            "Inbound emails originated from spoofed sender accounting[at]payroll-portal.example[.]com transmitting links to credential capture site. "
            "Landing portal clones corporate Single Sign-On (SSO) login view with JavaScript keylogger payload. "
            "Payload hashes MD5 44d88612fea8a8f36de82e1278abb02f detected on external CDN staging server. "
            "Adversary infrastructure is hosted at external IP 192.0.2.144 on port 8080."
        ),
        iocs=[
            {"defanged": "192.0.2[.]144", "type": "IPv4", "reputation": "Suspicious / Phishing Host", "context": "Phishing landing portal external IP"},
            {"defanged": "secure-auth.corp-benefits.example[.]org", "type": "Domain", "reputation": "Malicious (Phishing)", "context": "Cloned corporate SSO harvest portal"},
            {"defanged": "accounting[at]payroll-portal.example[.]com", "type": "Email", "reputation": "Spoofed Sender", "context": "Header sender address in phishing lure"},
            {"defanged": "hxxps://secure-auth.corp-benefits.example[.]org/login", "type": "URL", "reputation": "Malicious Harvest URL", "context": "Landing authentication portal"}
        ],
        techniques=[
            {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access", "evidence": "Email delivery with embedded malicious authentication URL."},
            {"id": "T1056.003", "name": "Web Portal Credential Capture", "tactic": "Credential Access", "evidence": "Fake corporate SSO login form capturing employee credentials."}
        ],
        recommendations=[
            {"priority": "P1 - HIGH", "action": "User Password Reset & Session Revocation", "detail": "Immediately revoke active OAuth refresh tokens and reset passwords for impacted accounts."},
            {"priority": "P1 - HIGH", "action": "Domain Sinkhole & Proxy Blacklist", "detail": "Add secure-auth.corp-benefits.example[.]org to DNS blackholes and secure web gateway blocklists."},
            {"priority": "P2 - MEDIUM", "action": "FIDO2 / WebAuthn Enforcement", "detail": "Enforce phishing-resistant hardware MFA keys to prevent stolen credentials from functioning."}
        ]
    )

    print("=== ALL SAMPLE CYBERSECURITY PDFS GENERATED SUCCESSFULLY ===")

if __name__ == "__main__":
    main()
