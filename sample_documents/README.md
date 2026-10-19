# ThreatLens Sample Test Documents Suite (20 Scenarios as PDFs)

This directory contains realistic cyber threat and operational test documents generated for testing, evaluating, and verifying the **ThreatLens** Document Parsing, Triage, and Threat Detection pipeline.

All 20 test documents are available as standalone, high-fidelity **PDF** files with extractable digital text.

---

## Folder Location
```
c:\projects\Threatlens\sample_documents\
```

---

## Document Inventory (All 20 PDF Files)

### 🛡️ Safe / Benign Documents (10 PDFs)

| # | Filename | Scenario Name | Description |
|---|---|---|---|
| 1 | **`safe_company_policy.pdf`** | Enterprise Information Security Governance | ISO/IEC 27001 policies, password complexity rules, FIDO2 MFA standards. |
| 2 | **`safe_project_report.pdf`** | Microservices Architecture Report | Technical milestone report on Kafka, FastAPI, and TimescaleDB microservices. |
| 3 | **`safe_security_awareness.pdf`** | Educational Phishing Awareness Module | Security training module explaining phishing mechanics and safe reporting. |
| 4 | **`safe_financial_report.pdf`** | Annual Corporate Financial Statement | Audited financial statement with operational balance sheets and auditor notes. |
| 5 | **`safe_incident_response_playbook.pdf`** | NIST SP 800-61 Incident Handling SOP | Operational runbook with incident triage SLAs and forensic custody rules. |
| 6 | **`safe_cloud_infrastructure_guide.pdf`** | Multi-Region Kubernetes Blueprint | Cloud hosting architecture, Terraform IaC modules, and Zero Trust design. |
| 7 | **`safe_devops_release_changelog.pdf`** | Production DevOps Release Manifest v3.2.1 | GitOps pipeline deployment manifest, unit test reports, and dependency updates. |
| 8 | **`safe_quarterly_budget_report.pdf`** | Corporate IT Infrastructure Ledger | Financial ledger tracking SaaS subscriptions, vendor allocations, and compute spend. |
| 9 | **`safe_remote_work_security_handbook.pdf`** | Remote Work & VPN Security Guide | Employee handbook covering corporate VPN, FIDO2 keys, and IT helpdesk channels. |
| 10 | **`safe_api_architecture_spec.pdf`** | OpenAPI 3.0 REST Microservice Specification | Technical specification for internal inventory REST service and health probes. |

---

### ⚠️ Threat-Causing Documents (10 PDFs)

| # | Filename | Scenario Name | Key Threat Indicators / Vectors |
|---|---|---|---|
| 11 | **`threat_phishing_email.pdf`** | Microsoft 365 Account Lure | Phishing domain `login-verify-account[.]example[.]com`, credential harvesting. |
| 12 | **`threat_credential_theft.pdf`** | Active Directory Credential Harvest | Spoofed IT admin prompt, phishing domain `sso-auth-reset[.]example[.]org`. |
| 13 | **`threat_suspicious_download.pdf`** | Zero-Day Patch Trojan Dropper | Deceptive security advisory delivering `security_patch_critical.exe`. |
| 14 | **`threat_social_engineering.pdf`** | Executive BEC Wire Fraud | Coercive CEO wire transfer request coercing out-of-band wire authorization. |
| 15 | **`threat_ransomware_incident.pdf`** | LockBit 3.0 Enterprise Ransomware | `vssadmin delete shadows`, C2 IP `198.51.100.220`, ransom note transcript. |
| 16 | **`threat_apt_spearphishing.pdf`** | APT29 Targeted Espionage Campaign | ISO container dropper, in-memory Mimikatz dumping, C2 IP `203.0.113.88`. |
| 17 | **`threat_log4shell_cve_alert.pdf`** | Log4Shell RCE Flaw Advisory | CVE-2021-44228 JNDI LDAP lookup strings, C2 IP `203.0.113.99`, ELF dropper hash. |
| 18 | **`threat_exfiltration_covert_c2.pdf`** | DNS Tunneling & Data Exfiltration | 14.8 GB exfiltration to `192.0.2.144`, Cobalt Strike beacon MD5 & SHA256 hashes. |
| 19 | **`threat_malicious_macro_invoice.pdf`** | EDR Process Telemetry Macro Dropper | Excel spawning PowerShell, download from bad domain, C2 IP `198.51.100.42`. |
| 20 | **`threat_executive_wire_fraud.pdf`** | Urgent CEO Impersonation Wire Fraud | CEO BEC scam demanding bypassing dual authorization for $485,000 wire transfer. |

---

## How to Test in ThreatLens

1. Open the **ThreatLens Workbench**: [http://localhost:5174/analyze](http://localhost:5174/analyze)
2. Switch to the **Document Analysis** tab.
3. Click **Browse Local Documents** (or drag and drop).
4. Navigate to `c:\projects\Threatlens\sample_documents\` in the Windows file picker.
5. Select any of the 20 PDF files and click **Run Threat Intelligence Analysis**.
