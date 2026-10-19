from typing import List, Dict, Any

RECOMMENDATIONS_BY_CATEGORY = {
    "Ransomware": [
        {"action": "Network Isolation", "detail": "Immediately disconnect compromised endpoints and adjacent VLANs from the core network to halt automated worming or lateral encryption."},
        {"action": "Backup Preservation", "detail": "Verify offline and immutable backup integrity. Confirm volume shadow copies (VSS) are preserved on uncompromised nodes."},
        {"action": "Containment Blocklists", "detail": "Deploy identified C2 IP addresses and file hashes to perimeter firewalls, proxy appliances, and EDR blocklists."},
        {"action": "Credential Invalidation", "detail": "Initiate enterprise-wide credential resets for domain admin and privileged service accounts."}
    ],
    "Phishing": [
        {"action": "Message Quarantine", "detail": "Search mail server logs (M365 / Google Workspace / Exchange) using subject terms and sender addresses to purge matching messages from inboxes."},
        {"action": "Credential Reset & MFA", "detail": "Force password change and revoke active session tokens for users who interacted with the phishing lure."},
        {"action": "Domain & URL Blocklisting", "detail": "Submit extracted malicious domains and defanged URLs to web filtering proxies and DNS sinkholes."},
        {"action": "Security Awareness Notification", "detail": "Issue a security flash bulletin alerting employees to the active spearphishing theme."}
    ],
    "Vulnerability Exploitation": [
        {"action": "Patch Deployment", "detail": "Prioritize rapid application of official vendor security patches for the referenced CVE."},
        {"action": "WAF Virtual Patching", "detail": "Deploy targeted Web Application Firewall (WAF) or IPS virtual patching signatures to intercept exploit payloads."},
        {"action": "Attack Surface Reduction", "detail": "Restrict exposure of vulnerable management ports (e.g. 443, 8443, 8080) to trusted IP ranges only."},
        {"action": "Exploitation Forensics", "detail": "Review web server access logs around exploitation timestamps for abnormal POST requests or shell spawns."}
    ],
    "Credential Theft": [
        {"action": "Identity Revocation", "detail": "Immediately revoke compromised session tokens, Kerberos TGTs, and passwords for exposed accounts."},
        {"action": "Enforce Phishing-Resistant MFA", "detail": "Ensure FIDO2 / WebAuthn hardware-based multi-factor authentication is strictly required on all SSO endpoints."},
        {"action": "LSASS Protection", "detail": "Enable Windows Defender Credential Guard and RunAsPPL on endpoints to prevent LSASS memory dumping."},
        {"action": "Audit Privilege Escalation", "detail": "Inspect Active Directory audit logs for anomalous additions to Domain Admins or sensitive security groups."}
    ],
    "Malware": [
        {"action": "EDR Remediation", "detail": "Trigger automated host isolation and endpoint remediation tasks to terminate malicious processes and delete scheduled tasks."},
        {"action": "Persistence Audit", "detail": "Check registry run keys, scheduled tasks, WMI event subscriptions, and startup directories on affected hosts."},
        {"action": "Network C2 Blocking", "detail": "Implement egress filtering on outbound ports and block discovered C2 IPs and domains."},
        {"action": "YARA / Hash Hunting", "detail": "Execute enterprise-wide threat hunts using extracted MD5/SHA256 hashes."}
    ],
    "Web Application Attack": [
        {"action": "Input Sanitization & Parameterization", "detail": "Implement strict parameterized queries and contextual output encoding to eradicate injection vectors."},
        {"action": "Web Shell Elimination", "detail": "Inspect web server document roots for newly created or modified scripts (.php, .jsp, .aspx)."},
        {"action": "WAF Tuning", "detail": "Adjust WAF blocking rules to challenge or block SQLi, XSS, and path traversal requests."}
    ],
    "Data Exfiltration": [
        {"action": "Egress Throttling & Severing", "detail": "Terminate active external TCP/UDP connections to untrusted file-hosting services and cloud storage endpoints."},
        {"action": "DLP Audit", "detail": "Analyze outbound data volumes on firewall logs to quantify the extent and timing of exfiltrated data."},
        {"action": "Regulatory & Legal Notification", "detail": "Notify internal legal and data protection teams regarding potential breach of personal data (PII/PHI)."}
    ],
    "Denial of Service": [
        {"action": "DDoS Mitigation Activation", "detail": "Engage cloud DDoS mitigation scrubbing provider (e.g., Cloudflare, Akamai, AWS Shield)."},
        {"action": "Rate Limiting", "detail": "Enforce strict IP connection rate limiting and syn-cookie protection on edge load balancers."}
    ],
    "Reconnaissance": [
        {"action": "Port Hardening", "detail": "Review external firewall rules to ensure non-essential ports are closed or restricted behind VPN."},
        {"action": "Threat Hunting", "detail": "Correlate probing source IPs with ongoing authentication attempts across exposed VPN and mail services."}
    ],
    "Benign or Informational": [
        {"action": "Documentation", "detail": "Document the verified benign nature or routine maintenance activity in the SOC shift log."},
        {"action": "Tuning Rule Baseline", "detail": "Update detection filters or alert exclusion lists if this activity triggered a false-positive alarm."}
    ]
}

class RecommendationEngine:
    @classmethod
    def generate_recommendations(cls, category: str, indicators: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        recs = RECOMMENDATIONS_BY_CATEGORY.get(category, [
            {"action": "Indicator Correlating", "detail": "Search SIEM and firewall logs for the presence of extracted indicators over the past 30 days."},
            {"action": "Asset Verification", "detail": "Identify internal systems that may have communicated with the flagged infrastructure."},
            {"action": "Continuous Monitoring", "detail": "Add extracted IOCs to threat intelligence feeds for automated alerting."}
        ])
        return recs
