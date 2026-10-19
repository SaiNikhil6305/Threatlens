import re
from typing import List, Dict, Any, Optional

class SeverityEngine:
    """
    Explainable, rule-based severity assessment engine.
    Calculates severity levels (Critical, High, Medium, Low, Informational)
    with explicit triggered rules, missing information, and investigative next steps.
    """

    @classmethod
    def assess_severity(
        cls,
        text: str,
        category: str,
        indicators: List[Dict[str, Any]],
        entities: List[Dict[str, Any]],
        source: Optional[str] = None
    ) -> Dict[str, Any]:
        text_lower = text.lower()
        score = 0.0
        triggered_rules: List[Dict[str, Any]] = []
        missing_info: List[str] = []
        recommended_steps: List[str] = []

        # --- Rule 1: High-Impact Destructive or Encryption Operations ---
        if any(term in text_lower for term in ["encrypted files", "ransom note", "shadow copies deleted", "double extortion"]):
            if any(term in text_lower for term in ["confirmed widespread", "active encryption", "domain controller compromised"]):
                score += 5.0
                triggered_rules.append({
                    "rule": "ACTIVE_RANSOMWARE_ENCRYPTION_WIDESPREAD",
                    "description": "Evidence of widespread encryption or domain controller disruption detected.",
                    "weight": 5.0
                })
            else:
                score += 3.5
                triggered_rules.append({
                    "rule": "RANSOMWARE_INDICATIONS",
                    "description": "Ransomware-related extortion or encryption artifacts identified in narrative.",
                    "weight": 3.5
                })
        elif category == "Ransomware":
            score += 2.5
            triggered_rules.append({
                "rule": "RANSOMWARE_CATEGORY_BASE",
                "description": "Incident classified under Ransomware category.",
                "weight": 2.5
            })

        # --- Rule 2: Active Remote Code Execution / Critical CVE Exploitation ---
        cve_indicators = [i for i in indicators if i.get("indicator_type") == "cve"]
        if cve_indicators or "remote code execution" in text_lower or "zero-day" in text_lower or "0-day" in text_lower:
            if "actively exploited" in text_lower or "in the wild" in text_lower:
                score += 4.0
                triggered_rules.append({
                    "rule": "ACTIVE_ZERO_DAY_OR_RCE_EXPLOITATION",
                    "description": "Unauthenticated Remote Code Execution or zero-day vulnerability actively exploited in the wild.",
                    "weight": 4.0
                })
            else:
                score += 2.5
                triggered_rules.append({
                    "rule": "VULNERABILITY_EXPLOITATION_DISCLOSED",
                    "description": "Specific CVE or exploitable flaw referenced in intelligence report.",
                    "weight": 2.5
                })

        # --- Rule 3: Credential Dumping / Identity Infrastructure Compromise ---
        if any(term in text_lower for term in ["mimikatz", "lsass", "ntds.dit", "kerberoasting", "active directory admin", "domain admin"]):
            score += 3.5
            triggered_rules.append({
                "rule": "CREDENTIAL_DUMPING_IDENTITY_THREAT",
                "description": "Privileged credential access (LSASS / Domain Admin credentials) compromised.",
                "weight": 3.5
            })

        # --- Rule 4: Data Exfiltration / Extortion Leak ---
        if any(term in text_lower for term in ["data exfiltration", "exfiltrated gigabytes", "stolen customer data", "megaupload", "rclone"]):
            score += 3.0
            triggered_rules.append({
                "rule": "DATA_EXFILTRATION_VERIFIED",
                "description": "Evidence indicates sensitive internal data has been staged or exfiltrated.",
                "weight": 3.0
            })

        # --- Rule 5: Active C2 Communication or Beaconing ---
        if any(term in text_lower for term in ["c2 beacon", "command and control", "reverse shell", "cobalt strike"]):
            score += 2.5
            triggered_rules.append({
                "rule": "ACTIVE_C2_INFRASTRUCTURE",
                "description": "Command & Control beaconing or interactive session established.",
                "weight": 2.5
            })

        # --- Rule 6: Phishing Lures or Initial Access Campaigns ---
        if category == "Phishing" or any(term in text_lower for term in ["phishing lure", "credential harvest", "spoofed login"]):
            score += 1.5
            triggered_rules.append({
                "rule": "PHISHING_INITIAL_ACCESS",
                "description": "Phishing lure detected targeting user credentials or deploying attachments.",
                "weight": 1.5
            })

        # --- Rule 7: Denial of Service / Availability Degradation ---
        if category == "Denial of Service" or "ddos" in text_lower:
            score += 2.0
            triggered_rules.append({
                "rule": "DENIAL_OF_SERVICE_ACTIVITY",
                "description": "Resource exhaustion or packet flooding impacting availability.",
                "weight": 2.0
            })

        # --- Rule 8: Reconnaissance / Port Scanning Only ---
        if category == "Reconnaissance" or any(term in text_lower for term in ["port scan", "nmap", "probing"]):
            score += 1.0
            triggered_rules.append({
                "rule": "EXTERNAL_RECONNAISSANCE_PROBE",
                "description": "Port scanning or automated network probes detected without breach.",
                "weight": 1.0
            })

        # --- Rule 9: Benign / Security Hygiene / Patch Notices ---
        if category == "Benign or Informational" or any(term in text_lower for term in ["scheduled maintenance", "routine patch", "informational notice"]):
            score = max(0.0, score - 2.0)
            triggered_rules.append({
                "rule": "ROUTINE_SECURITY_MAINTENANCE",
                "description": "Narrative reflects planned mitigation, maintenance, or advisory without confirmed compromise.",
                "weight": -2.0
            })

        # --- Presence of technical IOCs increases triage confidence ---
        if len(indicators) > 5:
            score += 1.0
            triggered_rules.append({
                "rule": "MULTIPLE_TECHNICAL_IOCS",
                "description": f"Over 5 technical indicators ({len(indicators)} total) extracted from report.",
                "weight": 1.0
            })
        elif len(indicators) == 0:
            missing_info.append("No technical indicators of compromise (IP, domain, hash) were found in the text.")

        # --- Evaluate Missing Information for Analyst ---
        if not any(term in text_lower for term in ["edr", "sysmon", "siem", "firewall log", "packet capture", "pcap"]):
            missing_info.append("Absence of telemetry or endpoint log verification (EDR/SIEM events).")
        if not any(term in text_lower for term in ["internal ip", "workstation", "server", "subnet"]):
            missing_info.append("Uncertain scope of internal asset exposure or affected subnets.")
        if "impact" not in text_lower and "downtime" not in text_lower:
            missing_info.append("Operational business impact is unspecified in the narrative.")

        # --- Recommended Investigation Steps ---
        if category == "Ransomware":
            recommended_steps.append("Immediately isolate affected hosts from the internal network VLAN.")
            recommended_steps.append("Verify integrity of offline backups and inspect VSS shadow copy states.")
            recommended_steps.append("Block all associated C2 domains and hashes on perimeter firewalls and EDR.")
        elif category == "Phishing":
            recommended_steps.append("Search email gateway logs for similar subject lines and sender addresses.")
            recommended_steps.append("Reset credentials for any users who accessed the lure URL.")
            recommended_steps.append("Submit extracted phishing URL for perimeter proxy blocklisting.")
        elif category == "Vulnerability Exploitation":
            recommended_steps.append("Identify public-facing assets running the vulnerable software version.")
            recommended_steps.append("Apply vendor security patches or apply recommended WAF virtual patch rules.")
        elif category == "Credential Theft":
            recommended_steps.append("Enforce Kerberos ticket and privileged account password changes.")
            recommended_steps.append("Audit LSASS memory access logs and investigate anomalous RDP connections.")
        else:
            recommended_steps.append("Correlate extracted indicators against internal DNS and proxy logs.")
            recommended_steps.append("Perform triage hunting in SIEM across the last 30 days of telemetry.")

        # --- Determine Final Severity Level ---
        # Scale:
        # Critical: >= 7.0
        # High: >= 4.5
        # Medium: >= 2.5
        # Low: >= 1.0
        # Informational: < 1.0
        if score >= 7.0:
            severity = "Critical"
        elif score >= 4.5:
            severity = "High"
        elif score >= 2.5:
            severity = "Medium"
        elif score >= 1.0:
            severity = "Low"
        else:
            severity = "Informational"

        return {
            "severity": severity,
            "severity_score": round(score, 1),
            "triggered_rules": triggered_rules,
            "missing_information": missing_info,
            "recommended_investigation_steps": recommended_steps,
            "assessment_disclaimer": "Initial triage assessment based on natural language heuristic scoring. Not a definitive security verdict."
        }
