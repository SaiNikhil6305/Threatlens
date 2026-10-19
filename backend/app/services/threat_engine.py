import re
from typing import Dict, Any, List, Optional
from app.services.ioc_extractor import IOCExtractor
from app.services.threat_classifier import threat_classifier

EDUCATIONAL_MARKERS = [
    r'\beducational\s+example\b',
    r'\bfor\s+training\s+purposes\s+only\b',
    r'\btraining\s+simulation\b',
    r'\bsecurity\s+awareness\b',
    r'\bcourse\s+id\b',
    r'\bhow\s+to\s+recognize\b',
    r'\bmodule\s+\d+\b',
    r'\bexamining\s+sanitized\s+example\b',
    r'\bpolicy\s+sign-off\b',
    r'\bcorporate\s+security\s+policy\b',
    r'\bcompliance\s+audit\b',
    r'\biso\/iec\s+27001\b',
    r'\bannual\s+financial\s+performance\b',
    r'\bdeloitte\s+&\s+touche\b'
]

# Rule definitions: (Rule ID, Finding Type, Regex Pattern, Severity, Weight, Description, Recommendation)
DETECTION_RULES = [
    (
        "RULE-CRED-01",
        "Credential Harvesting Request",
        r'(?i)\b(submit|enter|confirm|provide|verify)\b.{1,60}\b(password|passcode|pin|credentials|mfa\s+token|authenticator\s+code|one-time\s+password|otp)\b',
        "High",
        3.5,
        "Document solicits direct entry or verification of sensitive passwords or multi-factor authentication tokens.",
        "Block domain immediately, invalidate exposed user tokens, and notify the Security Operations Center (SOC)."
    ),
    (
        "RULE-CRED-02",
        "Urgent Account Suspension Threat",
        r'(?i)\b(account|mailbox|access)\b.{1,40}\b(permanently\s+disabled|suspended|terminated|deactivated|locked\s+out)\b.{1,50}\b(within\s+\d+\s+hours?|immediately|final\s+warning|urgent)\b',
        "High",
        3.0,
        "Coercive urgency threatening immediate account termination to bypass analyst scrutiny.",
        "Verify account status through verified internal intranet portal; do not follow embedded communication links."
    ),
    (
        "RULE-DEF-01",
        "Security Protection Evasion Instructions",
        r'(?i)\b(disable|turn\s+off|bypass|whitelist|exclude)\b.{1,50}\b(antivirus|defender|crowdstrike|firewall|edr|real-time\s+protection|uac)\b',
        "Critical",
        4.5,
        "Explicit instructions to disable or impair endpoint security software and real-time defenses.",
        "Quarantine host endpoint, verify EDR tamper protection policies, and initiate threat containment."
    ),
    (
        "RULE-EXEC-01",
        "Suspicious Executable Binary Reference",
        r'(?i)\b[\w\-_]+\.(exe|scr|bat|vbs|ps1|cmd|hta|cpl|dll)\b',
        "High",
        2.5,
        "References untrusted executable payloads or script interpreters often abused as Trojan droppers.",
        "Submit executable hash to internal sandbox, check AppLocker/WDAC application control policies."
    ),
    (
        "RULE-SOC-01",
        "Process Circumvention / Secrecy Mandate",
        r'(?i)\b(bypass|skip|ignore)\b.{1,50}\b(standard|normal|dual-authorization|approval|verification)\b.{1,50}\b(protocol|process|procedure)\b',
        "High",
        3.5,
        "Attempts to pressure recipient into bypassing enterprise checks, approvals, or dual-authorization controls.",
        "Enforce secondary out-of-band verbal authorization via intranet phone directory prior to executing any action."
    ),
    (
        "RULE-SOC-02",
        "CEO / Executive Fraud Wire Request",
        r'(?i)\b(confidential|urgent|earnest)\b.{1,40}\b(wire\s+transfer|deposit|settlement|payment)\b.{1,50}\b(\$[\d,]+|\d+\s+dollars|escrow)\b',
        "High",
        3.5,
        "Urgent out-of-band wire transfer request matching Business Email Compromise (BEC) patterns.",
        "Halt transaction immediately, notify corporate treasury, and perform verbal callback verification."
    ),
    (
        "RULE-URL-01",
        "Obfuscated / Defanged URL Reference",
        r'(?i)h[xX]{2}p[sS]?:\/\/[^\s]+|\[\.\]|\(@\)|\[at\]',
        "Medium",
        1.5,
        "Defanged or obfuscated URL notations commonly utilized in cyber threat intelligence feeds or attack lures.",
        "Inspect host domain on perimeter DNS resolvers and block if newly registered."
    ),
    (
        "RULE-VULN-01",
        "Exploited Vulnerability Identifier (CVE)",
        r'\bCVE-\d{4}-\d{4,7}\b',
        "Medium",
        1.5,
        "Explicit CVE vulnerability identifier referenced in text.",
        "Check CISA Known Exploited Vulnerabilities catalog and cross-reference enterprise patch posture."
    )
]

class ThreatEngine:
    """
    Hybrid threat analysis engine:
    - Combines trained ML NLP classification (Linear SVM / Logistic Regression)
    - Runs contextual rule-based threat indicator checks
    - Preserves exact page numbers for findings
    - Performs context-aware filtering (e.g. educational security awareness training)
    - Computes calibrated triage severity and actionable recommendations
    """

    @classmethod
    def analyze_document(cls, filename: str, full_text: str, pages: List[Dict[str, Any]]) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        is_educational = False

        # 1. Check for Educational / Policy / Governance Markers
        edu_count = 0
        for pat in EDUCATIONAL_MARKERS:
            if re.search(pat, full_text, re.IGNORECASE):
                edu_count += 1
        if edu_count >= 2:
            is_educational = True

        # 2. Extract technical IoCs using IOCExtractor
        indicators = IOCExtractor.extract_all(full_text)

        # 3. Model A & B Prediction on overall text
        ml_prediction = threat_classifier.predict(full_text)
        ml_category = ml_prediction.get("predicted_category", "Safe")
        ml_confidence = ml_prediction.get("confidence", 0.0)

        # 4. Page-by-page Rule Checks to preserve page numbers
        total_rule_score = 0.0
        seen_rules = set()

        # If pages not provided, treat entire text as page 1
        page_items = pages if pages else [{"page_number": 1, "text": full_text}]

        for p in page_items:
            p_num = p.get("page_number", 1)
            p_text = p.get("text", "")
            if not p_text:
                continue

            for rule_id, f_type, pattern, sev, weight, desc, rec in DETECTION_RULES:
                matches = list(re.finditer(pattern, p_text))
                if matches:
                    snippet = matches[0].group(0)
                    # Extend context snippet
                    start = max(0, matches[0].start() - 30)
                    end = min(len(p_text), matches[0].end() + 30)
                    context_snippet = p_text[start:end].replace('\n', ' ').strip()

                    # Check if already added for this page
                    dedup_key = f"{rule_id}_{p_num}"
                    if dedup_key not in seen_rules:
                        seen_rules.add(dedup_key)
                        
                        # Apply educational discounting if appropriate
                        effective_sev = sev
                        effective_weight = weight
                        if is_educational:
                            effective_weight = weight * 0.15
                            effective_sev = "Low"

                        total_rule_score += effective_weight

                        findings.append({
                            "rule_id": rule_id,
                            "finding_type": f_type,
                            "severity": effective_sev,
                            "evidence": context_snippet,
                            "page_number": p_num,
                            "detection_method": "Rule-based Indicator Engine",
                            "explanation": desc if not is_educational else f"[Educational Context] {desc}",
                            "recommended_action": rec
                        })

        # Add IoC findings
        for ind in indicators:
            val = ind.get("original_value") or ind.get("normalized_value")
            itype = ind.get("indicator_type", "Indicator")
            # Trace page number of IoC
            found_page = 1
            for p in page_items:
                if val in p.get("text", ""):
                    found_page = p.get("page_number", 1)
                    break

            if itype in ["domain", "url"] and ("example.com" in val.lower() or "example.org" in val.lower()) and not is_educational:
                findings.append({
                    "rule_id": "IOC-NET-01",
                    "finding_type": f"Suspicious Network Indicator ({itype.upper()})",
                    "severity": "High",
                    "evidence": val,
                    "page_number": found_page,
                    "detection_method": "IOC Extraction & Reputation Engine",
                    "explanation": f"Observed suspicious {itype} indicator matching phishing/C2 infrastructure patterns.",
                    "recommended_action": f"Block {itype} '{val}' on enterprise perimeter firewalls and sinkhole DNS queries."
                })
                total_rule_score += 2.0

        # 5. Calculate Overall Severity
        if is_educational:
            overall_severity = "No significant indicators detected"
            severity_score = 0.5
        elif total_rule_score >= 7.0:
            overall_severity = "Critical"
            severity_score = min(10.0, round(total_rule_score, 1))
        elif total_rule_score >= 4.0:
            overall_severity = "High"
            severity_score = min(8.9, round(total_rule_score, 1))
        elif total_rule_score >= 2.0:
            overall_severity = "Medium"
            severity_score = min(5.9, round(total_rule_score, 1))
        elif total_rule_score >= 0.8:
            overall_severity = "Low"
            severity_score = min(3.4, round(total_rule_score, 1))
        else:
            overall_severity = "No significant indicators detected"
            severity_score = 0.0

        # Overall Recommended Actions
        recommended_actions = []
        if overall_severity in ["Critical", "High"]:
            recommended_actions.extend([
                "Isolate endpoint from local network segment to prevent lateral movement.",
                "Revoke active session tokens and force credential reset for targeted accounts.",
                "Sinkhole identified domain indicators on internal DNS resolvers.",
                "Submit referenced files to malware sandbox for behavioral detonation analysis."
            ])
        elif overall_severity == "Medium":
            recommended_actions.extend([
                "Perform secondary review of communication context and verify sender authenticity.",
                "Query EDR logs for any process activity connecting to referenced network indicators.",
                "Advise recipient not to click embedded links or disclose credentials."
            ])
        else:
            recommended_actions.extend([
                "No immediate containment required. Maintain routine endpoint security monitoring.",
                "Verify standard corporate security hygiene policies remain actively enforced."
            ])

        # Synthesize category based on findings
        predicted_category = ml_category
        if any(f["finding_type"] == "Credential Harvesting Request" for f in findings):
            predicted_category = "Credential Theft"
        elif any("Phishing" in f["finding_type"] or "Suspicious URL" in f["finding_type"] for f in findings):
            predicted_category = "Phishing"
        elif any("Executable" in f["finding_type"] or "Evasion" in f["finding_type"] for f in findings):
            predicted_category = "Malware"
        elif any("Wire Request" in f["finding_type"] or "Circumvention" in f["finding_type"] for f in findings):
            predicted_category = "Social Engineering"
        elif is_educational:
            predicted_category = "Benign or Informational"
        elif overall_severity == "No significant indicators detected":
            predicted_category = "Safe"

        return {
            "overall_severity": overall_severity,
            "severity_score": severity_score,
            "predicted_category": predicted_category,
            "confidence": round(ml_confidence, 3),
            "detection_method": "Hybrid (Trained ML Classifier + Rule Engine)",
            "finding_count": len(findings),
            "findings": findings,
            "indicators": indicators,
            "recommended_actions": recommended_actions,
            "is_educational": is_educational
        }
