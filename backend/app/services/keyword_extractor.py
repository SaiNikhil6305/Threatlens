import re
from typing import List, Dict, Any
from collections import Counter

# Cybersecurity terminology dictionary grouped by attack taxonomy
KEYWORD_TAXONOMY = {
    "Ransomware": [
        "ransomware", "ransom note", "encrypted files", "decryptor", "bitcoin",
        "monero", "double extortion", "shadow copies", "vssadmin", "data leak site"
    ],
    "Phishing": [
        "phishing", "spearphishing", "lure", "credential harvesting", "spoofed",
        "malicious attachment", "fake login", "dmarc", "spf", "invoice attachment",
        "urgent action required", "password reset"
    ],
    "Malware": [
        "malware", "trojan", "backdoor", "dropper", "payload", "c2", "command and control",
        "beacon", "c2 server", "process hollowing", "dll injection", "obfuscation"
    ],
    "Credential Theft": [
        "credential dumping", "mimikatz", "lsass", "sam database", "brute force",
        "password spray", "ntlm hash", "kerberoasting", "keylogger", "stealer"
    ],
    "Vulnerability Exploitation": [
        "cve-", "remote code execution", "rce", "zero-day", "0-day", "buffer overflow",
        "privilege escalation", "exploit", "unauthenticated", "security patch", "advisory"
    ],
    "Web Application Attack": [
        "sql injection", "sqli", "cross-site scripting", "xss", "ssrf", "server-side request forgery",
        "path traversal", "web shell", "file inclusion", "deserialization", "csrf"
    ],
    "Data Exfiltration": [
        "data exfiltration", "data theft", "mega.nz", "rclone", "exfiltrated",
        "stolen credentials", "cloud storage upload", "ftp upload", "staging directory"
    ],
    "Denial of Service": [
        "denial of service", "ddos", "syn flood", "amplification attack", "udp flood",
        "botnet", "service outage", "resource exhaustion"
    ],
    "Reconnaissance": [
        "reconnaissance", "port scanning", "nmap scan", "directory brute force",
        "subdomain enumeration", "shodan", "vulnerability scan", "network sweep"
    ],
    "Benign or Informational": [
        "routine audit", "scheduled maintenance", "false positive", "authorized penetration test",
        "best practices", "remediation verified", "informational notice", "patch released"
    ]
}

class KeywordExtractor:
    """
    Extracts relevant cybersecurity keywords, calculating category relevance scores.
    """

    @classmethod
    def extract_keywords(cls, text: str) -> Dict[str, Any]:
        if not text:
            return {"keywords": [], "category_weights": {}}

        text_lower = text.lower()
        found_keywords = []
        category_counts = Counter()

        for category, terms in KEYWORD_TAXONOMY.items():
            for term in terms:
                # Use word boundary where appropriate
                pattern = rf'\b{re.escape(term)}\b' if not term.endswith('-') else rf'{re.escape(term)}'
                matches = len(re.findall(pattern, text_lower))
                if matches > 0:
                    found_keywords.append({
                        "term": term,
                        "category": category,
                        "occurrences": matches
                    })
                    category_counts[category] += matches

        # Sort keywords by occurrences
        found_keywords.sort(key=lambda x: x["occurrences"], reverse=True)

        return {
            "keywords": found_keywords,
            "category_weights": dict(category_counts)
        }
