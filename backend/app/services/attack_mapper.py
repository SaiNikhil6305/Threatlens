import re
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.models.entities import AttackTechnique

# Technique matching heuristics with contextual evidence terms
TECHNIQUE_RULES = [
    {
        "technique_id": "T1566",
        "patterns": ["phishing", "spearphishing", "malicious email", "fake invoice", "credential harvesting link", "lure attachment"],
        "confidence": 0.90
    },
    {
        "technique_id": "T1190",
        "patterns": ["exploit public-facing", "unauthenticated rce", "cve-", "remote code execution", "vulnerability in apache", "log4j"],
        "confidence": 0.85
    },
    {
        "technique_id": "T1059",
        "patterns": ["powershell -enc", "powershell.exe", "cmd.exe", "bash script", "wscript", "cscript", "command interpreter"],
        "confidence": 0.88
    },
    {
        "technique_id": "T1204",
        "patterns": ["user execution", "clicked the link", "opened the attachment", "macro enabled", "executed the payload"],
        "confidence": 0.80
    },
    {
        "technique_id": "T1110",
        "patterns": ["brute force", "password spraying", "multiple failed login attempts", "credential guessing"],
        "confidence": 0.85
    },
    {
        "technique_id": "T1003",
        "patterns": ["mimikatz", "lsass", "credential dumping", "ntds.dit", "sam hive", "dumping password hashes"],
        "confidence": 0.92
    },
    {
        "technique_id": "T1486",
        "patterns": ["ransomware", "data encrypted", "encrypted files", "ransom note", "shadow copies", "vssadmin delete"],
        "confidence": 0.95
    },
    {
        "technique_id": "T1499",
        "patterns": ["denial of service", "ddos", "syn flood", "endpoint denial of service", "resource starvation"],
        "confidence": 0.85
    },
    {
        "technique_id": "T1041",
        "patterns": ["exfiltration over c2", "data exfiltrated", "exfiltrating stolen files", "rclone upload", "mega.nz upload"],
        "confidence": 0.86
    },
    {
        "technique_id": "T1046",
        "patterns": ["network service discovery", "port scan", "nmap", "scanning subnet", "reconnaissance sweep"],
        "confidence": 0.85
    },
    {
        "technique_id": "T1071",
        "patterns": ["http c2", "https beacon", "c2 communication", "dns tunneling", "application layer protocol"],
        "confidence": 0.80
    },
    {
        "technique_id": "T1505",
        "patterns": ["web shell", "chopper", "b374k", "backdoor on web server", "server software component"],
        "confidence": 0.90
    },
    {
        "technique_id": "T1021",
        "patterns": ["rdp connection", "remote desktop", "ssh session", "psexec", "lateral movement via rdp"],
        "confidence": 0.85
    },
    {
        "technique_id": "T1068",
        "patterns": ["privilege escalation", "elevation of privilege", "kernel exploit", "token impersonation"],
        "confidence": 0.85
    }
]

class AttackMapper:
    """
    Maps threat report evidence to official MITRE ATT&CK techniques with
    contextual snippet evidence and confidence scoring.
    """

    @classmethod
    def map_techniques(cls, text: str, db: Session) -> List[Dict[str, Any]]:
        if not text:
            return []

        text_lower = text.lower()
        matched_techniques = []

        for rule in TECHNIQUE_RULES:
            tech_id = rule["technique_id"]
            for pattern in rule["patterns"]:
                match = re.search(rf'\b{re.escape(pattern)}\b', text_lower)
                if match:
                    # Query DB for technique metadata
                    tech_db = db.query(AttackTechnique).filter(AttackTechnique.technique_id == tech_id).first()
                    if tech_db:
                        # Extract evidence snippet
                        start, end = match.start(), match.end()
                        snippet_start = max(0, start - 60)
                        snippet_end = min(len(text), end + 60)
                        snippet = f"...{text[snippet_start:snippet_end].strip()}..."

                        matched_techniques.append({
                            "database_id": tech_db.id,
                            "technique_id": tech_db.technique_id,
                            "technique_name": tech_db.technique_name,
                            "tactic": tech_db.tactic,
                            "description": tech_db.description,
                            "evidence": snippet,
                            "mapping_confidence": rule["confidence"],
                            "mapping_source": tech_db.mapping_source,
                            "verification_status": "Potential Mapping",
                            "url": tech_db.url
                        })
                        # Break pattern loop so we don't duplicate the same technique
                        break

        return matched_techniques
