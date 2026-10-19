import logging
from sqlalchemy.orm import Session
from app.database.session import engine, Base, SessionLocal
from app.models.entities import AttackTechnique

logger = logging.getLogger(__name__)

# Curated reference MITRE ATT&CK techniques with tactics and descriptions
MITRE_ATTACK_SEEDS = [
    {
        "technique_id": "T1566",
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems via spearphishing attachments, links, or services.",
        "url": "https://attack.mitre.org/techniques/T1566/"
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program using software, web, or protocol vulnerabilities.",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
    {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters (PowerShell, Bash, Python, Windows Command Shell) to execute malicious commands.",
        "url": "https://attack.mitre.org/techniques/T1059/"
    },
    {
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic": "Execution",
        "description": "An adversary may rely upon specific actions by a user, such as executing a malicious file or clicking a malicious link.",
        "url": "https://attack.mitre.org/techniques/T1204/"
    },
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, or Privilege Escalation.",
        "url": "https://attack.mitre.org/techniques/T1078/"
    },
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt credential guessing or password spraying against target accounts.",
        "url": "https://attack.mitre.org/techniques/T1110/"
    },
    {
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials from the operating system to obtain account login and credential material.",
        "url": "https://attack.mitre.org/techniques/T1003/"
    },
    {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability of system and network resources (Ransomware operations).",
        "url": "https://attack.mitre.org/techniques/T1486/"
    },
    {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform Endpoint Denial of Service attacks to degrade or block the availability of services to users.",
        "url": "https://attack.mitre.org/techniques/T1499/"
    },
    {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
        "url": "https://attack.mitre.org/techniques/T1041/"
    },
    {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on hosts in a network to identify vulnerable targets.",
        "url": "https://attack.mitre.org/techniques/T1046/"
    },
    {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using OSI application layer protocols (HTTP, HTTPS, DNS) to blend in with normal network traffic.",
        "url": "https://attack.mitre.org/techniques/T1071/"
    },
    {
        "technique_id": "T1505",
        "technique_name": "Server Software Component: Web Shell",
        "tactic": "Persistence",
        "description": "Adversaries may backdoor web servers by installing a web shell to establish persistent access and execute arbitrary commands.",
        "url": "https://attack.mitre.org/techniques/T1505/"
    },
    {
        "technique_id": "T1021",
        "technique_name": "Remote Services: RDP / SSH",
        "tactic": "Lateral Movement",
        "description": "Adversaries may log into remote systems using valid credentials over remote desktop or secure shell services.",
        "url": "https://attack.mitre.org/techniques/T1021/"
    },
    {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities in elevated processes or the operating system kernel to elevate access privileges.",
        "url": "https://attack.mitre.org/techniques/T1068/"
    }
]

def init_db():
    Base.metadata.create_all(bind=engine)
    db: Session = SessionLocal()
    try:
        # Seed MITRE techniques if not already populated
        existing = db.query(AttackTechnique).count()
        if existing == 0:
            for seed in MITRE_ATTACK_SEEDS:
                tech = AttackTechnique(
                    technique_id=seed["technique_id"],
                    technique_name=seed["technique_name"],
                    tactic=seed["tactic"],
                    description=seed["description"],
                    mapping_source="MITRE ATT&CK Enterprise v14",
                    url=seed.get("url")
                )
                db.add(tech)
            db.commit()
            logger.info("Successfully seeded reference MITRE ATT&CK dataset.")
    except Exception as e:
        db.rollback()
        logger.error(f"Error seeding database: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
