import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Curated cybersecurity knowledge entities
CYBER_ENTITIES = {
    "MALWARE": [
        "Cobalt Strike", "LockBit", "Emotet", "TrickBot", "RedLine Stealer", "RedLine",
        "AgentTesla", "Agent Tesla", "BlackCat", "ALPHV", "WannaCry", "Conti", "Ryuk",
        "DarkSide", "REvil", "Mimikatz", "Qakbot", "Qbot", "DanaBot", "SmokeLoader",
        "AsyncRAT", "Remcos", "NjRAT", "GuLoader", "IcedID", "Bumblebee", "Pikabot",
        "BlackBasta", "Akira", "Royal Ransomware", "Play Ransomware", "Medusa"
    ],
    "THREAT_ACTOR": [
        "APT28", "Fancy Bear", "APT29", "Cozy Bear", "Lazarus Group", "Lazarus",
        "FIN7", "TA505", "Sandworm", "MuddyWater", "Turla", "Volt Typhoon",
        "Scattered Spider", "Lapsus$", "UNC3944", "Wizard Spider", "Silence",
        "DarkHotel", "Kimsuky", "Mustang Panda", "Salt Typhoon"
    ],
    "SECURITY_TOOL": [
        "CrowdStrike", "Windows Defender", "Defender", "SentinelOne", "Splunk",
        "Suricata", "Snort", "Wireshark", "Metasploit", "Nmap", "Burp Suite",
        "BloodHound", "YARA", "Sysmon", "Zeek", "Palo Alto", "Fortinet"
    ],
    "NAMED_VULNERABILITY": [
        "Log4j", "Log4Shell", "Spring4Shell", "ProxyLogon", "ProxyShell",
        "EternalBlue", "PrintNightmare", "Zerologon", "Follina", "Citrix Bleed"
    ]
}

class EntityExtractor:
    """
    Extracts cybersecurity-specific named entities (Malware, Threat Actors, Tools,
    Named Vulnerabilities) combined with spaCy linguistic NER for Organizations and Locations.
    """

    def __init__(self):
        self.nlp = None
        try:
            import spacy
            self.nlp = spacy.load("en_core_web_sm")
            logger.info("Loaded spaCy en_core_web_sm model.")
        except Exception as e:
            logger.warning(f"Could not load spaCy en_core_web_sm: {e}. Falling back to rule-based NER.")

    def extract_entities(self, text: str) -> List[Dict[str, Any]]:
        if not text:
            return []

        results: List[Dict[str, Any]] = []
        seen_keys = set()

        # 1. Regex/Dictionary matching for cybersecurity taxonomy
        for category, entity_list in CYBER_ENTITIES.items():
            for entity in entity_list:
                pattern = rf'\b{re.escape(entity)}\b'
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    val = match.group(0)
                    key = f"{category}:{val.lower()}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        start, end = match.start(), match.end()
                        results.append({
                            "entity_type": category,
                            "entity_value": entity,  # standardized casing
                            "evidence_snippet": self._get_snippet(text, start, end),
                            "confidence": 0.95,
                            "verification_status": "Unverified (Automated Detection)"
                        })

        # 2. Extract standard spaCy entities (ORG, GPE, PERSON)
        if self.nlp:
            try:
                # Limit text size processed by spacy to prevent overhead on massive inputs
                doc = self.nlp(text[:100000])
                for ent in doc.ents:
                    if ent.label_ in ("ORG", "GPE", "PERSON"):
                        val = ent.text.strip()
                        # Skip short acronyms or numbers
                        if len(val) < 3 or val.isdigit():
                            continue
                        # Skip if already identified in cyber entities
                        key = f"{ent.label_}:{val.lower()}"
                        if key not in seen_keys:
                            seen_keys.add(key)
                            start, end = ent.start_char, ent.end_char
                            results.append({
                                "entity_type": ent.label_,
                                "entity_value": val,
                                "evidence_snippet": self._get_snippet(text, start, end),
                                "confidence": 0.85,
                                "verification_status": "Unverified (spaCy NER)"
                            })
            except Exception as e:
                logger.error(f"Error in spaCy NER processing: {e}")

        return results

    @staticmethod
    def _get_snippet(text: str, start: int, end: int, context_chars: int = 50) -> str:
        snippet_start = max(0, start - context_chars)
        snippet_end = min(len(text), end + context_chars)
        prefix = "..." if snippet_start > 0 else ""
        suffix = "..." if snippet_end < len(text) else ""
        return f"{prefix}{text[snippet_start:snippet_end].strip()}{suffix}"

entity_extractor = EntityExtractor()
