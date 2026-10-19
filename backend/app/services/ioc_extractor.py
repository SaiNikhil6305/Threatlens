import re
import ipaddress
from typing import List, Dict, Any, Optional

# Top-level domains for domain verification
VALID_TLDS = {
    "com", "org", "net", "io", "gov", "edu", "mil", "int", "info", "biz",
    "co", "uk", "de", "ru", "cn", "nl", "fr", "eu", "top", "xyz", "club",
    "online", "site", "vip", "icu", "space", "live", "tech", "store", "pro",
    "me", "cc", "ws", "tv", "us", "ca", "au", "in", "br", "ch", "jp", "kr",
    "onion", "local"
}

# File extensions to exclude from domain extraction false positives
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bin", "dat", "txt", "pdf", "doc", "docx", "xls",
    "xlsx", "ppt", "pptx", "zip", "rar", "7z", "tar", "gz", "py", "sh",
    "bat", "cmd", "ps1", "vbs", "js", "ts", "json", "xml", "yaml", "yml",
    "png", "jpg", "jpeg", "gif", "svg", "css", "html", "php", "asp", "aspx"
}

class IOCExtractor:
    """
    Robust Indicator of Compromise (IoC) extraction engine.
    Supports standard indicators, defanged formats, evidence context snippets,
    strict IP validation, and safe defanging for analyst display.
    """

    @staticmethod
    def refang(text: str) -> str:
        """Converts defanged syntax into normalized technical representations."""
        result = text
        result = re.sub(r'hxxp://', 'http://', result, flags=re.IGNORECASE)
        result = re.sub(r'hxxps://', 'https://', result, flags=re.IGNORECASE)
        result = re.sub(r'h\[xx\]ps?://', 'https://', result, flags=re.IGNORECASE)
        result = re.sub(r'\[\.\]|\(\.\)|\[dot\]', '.', result, flags=re.IGNORECASE)
        result = re.sub(r'\[at\]|\[@\]|\(at\)', '@', result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def defang(value: str, ioc_type: str) -> str:
        """Safely defangs indicators so analysts cannot accidentally click or trigger them."""
        if not value:
            return ""
        if ioc_type == "url":
            val = re.sub(r'^https://', 'hxxps://', value, flags=re.IGNORECASE)
            val = re.sub(r'^http://', 'hxxp://', val, flags=re.IGNORECASE)
            return val.replace('.', '[.]')
        elif ioc_type in ("domain", "ipv4"):
            return value.replace('.', '[.]')
        elif ioc_type == "email":
            return value.replace('@', '[at]').replace('.', '[.]')
        return value

    @staticmethod
    def is_valid_ipv4(ip_str: str) -> bool:
        try:
            ip = ipaddress.IPv4Address(ip_str)
            # Exclude loopback or broadcast 255.255.255.255 from threat detections if desired,
            # but allow RFC 1918 / RFC 5737 documentation test IPs
            return True
        except ValueError:
            return False

    @classmethod
    def extract_all(cls, text: str) -> List[Dict[str, Any]]:
        """
        Extracts all technical indicators from text, recording start/end offsets,
        evidence snippets, normalized values, and safe defanged representations.
        """
        if not text:
            return []

        indicators: List[Dict[str, Any]] = []

        # 1. URLs (including defanged hxxp/hxxps)
        url_pattern = re.compile(
            r'(?:https?|hxxps?|ftp)://[^\s<>"\',;]+|'
            r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>"\',;]*)?',
            re.IGNORECASE
        )
        
        # We also specifically look for standard HTTP/HTTPS/HXXP
        protocol_url_pattern = re.compile(
            r'\b(?:https?|hxxps?|ftp)://(?:[a-zA-Z0-9_\-\[\]\(\)]+\.)+[a-zA-Z0-9_\-\[\]\(\)]+(?::\d+)?(?:/[^\s<>"\',;]*)?',
            re.IGNORECASE
        )

        for match in protocol_url_pattern.finditer(text):
            raw_val = match.group(0).rstrip('.,;:)!?"\'')
            refanged = cls.refang(raw_val)
            start, end = match.start(), match.start() + len(raw_val)
            indicators.append({
                "original_value": raw_val,
                "normalized_value": refanged,
                "defanged_value": cls.defang(refanged, "url"),
                "indicator_type": "url",
                "start": start,
                "end": end,
                "evidence_snippet": cls._get_snippet(text, start, end),
                "confidence": 0.95
            })

        # 2. IPv4 Addresses (including defanged like 192[.]168[.]1[.]1)
        # Matches d.d.d.d and d[.]d[.]d[.]d
        ip_pattern = re.compile(
            r'\b(\d{1,3}(?:\[\.\]|\(\.\)|\.|\b\[dot\]\b)\d{1,3}(?:\[\.\]|\(\.\)|\.|\b\[dot\]\b)\d{1,3}(?:\[\.\]|\(\.\)|\.|\b\[dot\]\b)\d{1,3})\b'
        )

        for match in ip_pattern.finditer(text):
            raw_val = match.group(1)
            refanged = cls.refang(raw_val)
            if cls.is_valid_ipv4(refanged):
                # Ensure it's not part of an extracted URL
                start, end = match.start(), match.end()
                if not any(i["indicator_type"] == "url" and i["start"] <= start and i["end"] >= end for i in indicators):
                    indicators.append({
                        "original_value": raw_val,
                        "normalized_value": refanged,
                        "defanged_value": cls.defang(refanged, "ipv4"),
                        "indicator_type": "ipv4",
                        "start": start,
                        "end": end,
                        "evidence_snippet": cls._get_snippet(text, start, end),
                        "confidence": 0.98
                    })

        # 3. Email Addresses (including user[at]example[.]com)
        email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+(?:\@|\[at\]|\[@\]|\(at\))[A-Za-z0-9.-]+(?:\[\.\]|\.|\b\[dot\]\b)[A-Za-z]{2,}\b',
            re.IGNORECASE
        )
        for match in email_pattern.finditer(text):
            raw_val = match.group(0).rstrip('.,;:)!?"\'')
            refanged = cls.refang(raw_val)
            start, end = match.start(), match.start() + len(raw_val)
            indicators.append({
                "original_value": raw_val,
                "normalized_value": refanged.lower(),
                "defanged_value": cls.defang(refanged.lower(), "email"),
                "indicator_type": "email",
                "start": start,
                "end": end,
                "evidence_snippet": cls._get_snippet(text, start, end),
                "confidence": 0.95
            })

        # 4. Domains (standalone, not inside URLs or emails)
        domain_pattern = re.compile(
            r'\b((?:[a-zA-Z0-9-]{1,63}(?:\[\.\]|\(\.\)|\.|\b\[dot\]\b))+([a-zA-Z]{2,}))\b',
            re.IGNORECASE
        )
        for match in domain_pattern.finditer(text):
            raw_val = match.group(1).rstrip('.,;:)!?"\'')
            tld = match.group(2).lower()
            refanged = cls.refang(raw_val).lower()
            
            # Skip if TLD is a known file extension or not a recognized TLD
            if tld in FILE_EXTENSIONS or tld not in VALID_TLDS:
                continue
                
            # Skip if it is an IP address
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', refanged):
                continue
                
            start, end = match.start(), match.start() + len(raw_val)
            # Skip if already part of an extracted URL or email
            if any(i["indicator_type"] in ("url", "email") and i["start"] <= start and i["end"] >= end for i in indicators):
                continue

            indicators.append({
                "original_value": raw_val,
                "normalized_value": refanged,
                "defanged_value": cls.defang(refanged, "domain"),
                "indicator_type": "domain",
                "start": start,
                "end": end,
                "evidence_snippet": cls._get_snippet(text, start, end),
                "confidence": 0.92
            })

        # 5. Hashes (MD5, SHA-1, SHA-256)
        # SHA-256: 64 hex chars
        sha256_pattern = re.compile(r'\b([a-fA-F0-9]{64})\b')
        for match in sha256_pattern.finditer(text):
            val = match.group(1).lower()
            start, end = match.start(), match.end()
            indicators.append({
                "original_value": match.group(1),
                "normalized_value": val,
                "defanged_value": val,
                "indicator_type": "sha256",
                "start": start,
                "end": end,
                "evidence_snippet": cls._get_snippet(text, start, end),
                "confidence": 0.99
            })

        # SHA-1: 40 hex chars
        sha1_pattern = re.compile(r'\b([a-fA-F0-9]{40})\b')
        for match in sha1_pattern.finditer(text):
            val = match.group(1).lower()
            start, end = match.start(), match.end()
            # Ensure not substring of sha256
            if not any(i["indicator_type"] == "sha256" and i["start"] <= start and i["end"] >= end for i in indicators):
                indicators.append({
                    "original_value": match.group(1),
                    "normalized_value": val,
                    "defanged_value": val,
                    "indicator_type": "sha1",
                    "start": start,
                    "end": end,
                    "evidence_snippet": cls._get_snippet(text, start, end),
                    "confidence": 0.99
                })

        # MD5: 32 hex chars
        md5_pattern = re.compile(r'\b([a-fA-F0-9]{32})\b')
        for match in md5_pattern.finditer(text):
            val = match.group(1).lower()
            start, end = match.start(), match.end()
            # Ensure not substring of sha1 or sha256
            if not any(i["indicator_type"] in ("sha256", "sha1") and i["start"] <= start and i["end"] >= end for i in indicators):
                indicators.append({
                    "original_value": match.group(1),
                    "normalized_value": val,
                    "defanged_value": val,
                    "indicator_type": "md5",
                    "start": start,
                    "end": end,
                    "evidence_snippet": cls._get_snippet(text, start, end),
                    "confidence": 0.95
                })

        # 6. CVE identifiers
        cve_pattern = re.compile(r'\b(CVE-\d{4}-\d{4,7})\b', re.IGNORECASE)
        for match in cve_pattern.finditer(text):
            val = match.group(1).upper()
            start, end = match.start(), match.end()
            indicators.append({
                "original_value": match.group(1),
                "normalized_value": val,
                "defanged_value": val,
                "indicator_type": "cve",
                "start": start,
                "end": end,
                "evidence_snippet": cls._get_snippet(text, start, end),
                "confidence": 1.0
            })

        # Deduplicate while preserving earliest start/end and evidence
        deduped: Dict[str, Dict[str, Any]] = {}
        for ind in indicators:
            key = f"{ind['indicator_type']}:{ind['normalized_value']}"
            if key not in deduped:
                deduped[key] = ind

        return list(deduped.values())

    @staticmethod
    def _get_snippet(text: str, start: int, end: int, context_chars: int = 70) -> str:
        """Extracts context surrounding the indicator for analyst evidence."""
        snippet_start = max(0, start - context_chars)
        snippet_end = min(len(text), end + context_chars)
        prefix = "..." if snippet_start > 0 else ""
        suffix = "..." if snippet_end < len(text) else ""
        return f"{prefix}{text[snippet_start:snippet_end].strip()}{suffix}"
