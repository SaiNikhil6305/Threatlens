import re
from typing import Dict, Any

class TextPreprocessor:
    """
    Safely cleans and segments text while strictly preserving technical tokens
    such as IP addresses, domains, URLs, hashes, CVEs, and defanged indicators.
    """
    
    @staticmethod
    def preprocess(text: str) -> Dict[str, Any]:
        if not text or not isinstance(text, str):
            return {
                "cleaned_text": "",
                "original_text": text or "",
                "sentence_count": 0,
                "character_count": 0,
                "word_count": 0,
                "is_empty": True
            }
        
        # Preserve original text for evidence snippet matching & indexing
        original = text
        
        # Replace non-printable characters except standard whitespace
        cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
        
        # Standardize line breaks
        cleaned = cleaned.replace('\r\n', '\n').replace('\r', '\n')
        
        # Compress multiple blank lines to at most two
        cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
        
        # Sentence splitting approximation (preserving abbreviations and IPs)
        sentences = re.split(r'(?<=[.!?])\s+(?=[A-Z0-9])', cleaned)
        sentences = [s.strip() for s in sentences if s.strip()]
        
        words = re.findall(r'\b\w+\b', cleaned)
        
        return {
            "cleaned_text": cleaned.strip(),
            "original_text": original,
            "sentence_count": len(sentences),
            "character_count": len(cleaned),
            "word_count": len(words),
            "is_empty": len(cleaned.strip()) == 0
        }
