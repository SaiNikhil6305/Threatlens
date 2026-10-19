import re
from sklearn.feature_extraction.text import TfidfVectorizer
from ml.config import TFIDF_MAX_FEATURES, TFIDF_NGRAM_RANGE

def clean_text(text: str) -> str:
    """
    Cleans raw document text:
    - Normalizes defanged notations (hxxp -> http, [.] -> ., etc.)
    - Removes control characters and excess whitespace
    - Lowercases text for consistent TF-IDF feature extraction
    """
    if not isinstance(text, str):
        return ""

    # Normalize common obfuscations/defanging
    text = re.sub(r'h[xX]{2}p([sS]?):\/\/', r'http\1://', text)
    text = text.replace('[.]', '.').replace('(.)', '.').replace('{.}', '.')
    text = text.replace('[@]', '@').replace('[at]', '@').replace('(at)', '@')

    # Remove non-printable control chars except newlines and tabs
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', ' ', text)

    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text)
    return text.strip().lower()

def build_vectorizer(
    max_features: int = TFIDF_MAX_FEATURES,
    ngram_range: tuple = TFIDF_NGRAM_RANGE
) -> TfidfVectorizer:
    """Builds and returns configured TfidfVectorizer."""
    return TfidfVectorizer(
        preprocessor=clean_text,
        max_features=max_features,
        ngram_range=ngram_range,
        min_df=2,
        max_df=0.90,
        sublinear_tf=True
    )
