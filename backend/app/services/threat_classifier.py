import os
import joblib
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from app.services.keyword_extractor import KeywordExtractor

logger = logging.getLogger(__name__)

SUPPORTED_CATEGORIES = [
    "Phishing",
    "Malware",
    "Ransomware",
    "Credential Theft",
    "Denial of Service",
    "Web Application Attack",
    "Vulnerability Exploitation",
    "Data Exfiltration",
    "Reconnaissance",
    "Benign or Informational",
    "Other or Unknown"
]

class ThreatClassifier:
    """
    Threat classifier service supporting:
    1. Trained scikit-learn models (TF-IDF + LogisticRegression / LinearSVC)
    2. Model artifact versioning and hot-reloading
    3. Explicit uncertainty calculation
    4. Transparent rule-based fallback when no trained model artifact is loaded
    """

    def __init__(self, artifacts_dir: Optional[str] = None):
        self.artifacts_dir = Path(artifacts_dir) if artifacts_dir else Path(__file__).resolve().parent.parent / "ml" / "artifacts"
        self.model = None
        self.vectorizer = None
        self.model_metadata = None
        self.load_active_model()

    def load_active_model(self) -> bool:
        """Attempts to load the serialized model and vectorizer from the artifacts directory."""
        model_path = self.artifacts_dir / "threat_classifier.joblib"
        vectorizer_path = self.artifacts_dir / "tfidf_vectorizer.joblib"
        meta_path = self.artifacts_dir / "metadata.joblib"

        if model_path.exists() and vectorizer_path.exists():
            try:
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vectorizer_path)
                if meta_path.exists():
                    self.model_metadata = joblib.load(meta_path)
                else:
                    self.model_metadata = {"model_name": "Logistic Regression", "version": "1.0.0"}
                logger.info(f"Loaded trained threat classification model: {self.model_metadata}")
                return True
            except Exception as e:
                logger.error(f"Failed to load model artifacts: {e}")
                self.model = None
                self.vectorizer = None
                return False
        else:
            logger.info("No trained model artifacts found on disk. Utilizing explainable rule-based fallback.")
            self.model = None
            self.vectorizer = None
            return False

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Classifies threat text. Returns category, confidence, prediction method,
        model version, uncertainty status, and supporting evidence keywords.
        """
        if not text or not text.strip():
            return {
                "predicted_category": "Other or Unknown",
                "confidence": 0.0,
                "prediction_method": "Input Validation Fallback",
                "model_version": None,
                "is_uncertain": True,
                "uncertainty_reason": "Empty or whitespace-only input provided",
                "supporting_terms": []
            }

        # 1. If trained ML model is available
        if self.model and self.vectorizer:
            try:
                vec = self.vectorizer.transform([text])
                
                # Check if model supports predict_proba (like LogisticRegression) or decision_function (LinearSVC)
                if hasattr(self.model, "predict_proba"):
                    probas = self.model.predict_proba(vec)[0]
                    classes = self.model.classes_
                    best_idx = probas.argmax()
                    best_class = classes[best_idx]
                    confidence = float(probas[best_idx])
                    
                    # Sort top probabilities for uncertainty evaluation
                    sorted_probas = sorted(probas, reverse=True)
                    margin = sorted_probas[0] - sorted_probas[1] if len(sorted_probas) > 1 else 1.0
                    is_uncertain = confidence < 0.50 or margin < 0.15
                    uncertainty_reason = "Classification confidence below threshold (< 0.50) or narrow decision margin" if is_uncertain else None
                elif hasattr(self.model, "decision_function"):
                    scores = self.model.decision_function(vec)[0]
                    classes = self.model.classes_
                    best_idx = scores.argmax()
                    best_class = classes[best_idx]
                    # Softmax approximation of decision score for display
                    import numpy as np
                    exp_scores = np.exp(scores - np.max(scores))
                    softmax_probs = exp_scores / exp_scores.sum()
                    confidence = float(softmax_probs[best_idx])
                    is_uncertain = confidence < 0.45
                    uncertainty_reason = "Decision score margin low across classes" if is_uncertain else None
                else:
                    best_class = self.model.predict(vec)[0]
                    confidence = 0.70
                    is_uncertain = False
                    uncertainty_reason = None

                # Extract supporting terms
                kw_data = KeywordExtractor.extract_keywords(text)
                supporting = [k["term"] for k in kw_data["keywords"][:5]]

                return {
                    "predicted_category": best_class,
                    "confidence": round(confidence, 3),
                    "prediction_method": f"Trained Model ({self.model_metadata.get('model_name', 'Classifier')})",
                    "model_version": self.model_metadata.get("version", "v1.0"),
                    "is_uncertain": is_uncertain,
                    "uncertainty_reason": uncertainty_reason,
                    "supporting_terms": supporting
                }
            except Exception as e:
                logger.error(f"Error during ML model inference: {e}")
                # Fall back to rule-based engine

        # 2. Transparent Rule-Based Fallback Engine
        kw_data = KeywordExtractor.extract_keywords(text)
        category_weights = kw_data["category_weights"]
        keywords = kw_data["keywords"]

        if not category_weights:
            return {
                "predicted_category": "Other or Unknown",
                "confidence": 0.30,
                "prediction_method": "Rule-based Fallback (No Model Loaded)",
                "model_version": None,
                "is_uncertain": True,
                "uncertainty_reason": "No domain-specific threat indicators or taxonomy keywords matched",
                "supporting_terms": []
            }

        # Find category with highest frequency
        top_cat = max(category_weights.items(), key=lambda x: x[1])
        cat_name, count = top_cat
        total_hits = sum(category_weights.values())
        
        # Calculate ratio confidence
        confidence = min(0.85, round(0.40 + (count / total_hits) * 0.45, 3))
        is_uncertain = total_hits < 2 or (count / total_hits < 0.40)
        
        uncertainty_reason = "Limited keyword occurrences (< 2 matches) or mixed threat indicators" if is_uncertain else None
        supporting = [k["term"] for k in keywords if k["category"] == cat_name][:5]

        return {
            "predicted_category": cat_name,
            "confidence": confidence,
            "prediction_method": "Rule-based Fallback (No Model Loaded)",
            "model_version": None,
            "is_uncertain": is_uncertain,
            "uncertainty_reason": uncertainty_reason,
            "supporting_terms": supporting
        }

threat_classifier = ThreatClassifier()
