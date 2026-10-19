import joblib
from typing import Dict, Any, List
from ml.config import MODEL_SAVE_PATH, VECTORIZER_SAVE_PATH, MODEL_METADATA_PATH
from ml.preprocess import clean_text

class ThreatPredictor:
    """Inference class for ThreatLens trained models."""

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.metadata = None
        self._load()

    def _load(self):
        if MODEL_SAVE_PATH.exists() and VECTORIZER_SAVE_PATH.exists():
            self.model = joblib.load(MODEL_SAVE_PATH)
            self.vectorizer = joblib.load(VECTORIZER_SAVE_PATH)
            if MODEL_METADATA_PATH.exists():
                import json
                with open(MODEL_METADATA_PATH, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

    def predict(self, text: str) -> Dict[str, Any]:
        if not self.model or not self.vectorizer:
            return {
                "label": "Unknown",
                "confidence": 0.0,
                "is_uncertain": True,
                "error": "Model not loaded"
            }

        cleaned = clean_text(text)
        if not cleaned:
            return {
                "label": "Safe",
                "confidence": 0.5,
                "is_uncertain": True,
                "error": "Empty text"
            }

        vec = self.vectorizer.transform([cleaned])
        pred_label = self.model.predict(vec)[0]

        confidence = 0.85
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(vec)[0]
            confidence = float(max(probs))

        is_uncertain = confidence < 0.65

        return {
            "label": str(pred_label),
            "confidence": round(confidence, 4),
            "is_uncertain": is_uncertain,
            "model_name": self.metadata.get("model_name", "Trained Classifier") if self.metadata else "Trained Classifier"
        }
