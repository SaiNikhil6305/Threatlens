from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from app.database.session import get_db
from app.ml.evaluate_model import get_latest_evaluation
from app.ml.train_classifier import train_and_evaluate
from app.services.threat_classifier import threat_classifier

router = APIRouter(prefix="/model", tags=["Model Operations"])

class TrainRequest(BaseModel):
    algorithm: Optional[str] = "Logistic Regression"  # "Logistic Regression" or "Linear SVM"

@router.get("/status")
def get_model_status():
    """Returns active model metadata, algorithm name, and artifacts status."""
    has_model = bool(threat_classifier.model is not None)
    return {
        "is_model_loaded": has_model,
        "active_algorithm": threat_classifier.model_metadata.get("model_name") if threat_classifier.model_metadata else "Rule-based Fallback",
        "version": threat_classifier.model_metadata.get("version") if threat_classifier.model_metadata else None,
        "mode": "ML Inference" if has_model else "Rule-based Fallback"
    }

@router.get("/evaluation")
def get_model_evaluation():
    """Returns real dataset and evaluation metrics, confusion matrix, and model comparisons."""
    eval_data = get_latest_evaluation()
    return eval_data

@router.post("/train")
def train_model(payload: TrainRequest = TrainRequest()):
    """Triggers dataset training and evaluation, deploying the selected model."""
    algo = "Linear SVM" if payload.algorithm and "svm" in payload.algorithm.lower() else "Logistic Regression"
    try:
        res = train_and_evaluate(active_algorithm=algo)
        # Reload classifier in memory
        threat_classifier.load_active_model()
        return {
            "success": True,
            "message": f"Successfully trained and evaluated {algo} model ({res['version']}).",
            "version": res["version"],
            "metadata": res["metadata"],
            "evaluation": res["eval_baseline_lr"] if algo == "Logistic Regression" else res["eval_comparison_svm"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model training failed: {str(e)}")
