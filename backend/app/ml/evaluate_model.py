import logging
import json
from pathlib import Path
import joblib

from app.core.config import settings
from app.database.session import SessionLocal
from app.models.entities import ModelVersion, ModelEvaluation

logger = logging.getLogger(__name__)

def get_latest_evaluation():
    """Returns the most recent model version and evaluation metrics from database or artifacts."""
    db = SessionLocal()
    try:
        active_version = db.query(ModelVersion).filter(ModelVersion.is_active == True).first()
        if active_version and active_version.evaluations:
            latest_eval = active_version.evaluations[0]
            details = json.loads(latest_eval.evaluation_details)
            return {
                "has_trained_model": True,
                "version": active_version.version,
                "model_name": active_version.model_name,
                "dataset_reference": active_version.dataset_reference,
                "accuracy": latest_eval.accuracy,
                "precision": latest_eval.precision,
                "recall": latest_eval.recall,
                "f1_score": latest_eval.f1_score,
                "created_at": latest_eval.created_at.isoformat(),
                "details": details
            }
    finally:
        db.close()

    # Check disk artifacts if not in database
    artifacts_dir = Path(settings.MODEL_DIR)
    meta_path = artifacts_dir / "metadata.joblib"
    eval_path = artifacts_dir / "evaluation_results.joblib"
    if meta_path.exists() and eval_path.exists():
        metadata = joblib.load(meta_path)
        evals = joblib.load(eval_path)
        active_name = metadata.get("model_name", "Logistic Regression")
        key = "logistic_regression" if active_name == "Logistic Regression" else "linear_svm"
        m = evals.get(key, evals.get("logistic_regression", {}))
        return {
            "has_trained_model": True,
            "version": metadata.get("version"),
            "model_name": active_name,
            "dataset_reference": metadata.get("dataset_reference"),
            "accuracy": m.get("accuracy", 0.0),
            "precision": m.get("precision", 0.0),
            "recall": m.get("recall", 0.0),
            "f1_score": m.get("f1_score", 0.0),
            "created_at": metadata.get("trained_at"),
            "details": {
                "selected_model": active_name,
                "metrics": m,
                "comparison": evals,
                "train_samples": metadata.get("train_samples", 0),
                "test_samples": metadata.get("test_samples", 0)
            }
        }

    return {
        "has_trained_model": False,
        "message": "No trained model found. You can train baseline models (Logistic Regression & Linear SVM) using the training workflow."
    }

if __name__ == "__main__":
    print(json.dumps(get_latest_evaluation(), indent=2))
