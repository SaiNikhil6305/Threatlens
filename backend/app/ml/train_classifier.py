import os
import csv
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
import joblib
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support, confusion_matrix

from app.core.config import settings
from app.database.session import SessionLocal
from app.models.entities import ModelVersion, ModelEvaluation, AuditEvent

logger = logging.getLogger(__name__)

def train_and_evaluate(dataset_path: str = None, active_algorithm: str = "Logistic Regression"):
    """
    Executes full ML training workflow:
    1. Loads and validates dataset
    2. Computes class distribution
    3. Stratified split into training (80%) and test (20%)
    4. Trains Baseline (Logistic Regression) and Comparison (Linear SVM)
    5. Computes real evaluation metrics and confusion matrices
    6. Serializes artifacts
    7. Records model version and evaluations in database
    """
    if not dataset_path:
        dataset_path = str(Path(settings.DATASET_DIR) / "threat_intelligence_dataset.csv")

    p = Path(dataset_path)
    if not p.exists():
        raise FileNotFoundError(f"Dataset not found at {dataset_path}")

    # 1. Load and validate
    texts = []
    labels = []
    with open(p, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            t = (row.get("text") or "").strip()
            l = (row.get("label") or "").strip()
            if t and l:
                texts.append(t)
                labels.append(l)

    if len(texts) < 10:
        raise ValueError(f"Dataset too small ({len(texts)} samples). Minimum 10 samples required.")

    # Class distribution
    unique_labels, counts = np.unique(labels, return_counts=True)
    class_distribution = {str(k): int(v) for k, v in zip(unique_labels, counts)}

    # 2. Stratified Train/Test Split
    splitter = StratifiedShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    train_idx, test_idx = next(splitter.split(texts, labels))

    X_train = [texts[i] for i in train_idx]
    y_train = [labels[i] for i in train_idx]
    X_test = [texts[i] for i in test_idx]
    y_test = [labels[i] for i in test_idx]

    # 3. Vectorization
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=5000,
        sublinear_tf=True
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # 4. Train Model A: Logistic Regression (Baseline)
    lr_model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        random_state=42
    )
    lr_model.fit(X_train_vec, y_train)
    y_pred_lr = lr_model.predict(X_test_vec)

    # 5. Train Model B: Linear SVM (Comparison)
    svm_model = LinearSVC(
        class_weight="balanced",
        random_state=42,
        dual="auto"
    )
    svm_model.fit(X_train_vec, y_train)
    y_pred_svm = svm_model.predict(X_test_vec)

    # 6. Evaluate Models
    classes = [str(c) for c in sorted(list(unique_labels))]
    
    def evaluate_model(y_true, y_pred):
        acc = float(accuracy_score(y_true, y_pred))
        p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
        p_class, r_class, f1_class, support = precision_recall_fscore_support(y_true, y_pred, average=None, labels=classes, zero_division=0)
        
        per_class = {}
        for idx, c in enumerate(classes):
            per_class[c] = {
                "precision": round(float(p_class[idx]), 3),
                "recall": round(float(r_class[idx]), 3),
                "f1_score": round(float(f1_class[idx]), 3),
                "support": int(support[idx])
            }
            
        cm = confusion_matrix(y_true, y_pred, labels=classes)
        return {
            "accuracy": round(acc, 4),
            "precision": round(float(p_macro), 4),
            "recall": round(float(r_macro), 4),
            "f1_score": round(float(f1_macro), 4),
            "per_class": per_class,
            "confusion_matrix": cm.tolist(),
            "labels": classes
        }

    eval_lr = evaluate_model(y_test, y_pred_lr)
    eval_svm = evaluate_model(y_test, y_pred_svm)

    # Select chosen model for active deployment
    selected_model = lr_model if active_algorithm == "Logistic Regression" else svm_model
    selected_eval = eval_lr if active_algorithm == "Logistic Regression" else eval_svm

    # 7. Serialize Artifacts
    artifacts_dir = Path(settings.MODEL_DIR)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    version_str = f"v1.{int(datetime.now().timestamp()) % 10000}"
    metadata = {
        "version": version_str,
        "model_name": active_algorithm,
        "dataset_reference": str(Path(dataset_path).name),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "total_samples": len(texts),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "classes": classes,
        "comparison": {
            "Logistic Regression": {
                "accuracy": eval_lr["accuracy"],
                "f1_score": eval_lr["f1_score"]
            },
            "Linear SVM": {
                "accuracy": eval_svm["accuracy"],
                "f1_score": eval_svm["f1_score"]
            }
        }
    }

    joblib.dump(selected_model, artifacts_dir / "threat_classifier.joblib")
    joblib.dump(vectorizer, artifacts_dir / "tfidf_vectorizer.joblib")
    joblib.dump(metadata, artifacts_dir / "metadata.joblib")
    joblib.dump({"logistic_regression": eval_lr, "linear_svm": eval_svm}, artifacts_dir / "evaluation_results.joblib")

    # 8. Store in Database
    db = SessionLocal()
    try:
        # Mark previous models inactive
        db.query(ModelVersion).update({"is_active": False})
        
        m_version = ModelVersion(
            version=version_str,
            model_name=active_algorithm,
            dataset_reference=str(Path(dataset_path).name),
            configuration=json.dumps(metadata),
            is_active=True
        )
        db.add(m_version)
        db.flush()

        m_eval = ModelEvaluation(
            model_version_id=m_version.id,
            dataset_reference=str(Path(dataset_path).name),
            accuracy=selected_eval["accuracy"],
            precision=selected_eval["precision"],
            recall=selected_eval["recall"],
            f1_score=selected_eval["f1_score"],
            evaluation_details=json.dumps({
                "selected_model": active_algorithm,
                "metrics": selected_eval,
                "comparison": {
                    "logistic_regression": eval_lr,
                    "linear_svm": eval_svm
                },
                "class_distribution": class_distribution,
                "train_samples": len(X_train),
                "test_samples": len(X_test)
            })
        )
        db.add(m_eval)

        audit = AuditEvent(
            entity_type="MODEL",
            entity_id=m_version.id,
            action="TRAIN_AND_DEPLOY",
            details=f"Trained {active_algorithm} {version_str} with Accuracy: {selected_eval['accuracy']}, Macro-F1: {selected_eval['f1_score']}"
        )
        db.add(audit)
        db.commit()
    finally:
        db.close()

    return {
        "success": True,
        "version": version_str,
        "active_algorithm": active_algorithm,
        "metadata": metadata,
        "eval_baseline_lr": eval_lr,
        "eval_comparison_svm": eval_svm
    }

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    res = train_and_evaluate()
    print("Training Complete:", res["metadata"])
