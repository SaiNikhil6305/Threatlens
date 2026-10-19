import json
import joblib
import numpy as np
from typing import Dict, Any, List
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score
)
from ml.config import (
    MODEL_SAVE_PATH,
    VECTORIZER_SAVE_PATH,
    EVALUATION_RESULTS_PATH,
    MODEL_METADATA_PATH
)
from ml.dataset_loader import get_train_val_test_splits

def evaluate_classifier(model, X_test_vec, y_test, class_names: List[str] = None) -> Dict[str, Any]:
    """
    Computes complete classification metrics on held-out test data:
    Accuracy, Precision, Recall, F1, Confusion Matrix, and ROC-AUC.
    """
    y_pred = model.predict(X_test_vec)

    acc = float(accuracy_score(y_test, y_pred))
    prec_macro = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    prec_weighted = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    rec_macro = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
    rec_weighted = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1_macro = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    f1_weighted = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    labels = sorted(list(set(y_test)))
    cm = confusion_matrix(y_test, y_pred, labels=labels).tolist()

    # ROC-AUC calculation
    roc_auc = None
    try:
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(X_test_vec)
            if len(labels) == 2:
                roc_auc = float(roc_auc_score(y_test, probs[:, 1]))
            else:
                roc_auc = float(roc_auc_score(y_test, probs, multi_class="ovr"))
        elif hasattr(model, "decision_function"):
            decision = model.decision_function(X_test_vec)
            if len(labels) == 2:
                roc_auc = float(roc_auc_score(y_test, decision))
    except Exception:
        roc_auc = None

    # Per-class metrics
    per_class = {}
    for cls in labels:
        y_true_binary = (y_test == cls).astype(int)
        y_pred_binary = (np.array(y_pred) == cls).astype(int)
        per_class[str(cls)] = {
            "precision": round(float(precision_score(y_true_binary, y_pred_binary, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true_binary, y_pred_binary, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_true_binary, y_pred_binary, zero_division=0)), 4)
        }

    return {
        "accuracy": round(acc, 4),
        "precision_macro": round(prec_macro, 4),
        "precision_weighted": round(prec_weighted, 4),
        "recall_macro": round(rec_macro, 4),
        "recall_weighted": round(rec_weighted, 4),
        "f1_macro": round(f1_macro, 4),
        "f1_weighted": round(f1_weighted, 4),
        "confusion_matrix": cm,
        "labels": [str(l) for l in labels],
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "per_class": per_class
    }

def print_evaluation_summary():
    """Prints saved evaluation results or evaluates on current test set."""
    if EVALUATION_RESULTS_PATH.exists():
        with open(EVALUATION_RESULTS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        print("=" * 60)
        print(f" THREATLENS MODEL EVALUATION REPORT")
        print("=" * 60)
        best = data.get("best_model", "Unknown")
        meta = data.get("metadata", {})
        print(f"Active Model: {best} ({meta.get('version')})")
        print(f"Dataset:      {meta.get('dataset_name')} (Total: {meta.get('total_samples')} samples)")
        print(f"Test Set:     {meta.get('test_samples')} samples")
        print("\nCandidate Comparison:")
        print(f"{'Model Name':<25} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1-Score':<10} {'ROC-AUC':<10}")
        print("-" * 75)
        for name, comp in meta.get("candidate_comparison", {}).items():
            auc_str = f"{comp.get('roc_auc'):.4f}" if comp.get("roc_auc") else "N/A"
            print(f"{name:<25} {comp['accuracy']:<10.4f} {comp['precision']:<10.4f} {comp['recall']:<10.4f} {comp['f1_score']:<10.4f} {auc_str:<10}")

        print("\nConfusion Matrix (Labels: " + ", ".join(meta.get("classes", [])) + "):")
        best_results = data.get("detailed_results", {}).get(best, {})
        for row in best_results.get("confusion_matrix", []):
            print("  ", row)
    else:
        print("[!] No evaluation results found. Running evaluation...")
        model = joblib.load(MODEL_SAVE_PATH)
        vec = joblib.load(VECTORIZER_SAVE_PATH)
        _, _, X_test, _, _, y_test = get_train_val_test_splits()
        X_test_vec = vec.transform(X_test)
        metrics = evaluate_classifier(model, X_test_vec, y_test)
        print(json.dumps(metrics, indent=2))

if __name__ == "__main__":
    print_evaluation_summary()
