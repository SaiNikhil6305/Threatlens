import time
import json
import joblib
from datetime import datetime, timezone
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV

from ml.config import (
    MODEL_SAVE_PATH,
    VECTORIZER_SAVE_PATH,
    MODEL_METADATA_PATH,
    EVALUATION_RESULTS_PATH,
    MODELS_DIR
)
from ml.dataset_loader import get_train_val_test_splits
from ml.preprocess import build_vectorizer
from ml.evaluate import evaluate_classifier

def run_training_pipeline():
    print("=" * 60)
    print(" ThreatLens ML Training & Evaluation Pipeline")
    print("=" * 60)

    # 1. Load splits
    print("[1/5] Loading and splitting dataset...")
    X_train, X_val, X_test, y_train, y_val, y_test = get_train_val_test_splits()
    print(f"      Train samples:      {len(X_train)}")
    print(f"      Validation samples: {len(X_val)}")
    print(f"      Test samples:       {len(X_test)}")
    print(f"      Total samples:      {len(X_train) + len(X_val) + len(X_test)}")

    # 2. Vectorization
    print("[2/5] Fitting TF-IDF Vectorizer...")
    t0 = time.time()
    vectorizer = build_vectorizer()
    X_train_vec = vectorizer.fit_transform(X_train)
    X_val_vec = vectorizer.transform(X_val)
    X_test_vec = vectorizer.transform(X_test)
    vec_time = time.time() - t0
    print(f"      Vocabulary size: {len(vectorizer.vocabulary_)} features (took {vec_time:.2f}s)")

    # 3. Candidate models
    candidates = {
        "Logistic Regression": LogisticRegression(max_iter=1000, C=1.0, random_state=42),
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.1),
        "Linear SVM": CalibratedClassifierCV(LinearSVC(dual=False, random_state=42, max_iter=2000), cv=3),
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=25, random_state=42, n_jobs=-1)
    }

    results = {}
    val_f1_scores = {}

    print("[3/5] Training and validating candidate models...")
    for name, clf in candidates.items():
        print(f"      Training {name}...")
        start_train = time.time()
        clf.fit(X_train_vec, y_train)
        duration = round(time.time() - start_train, 3)

        # Evaluate on validation set for selection
        val_eval = evaluate_classifier(clf, X_val_vec, y_val)
        val_f1_scores[name] = val_eval["f1_macro"]

        # Evaluate on test set for reporting
        test_eval = evaluate_classifier(clf, X_test_vec, y_test)
        test_eval["training_duration_seconds"] = duration
        results[name] = test_eval

        print(f"      -> {name}: Acc={test_eval['accuracy']:.4f}, Prec={test_eval['precision_macro']:.4f}, "
              f"Rec={test_eval['recall_macro']:.4f}, F1={test_eval['f1_macro']:.4f} (Duration: {duration}s)")

    # 4. Select best model based on validation F1 score
    best_model_name = max(val_f1_scores, key=val_f1_scores.get)
    best_model = candidates[best_model_name]
    print(f"\n[4/5] Selected Best Model: '{best_model_name}' (Validation Macro-F1: {val_f1_scores[best_model_name]:.4f})")

    # 5. Persist artifacts
    print("[5/5] Saving model artifacts to disk...")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_model, MODEL_SAVE_PATH)
    joblib.dump(vectorizer, VECTORIZER_SAVE_PATH)

    metadata = {
        "model_name": best_model_name,
        "version": f"v2.{int(time.time())}",
        "dataset_name": "Enron Spam & Phishing Cleaned Corpus",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "total_samples": int(len(X_train) + len(X_val) + len(X_test)),
        "train_samples": int(len(X_train)),
        "val_samples": int(len(X_val)),
        "test_samples": int(len(X_test)),
        "classes": sorted(list(set(y_test))),
        "vocabulary_size": len(vectorizer.vocabulary_),
        "selected_metrics": results[best_model_name],
        "candidate_comparison": {
            name: {
                "accuracy": res["accuracy"],
                "precision": res["precision_macro"],
                "recall": res["recall_macro"],
                "f1_score": res["f1_macro"],
                "roc_auc": res["roc_auc"],
                "training_duration": res["training_duration_seconds"]
            }
            for name, res in results.items()
        }
    }

    with open(MODEL_METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    with open(EVALUATION_RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump({
            "best_model": best_model_name,
            "metadata": metadata,
            "detailed_results": results
        }, f, indent=2)

    # Also mirror artifacts to backend/app/ml/artifacts for seamless loading
    backend_artifacts = MODELS_DIR.parent / "backend" / "app" / "ml" / "artifacts"
    if backend_artifacts.exists():
        joblib.dump(best_model, backend_artifacts / "threat_classifier.joblib")
        joblib.dump(vectorizer, backend_artifacts / "tfidf_vectorizer.joblib")
        joblib.dump(metadata, backend_artifacts / "metadata.joblib")
        joblib.dump(results, backend_artifacts / "evaluation_results.joblib")
        print(f"      Mirrored models to backend artifacts directory: {backend_artifacts}")

    print("\n[+] Model Training and Evaluation Pipeline Succeeded!")
    print(f"    Best Model: {best_model_name}")
    print(f"    Test Accuracy:  {results[best_model_name]['accuracy']}")
    print(f"    Test Macro F1:  {results[best_model_name]['f1_macro']}")
    print(f"    Test Macro Rec: {results[best_model_name]['recall_macro']}")
    print(f"    Test Precision: {results[best_model_name]['precision_macro']}")
    return metadata

if __name__ == "__main__":
    run_training_pipeline()
