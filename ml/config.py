from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATASETS_DIR = BASE_DIR / "datasets"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"
SAMPLE_DOCS_DIR = BASE_DIR / "sample_documents"

MODELS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
SAMPLE_DOCS_DIR.mkdir(parents=True, exist_ok=True)

# Dataset paths
ENRON_DATASET_PATH = DATASETS_DIR / "enron_spam_cleaned.csv"
CTI_DATASET_PATH = DATASETS_DIR / "threat_intelligence_dataset.csv"
CISA_KEV_PATH = DATASETS_DIR / "cisa_kev.json"
METADATA_PATH = DATASETS_DIR / "metadata.json"

# Output model artifacts
MODEL_SAVE_PATH = MODELS_DIR / "threat_classifier.joblib"
VECTORIZER_SAVE_PATH = MODELS_DIR / "tfidf_vectorizer.joblib"
MODEL_METADATA_PATH = MODELS_DIR / "model_metadata.json"
EVALUATION_RESULTS_PATH = MODELS_DIR / "evaluation_results.json"

# Training hyperparameters
RANDOM_STATE = 42
TEST_SIZE = 0.20
VAL_SIZE = 0.10
TFIDF_MAX_FEATURES = 15000
TFIDF_NGRAM_RANGE = (1, 2)
