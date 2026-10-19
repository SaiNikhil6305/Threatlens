# Machine Learning Threat Classification Methodology

## 1. Overview
ThreatLens implements a supervised machine learning text classification pipeline to classify unstructured threat reports into 11 standardized threat categories:
1. `Phishing`
2. `Malware`
3. `Ransomware`
4. `Credential Theft`
5. `Denial of Service`
6. `Web Application Attack`
7. `Vulnerability Exploitation`
8. `Data Exfiltration`
9. `Reconnaissance`
10. `Benign or Informational`
11. `Other or Unknown`

---

## 2. Methodology & Feature Engineering

### 2.1 Text Vectorization
Text reports are vectorized using `TfidfVectorizer` with the following parameters:
- `ngram_range=(1, 2)`: Captures both individual security terms (e.g. `ransomware`, `mimikatz`) and key phrases (e.g. `credential dumping`, `remote code execution`).
- `sublinear_tf=True`: Applies logarithmic term frequency scaling ($1 + \log(tf)$) to prevent high-frequency terms from overwhelming discriminative tokens.
- `max_features=5000`: Bounds vocabulary size to prevent overfitting on small samples.

### 2.2 Model Architecture Selection
1. **Baseline Model: Logistic Regression**
   - Regularization: L2 regularization ($C=1.0$).
   - Solvers: L-BFGS optimizer with balanced class weights (`class_weight='balanced'`).
   - Advantage: Direct calibrated class probability estimation for uncertainty analysis.

2. **Comparison Model: Linear Support Vector Classifier (LinearSVC)**
   - Objective: Maximizes decision margin between classes in high-dimensional TF-IDF space.
   - Dual formulation: `dual='auto'`.
   - Advantage: Highly effective in sparse text classification domains.

---

## 3. Train / Test Evaluation Protocol

- **Dataset**: `datasets/threat_intelligence_dataset.csv` (curated, balanced samples across all 11 classes).
- **Partitioning**: Stratified Shuffle Split (80% training / 20% holdout test partition) with a fixed random seed (`random_state=42`) to ensure reproducibility.
- **Leakage Prevention**: TF-IDF vocabulary is strictly fitted on `X_train` only; `X_test` is transformed using the fitted vectorizer.
- **Evaluation Metrics**:
  - Macro Precision, Macro Recall, and Macro-F1 (unweighted class averages to prevent majority bias).
  - Class-by-class precision, recall, and support.
  - Comprehensive 11x11 confusion matrix.

---

## 4. Execution & Reproduction Commands

To retrain and evaluate the models via CLI:
```bash
# Windows PowerShell from project root
$env:PYTHONPATH="c:\projects\Threatlens\backend"
.\.venv\Scripts\python.exe -m app.ml.train_classifier
```

To inspect evaluation metrics via CLI:
```bash
$env:PYTHONPATH="c:\projects\Threatlens\backend"
.\.venv\Scripts\python.exe -m app.ml.evaluate_model
```

---

## 5. Academic Discussion on Uncertainty

In cyber threat intelligence, predicting with false confidence is dangerous. ThreatLens incorporates explicit uncertainty checking:
1. **Decision Margin**: If the difference between the top-scoring class probability and the second class is below 0.15, the report is flagged with `is_uncertain=True`.
2. **Confidence Threshold**: If top probability is below 0.50, an uncertainty warning is surfaced to the analyst.
3. **No Model Loaded**: If model artifacts are missing, the system utilizes an explainable rule-based fallback and explicitly states that no model was loaded.
