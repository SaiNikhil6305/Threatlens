# ThreatLens — See Beyond the Threat

**ThreatLens** is an NLP-powered Cyber Threat Intelligence (CTI) assistant and investigation workbench built for SOC analysts, incident response teams, and security researchers.

It transforms unstructured threat reports, incident narratives, and security advisories into structured, explainable, and actionable intelligence—extracting indicators of compromise, identifying MITRE ATT&CK techniques, classifying threats via machine learning, assessing triage severity, and generating formal intelligence reports.

---

## Key Features

1. **Intelligent Threat Triage**:
   - **Method A (Text Analysis)**: Submit unstructured emails, advisories, or CTI reports.
   - **Method B (Document Upload)**: Safely parses digital text from TXT, CSV, JSON, and PDF files.
   - **Method C (Direct Indicator Query)**: Fast lookups for IPv4, domains, URLs, hashes, or CVEs.
2. **Robust Indicator Extraction Engine**:
   - Extracts IPv4, domains, URLs, emails, MD5, SHA-1, SHA-256, and CVE identifiers.
   - Refangs common defanged notations (`hxxp://`, `[.]`, `[at]`) and safely defangs indicators for analyst display.
   - Retains context offsets and evidence snippets.
3. **Supervised Threat Classification**:
   - TF-IDF vectorization with unigram and bigram extraction.
   - Compares **Logistic Regression (Baseline)** against **Linear SVM (LinearSVC)**.
   - Surfaces explicit confidence scores and uncertainty flags.
4. **Explainable Severity Assessment**:
   - Transparent heuristic scoring with weighted rule breakdowns, missing context disclosures, and containment playbooks.
5. **MITRE ATT&CK Framework Mapping**:
   - Correlates evidence against official MITRE ATT&CK Enterprise techniques (Initial Access, Execution, Persistence, Impact, etc.).
6. **Academic Model Evaluation Dashboard**:
   - Live benchmarks: Test accuracy, Macro-Precision, Macro-Recall, Macro-F1, per-class metrics, and confusion matrix.
7. **Intelligence Feed & Reports**:
   - Searchable multi-source feed with one-click CISA KEV synchronization.
   - Formal 10-section intelligence report generation with JSON, Markdown, and CSV indicator exports.
8. **Demonstration Dataset Management**:
   - One-click import and cleanup of RFC 5737-compliant synthetic scenarios.

---

## Technology Stack

- **Frontend**: React 19, TypeScript, Vite, Tailwind CSS, Lucide React, Recharts, React Router.
- **Backend**: Python 3.14+, FastAPI, Uvicorn, Pydantic v2, SQLAlchemy 2.0.
- **NLP & ML**: spaCy (`en_core_web_sm`), scikit-learn (`TfidfVectorizer`, `LogisticRegression`, `LinearSVC`), PyPDF.
- **Database**: SQLite (default local) with zero-code migration path to PostgreSQL.

---

## Quickstart Guide (Windows)

### Prerequisites
- Python 3.10+ installed (`python --version`)
- Node.js 18+ and npm installed (`node --version`)

### 1. Clone & Setup Python Virtual Environment
```powershell
# Open Windows PowerShell in project root
cd c:\projects\Threatlens

# Create virtual environment
python -m venv .venv

# Install Python backend dependencies
.\.venv\Scripts\pip.exe install -r backend\requirements.txt

# Download spaCy English model
.\.venv\Scripts\python.exe -m spacy download en_core_web_sm
```

### 2. Initialize Database & Seed MITRE Dataset
```powershell
$env:PYTHONPATH="c:\projects\Threatlens\backend"
.\.venv\Scripts\python.exe -m app.database.init_db
```

### 3. Train Machine Learning Models
```powershell
$env:PYTHONPATH="c:\projects\Threatlens\backend"
.\.venv\Scripts\python.exe -m app.ml.train_classifier
```

### 4. Setup & Build Frontend
```powershell
cd c:\projects\Threatlens\frontend
npm install
npm run build
```

---

## Running ThreatLens

### Terminal 1: Backend Server (FastAPI)
```powershell
cd c:\projects\Threatlens
$env:PYTHONPATH="c:\projects\Threatlens\backend"
.\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000 --reload
```
*Backend runs on `http://127.0.0.1:8000` with interactive API docs at `http://127.0.0.1:8000/api/docs`.*

### Terminal 2: Frontend Web App (Vite)
```powershell
cd c:\projects\Threatlens\frontend
npm run dev
```
*Frontend runs on `http://localhost:5173` (or `http://localhost:5174`).*

---

## Running Automated Tests

Run the full pytest test suite covering IOC extraction, defanging, document parsing, severity assessment, and API contracts:
```powershell
cd c:\projects\Threatlens
$env:PYTHONPATH="c:\projects\Threatlens\backend"
.\.venv\Scripts\pytest.exe backend\app\tests\test_threatlens.py -v
```

---

## Project Structure

```
Threatlens/
├── backend/
│   ├── app/
│   │   ├── api/             # REST API routers (analyze, dashboard, feed, indicators, etc.)
│   │   ├── core/            # Configuration and settings
│   │   ├── database/        # SQLAlchemy engine, session, and init_db seeder
│   │   ├── models/          # Relational entities (analyses, indicators, etc.)
│   │   ├── schemas/         # Pydantic request and response schemas
│   │   ├── services/        # Preprocessor, IOC extractor, classifier, severity engine, etc.
│   │   ├── ml/              # Model training, evaluation, and serialized artifacts
│   │   ├── tests/           # Automated pytest test suite
│   │   └── main.py          # FastAPI application entrypoint
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/      # Reusable UI components (Sidebar, Header, Badges, Modals)
│   │   ├── pages/           # 9 primary workbench pages
│   │   ├── services/        # Frontend API client
│   │   ├── types/           # TypeScript definitions
│   │   ├── App.tsx          # Router and shell layout
│   │   └── main.tsx
│   ├── package.json
│   └── vite.config.ts
├── datasets/
│   ├── threat_intelligence_dataset.csv  # 11-class labeled training dataset
│   └── README.md
├── docs/
│   ├── architecture.md
│   ├── api_documentation.md
│   ├── model_training.md
│   └── security_notes.md
├── .env.example
├── .gitignore
└── README.md
```

---

## License & Attribution

ThreatLens is released under the MIT License. Demonstration threat scenarios utilize RFC 5737 documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 2606 reserved domains (`example.com`, `example.org`).
