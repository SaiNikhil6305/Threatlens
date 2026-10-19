# ThreatLens System Architecture

**Product**: ThreatLens  
**Tagline**: *See Beyond the Threat*  
**Architecture Style**: Decoupled Client-Server with Modular NLP & Heuristic Inference Engines

---

## 1. High-Level Architecture

ThreatLens is engineered as a professional cyber threat intelligence workbench designed for SOC analysts, incident response teams, and security researchers.

```
+-------------------------------------------------------------------------+
|                                FRONTEND                                 |
|      React 19 + TypeScript + Vite + Tailwind CSS + Recharts + Lucide     |
+------------------------------------+------------------------------------+
                                     |
                                     | HTTP REST (JSON / Multipart / Streams)
                                     v
+-------------------------------------------------------------------------+
|                                BACKEND                                  |
|            FastAPI + Uvicorn + Pydantic v2 + SQLAlchemy 2.0             |
|                                                                         |
|  +------------------+  +-------------------+  +----------------------+  |
|  | TextPreprocessor |  |   IOCExtractor    |  |   EntityExtractor    |  |
|  | - Token safety   |  | - Defang/Refang   |  | - spaCy NER          |  |
|  | - Normalization  |  | - Strict IP regex |  | - Cyber Ontology     |  |
|  +------------------+  +-------------------+  +----------------------+  |
|                                                                         |
|  +------------------+  +-------------------+  +----------------------+  |
|  | ThreatClassifier |  |  SeverityEngine   |  |     AttackMapper     |  |
|  | - TF-IDF Vector  |  | - Transparent Wts |  | - MITRE Reference    |  |
|  | - Logistic Reg.  |  | - Missing Context |  | - Evidence Snippets  |  |
|  | - Linear SVM     |  | - Triage Steps    |  | - Tactic Correlation |  |
|  +------------------+  +-------------------+  +----------------------+  |
|                                                                         |
|  +------------------+  +-------------------+  +----------------------+  |
|  | Recommendation   |  |  ReportGenerator  |  |  EnrichmentService   |  |
|  | - Containment    |  | - 10-Section Spec |  | - VirusTotal v3      |  |
|  | - Mitigation     |  | - JSON, MD, CSV   |  | - AlienVault OTX     |  |
|  +------------------+  +-------------------+  +----------------------+  |
+------------------------------------+------------------------------------+
                                     |
                                     | ORM Mapping
                                     v
+-------------------------------------------------------------------------+
|                          PERSISTENCE LAYER                              |
|                   SQLite (Dev) / PostgreSQL (Prod)                      |
|                                                                         |
|  - analyses                 - indicators              - analysis_indicators
|  - extracted_entities       - attack_techniques       - analysis_techniques
|  - analyst_notes            - model_versions          - model_evaluations
|  - audit_events             - intelligence_feed_items                       |
+-------------------------------------------------------------------------+
```

---

## 2. Core Subsystems

### 2.1 Natural Language Processing Pipeline
1. **TextPreprocessor**: Cleans raw text while strictly preserving technical tokens (IPs, domains, hashes, CVEs). Standardizes encoding and line breaks without token loss.
2. **IOCExtractor**: Employs boundary-checked regular expressions to extract IPv4, domains, URLs, email addresses, MD5, SHA-1, SHA-256, and CVE identifiers. Handles defanged notations (`hxxp://`, `[.]`, `[at]`) and normalizes indicators for deduplication. Provides safe defanged representations to prevent accidental navigation.
3. **EntityExtractor**: Merges linguistic entity recognition (`spaCy en_core_web_sm`) with domain-specific cybersecurity vocabularies covering APT groups, malware families, named vulnerabilities, and security tools.
4. **KeywordExtractor**: Calculates term frequencies against a curated cybersecurity ontology across 11 threat categories.

### 2.2 Machine Learning Threat Classification
- **Vectorization**: Sublinear TF-IDF vectorizer extracting unigrams and bigrams (max 5,000 features).
- **Classifiers**:
  - Baseline: L2-regularized Logistic Regression with balanced class weights.
  - Comparison: Linear Support Vector Classifier (LinearSVC).
- **Uncertainty Engine**: Calculates confidence scores and decision margins. When probability thresholds fall below 0.50 or margin is narrow, an uncertainty flag (`is_uncertain`) is raised with a descriptive explanation.
- **Rule-Based Fallback**: If no trained model artifact exists on disk, a transparent rule-based fallback executes, explicitly labeling `prediction_method` as `"Rule-based Fallback (No Model Loaded)"`.

### 2.3 Explainable Severity Assessment Engine
Calculates triage severity tiers (`Critical`, `High`, `Medium`, `Low`, `Informational`) based on weighted heuristic rules:
- Active widespread encryption / shadow copy deletion (+5.0)
- Zero-day / active RCE vulnerability exploitation (+4.0)
- Credential dumping / LSASS memory access (+3.5)
- Data exfiltration evidence (+3.0)
- Command & Control beaconing (+2.5)
- Phishing lures (+1.5)
- DoS flooding (+2.0)
- External reconnaissance probes (+1.0)
- Routine hygiene / benign notices (-2.0)

Generates:
1. Assessed severity level & score (0.0 to 10.0)
2. Triggered rules with weights
3. Missing context / telemetry gaps
4. Recommended investigative next steps

### 2.4 Document Parsing Engine
Safely ingests and extracts digital text from:
- **TXT**: UTF-8 stream processing.
- **CSV**: Delimited field serialization.
- **JSON**: Recursive textual key-value extraction.
- **PDF**: Digital text stream extraction via `pypdf`. Rejects image-only or scanned PDFs without OCR.
- **Safety**: Uploaded binaries, scripts, and macros are never executed.

---

## 3. Database Schema & Migration Path

### 3.1 Relational Architecture
- `analyses`: Core investigation record storing title, text, classification, severity score, rationale JSON, and timestamps.
- `indicators`: Normalized indicator catalog recording first/last observed timestamps, reputation findings, and verification statuses.
- `analysis_indicators`: Many-to-many join table storing character offsets (`source_start`, `source_end`), extraction confidence, and contextual evidence snippets.
- `extracted_entities`: Extracted threat actors, malware families, and technologies.
- `attack_techniques`: Seeded reference catalog of MITRE ATT&CK Enterprise techniques.
- `analysis_techniques`: Linkages connecting evidence snippets to specific ATT&CK technique IDs.
- `analyst_notes`: Audit-trailed investigation notes added by analysts.
- `model_versions` & `model_evaluations`: Persists real academic training metrics, confusion matrices, and model comparison records.
- `audit_events`: Tamper-evident activity log of creates, updates, deletes, and enrichments.

### 3.2 PostgreSQL Migration Strategy
To transition from SQLite to enterprise PostgreSQL:
1. Update `DATABASE_URL` in `backend/.env` to `postgresql+psycopg2://user:password@host:5432/threatlens`.
2. Remove SQLite-specific `connect_args={"check_same_thread": False}` in `backend/app/database/session.py`.
3. SQLAlchemy models use standard ANSI SQL datatypes (`String(36)`, `Text`, `Float`, `DateTime`) fully compatible with PostgreSQL.
4. Database migrations can be managed seamlessly with Alembic (`alembic init alembic && alembic revision --autogenerate`).
