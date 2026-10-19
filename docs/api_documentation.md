# ThreatLens REST API Documentation

**Base URL**: `http://localhost:8000/api`  
**OpenAPI Interactive UI**: `http://localhost:8000/api/docs`  
**ReDoc Specifications**: `http://localhost:8000/api/redoc`

---

## 1. Threat Analysis Endpoints

### `POST /api/analyze/text`
Analyzes raw unstructured text (threat report, incident description, or advisory).
- **Request Body**:
  ```json
  {
    "text": "Spearphishing email sent to accounting containing malicious link hxxps://phish.example[.]com/login.",
    "title": "Finance Phishing Campaign",
    "source": "SOC Mail Gateway",
    "notes": "Escalated for perimeter review"
  }
  ```
- **Response**: `AnalysisResponse` object containing predicted category, confidence, severity rationale, extracted indicators, entities, ATT&CK mappings, and defensive recommendations.

### `POST /api/analyze/document`
Extracts and analyzes text from an uploaded document.
- **Content-Type**: `multipart/form-data`
- **Fields**:
  - `file` (binary, required): TXT, CSV, JSON, or PDF file (max 10 MB).
  - `title` (string, optional): Investigation title.
  - `source` (string, optional): Intelligence source.
  - `notes` (string, optional): Analyst notes.

### `POST /api/analyze/indicator`
Performs targeted correlation on an individual technical indicator.
- **Request Body**:
  ```json
  {
    "indicator": "198.51.100.77",
    "notes": "Identified in perimeter firewall deny log"
  }
  ```

---

## 2. Analysis History Endpoints

### `GET /api/analyses`
Retrieves paginated investigation summaries with multi-attribute filtering.
- **Query Parameters**:
  - `q` (string): Search string in title or text.
  - `category` (string): Threat category filter.
  - `severity` (string): Severity level filter (`Critical`, `High`, `Medium`, `Low`, `Informational`).
  - `status` (string): Investigation status filter.
  - `skip` (int): Offset (default: 0).
  - `limit` (int): Number of records (default: 50).

### `GET /api/analyses/{analysis_id}`
Retrieves full investigation findings, extracted indicators, and evidence snippets.

### `DELETE /api/analyses/{analysis_id}`
Permanently deletes an analysis record and cascades to linked extraction records.

---

## 3. Dashboard Endpoints

### `GET /api/dashboard/summary`
Calculates real database-backed operational metrics and chart distributions.
- **Query Parameters**: `category`, `severity`, `status`, `days` (default: 30).
- **Response**:
  ```json
  {
    "total_reports": 6,
    "total_indicators": 14,
    "high_critical_count": 4,
    "top_threat_category": "Phishing",
    "pending_review_count": 10,
    "category_distribution": { "Phishing": 2, "Ransomware": 2, ... },
    "severity_distribution": { "Critical": 1, "High": 3, "Medium": 1, ... },
    "indicator_distribution": { "ipv4": 5, "domain": 3, "url": 3, ... },
    "activity_timeline": [ { "date": "2026-10-13", "count": 6 } ],
    "recent_investigations": [ ... ]
  }
  ```

---

## 4. Indicators Management Endpoints

### `GET /api/indicators`
Lists correlated indicators with type, reputation, report count, and verification status.
- **Query Parameters**: `q`, `type`, `status`, `skip`, `limit`.

### `GET /api/indicators/{indicator_id}`
Retrieves detailed evidence snippets and all linked historical investigations.

### `PATCH /api/indicators/{indicator_id}`
Updates verification status (`Unverified`, `Analyst Confirmed`, `False Positive`) or adds an analyst investigation note.
- **Request Body**:
  ```json
  {
    "verification_status": "Analyst Confirmed",
    "analyst_note": "Confirmed malicious beaconing in internal proxy logs."
  }
  ```

### `POST /api/indicators/{indicator_id}/enrich`
Queries configured external threat intelligence providers (VirusTotal v3 / AlienVault OTX).

### `GET /api/indicators/export/csv`
Exports all filtered indicators of compromise to CSV format.

---

## 5. Reports & Intelligence Feed Endpoints

### `GET /api/reports/{analysis_id}`
Generates the comprehensive 10-section formal threat intelligence report.

### `GET /api/reports/{analysis_id}/export?format={json|markdown|csv}`
Exports the intelligence assessment in formatted Markdown, JSON, or CSV.

### `GET /api/feed`
Retrieves searchable intelligence records from local analyses, imported feeds, and external advisories.

### `POST /api/feed/sync-cisa`
Queries the public CISA Known Exploited Vulnerabilities catalog and synchronizes active advisories.

---

## 6. Machine Learning Endpoints

### `GET /api/model/status`
Returns active model name, serialization version, and inference engine mode.

### `GET /api/model/evaluation`
Returns real test split evaluation metrics (Accuracy, Macro Precision, Macro Recall, Macro F1), per-class table, confusion matrix, and baseline vs. comparison records.

### `POST /api/model/train`
Triggers supervised training on the labeled threat dataset and hot-reloads the active classifier.
- **Request Body**:
  ```json
  {
    "algorithm": "Logistic Regression"  // or "Linear SVM"
  }
  ```

---

## 7. System & Settings Endpoints

### `GET /api/health`
Returns system status, database connection check, and active model state.

### `GET /api/settings`
Returns environment limits and integration enablement statuses without leaking secrets.

### `POST /api/demo/import`
Imports standardized synthetic demonstration threat scenarios.

### `POST /api/demo/clear`
Safely removes demonstration records without touching user-submitted data.
