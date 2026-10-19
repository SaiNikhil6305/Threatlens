import io
import pytest
import httpx

BASE_URL = "http://127.0.0.1:8000"

def test_api_health():
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "Healthy"
        assert data["application_status"] == "Operational"
        assert data["model_loading_status"] == "Loaded"
        assert "backend_version" in data

def test_api_samples_list():
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        resp = client.get("/api/samples")
        assert resp.status_code == 200
        samples = resp.json()
        assert len(samples) == 8

def test_api_scan_document():
    content = b"URGENT: Submit your password and MFA code immediately to avoid account lockout."
    files = {"file": ("urgent_notice.txt", io.BytesIO(content), "text/plain")}
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        resp = client.post("/api/scan", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert data["overall_severity"] in ["High", "Critical"]
        assert data["finding_count"] > 0
        assert "report_url" in data

def test_api_scans_history():
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0

def test_api_analytics():
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        resp = client.get("/api/analytics")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_documents_scanned" in data
        assert "severity_distribution" in data

def test_api_model_metrics():
    with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
        resp = client.get("/api/model-metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert "detailed_results" in data
