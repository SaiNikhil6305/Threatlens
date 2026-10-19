import pytest
import io
import json
from fastapi.testclient import TestClient

from app.main import app
from app.services.ioc_extractor import IOCExtractor
from app.services.text_preprocessor import TextPreprocessor
from app.services.threat_classifier import ThreatClassifier
from app.services.severity_engine import SeverityEngine
from app.services.document_parser import DocumentParser
from app.database.session import SessionLocal
from app.database.init_db import init_db

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    init_db()

@pytest.fixture
def client():
    return TestClient(app)

# --- 1. IOC Extractor Tests ---

def test_ipv4_extraction_valid_and_invalid():
    text = "Traffic from 192.0.2.1 and defanged 198[.]51[.]100[.]44. Invalid IPs: 300.1.2.3 and 2024.05.12.1."
    iocs = IOCExtractor.extract_all(text)
    ips = [i["normalized_value"] for i in iocs if i["indicator_type"] == "ipv4"]
    
    assert "192.0.2.1" in ips
    assert "198.51.100.44" in ips
    assert "300.1.2.3" not in ips
    assert "2024.05.12.1" not in ips

def test_defanged_url_and_domain_extraction():
    text = "Visit hxxps://malicious-portal[.]example[.]com/login or bad-domain[.]org."
    iocs = IOCExtractor.extract_all(text)
    
    urls = [i for i in iocs if i["indicator_type"] == "url"]
    domains = [i for i in iocs if i["indicator_type"] == "domain"]
    
    assert any("https://malicious-portal.example.com" in u["normalized_value"] for u in urls)
    # Check safe defanged presentation
    assert any("[.]" in u["defanged_value"] for u in urls)
    assert any("bad-domain.org" in d["normalized_value"] for d in domains)

def test_email_extraction_standard_and_defanged():
    text = "Contact phish[at]example[.]net or admin@corporate.com for details."
    iocs = IOCExtractor.extract_all(text)
    emails = [i["normalized_value"] for i in iocs if i["indicator_type"] == "email"]
    
    assert "phish@example.net" in emails
    assert "admin@corporate.com" in emails

def test_hash_and_cve_extraction():
    text = """Sample MD5: 44d88612fea8a8f36de82e1278abb02f
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Exploiting vulnerability CVE-2021-44228."""
    iocs = IOCExtractor.extract_all(text)
    
    md5s = [i["normalized_value"] for i in iocs if i["indicator_type"] == "md5"]
    sha256s = [i["normalized_value"] for i in iocs if i["indicator_type"] == "sha256"]
    cves = [i["normalized_value"] for i in iocs if i["indicator_type"] == "cve"]
    
    assert "44d88612fea8a8f36de82e1278abb02f" in md5s
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in sha256s
    assert "CVE-2021-44228" in cves

# --- 2. Text Preprocessor & Edge Cases ---

def test_empty_and_whitespace_input():
    res = TextPreprocessor.preprocess("   \n\t  ")
    assert res["is_empty"] is True
    assert res["word_count"] == 0

def test_preprocessing_preserves_tokens():
    text = "Alert: IP 192.0.2.1 connected to CVE-2024-1234 on server.example.com"
    res = TextPreprocessor.preprocess(text)
    assert "192.0.2.1" in res["cleaned_text"]
    assert "CVE-2024-1234" in res["cleaned_text"]

# --- 3. Severity Engine Tests ---

def test_severity_critical_ransomware():
    text = "Widespread active encryption across servers with ransom note and shadow copies deleted."
    res = SeverityEngine.assess_severity(
        text=text,
        category="Ransomware",
        indicators=[{"indicator_type": "ipv4", "normalized_value": "192.0.2.1"}],
        entities=[]
    )
    assert res["severity"] in ("Critical", "High")
    assert any("RANSOMWARE" in r["rule"] for r in res["triggered_rules"])
    assert len(res["recommended_investigation_steps"]) > 0

def test_severity_informational_routine_notice():
    text = "This is a scheduled maintenance and routine patch notice with no compromise."
    res = SeverityEngine.assess_severity(
        text=text,
        category="Benign or Informational",
        indicators=[],
        entities=[]
    )
    assert res["severity"] in ("Low", "Informational")
    assert len(res["missing_information"]) > 0

# --- 4. Document Parser Tests ---

def test_document_parser_txt_and_json():
    txt_bytes = b"Suspicious beaconing detected from 192.0.2.1"
    ok, text, _ = DocumentParser.parse_file("alert.txt", txt_bytes)
    assert ok is True
    assert "192.0.2.1" in text

    json_bytes = json.dumps({"incident": "Phishing email", "ioc": "evil.example.com"}).encode()
    ok, text, _ = DocumentParser.parse_file("alert.json", json_bytes)
    assert ok is True
    assert "evil.example.com" in text

def test_document_parser_unsupported_extension():
    ok, _, meta = DocumentParser.parse_file("malicious.exe", b"MZ\x90\x00")
    assert ok is False
    assert "Unsupported file type" in meta["error"]

# --- 5. Full API End-to-End Workflow Tests ---

def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "Healthy"
    assert data["database"] == "Connected"

def test_api_analyze_text_workflow(client):
    payload = {
        "title": "Automated Test Incident",
        "text": "Spearphishing email sent to accounting containing malicious link hxxps://phish.example[.]org/login. User executed payload connecting to 198.51.100.99.",
        "source": "SOC Unit Test"
    }
    res = client.post("/api/analyze/text", json=payload)
    assert res.status_code == 200
    data = res.json()
    
    assert data["title"] == "Automated Test Incident"
    assert len(data["indicators"]) >= 2
    assert "severity" in data
    assert "predicted_category" in data
    analysis_id = data["id"]

    # Verify retrieval from Analysis History
    hist_res = client.get("/api/analyses")
    assert hist_res.status_code == 200
    assert any(a["id"] == analysis_id for a in hist_res.json())

    # Verify Report generation
    rpt_res = client.get(f"/api/reports/{analysis_id}")
    assert rpt_res.status_code == 200
    rpt_data = rpt_res.json()
    assert "executive_summary" in rpt_data
    assert len(rpt_data["limitations"]) > 0

    # Verify Markdown export
    export_res = client.get(f"/api/reports/{analysis_id}/export?format=markdown")
    assert export_res.status_code == 200
    assert "THREATLENS INTELLIGENCE REPORT" in export_res.text

    # Verify Dashboard updates
    dash_res = client.get("/api/dashboard/summary")
    assert dash_res.status_code == 200
    dash_data = dash_res.json()
    assert dash_data["total_reports"] >= 1

    # Cleanup analysis
    del_res = client.delete(f"/api/analyses/{analysis_id}")
    assert del_res.status_code == 200
