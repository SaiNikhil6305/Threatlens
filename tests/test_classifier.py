import pytest
from app.services.threat_classifier import threat_classifier
from app.services.threat_engine import ThreatEngine

def test_classifier_loaded():
    assert threat_classifier.model is not None
    assert threat_classifier.vectorizer is not None

def test_classify_benign_text():
    text = (
        "Good morning team, please find attached the quarterly business review presentation. "
        "We look forward to celebrating our milestone achievements in the cafeteria this Friday."
    )
    result = threat_classifier.predict(text)
    assert result["predicted_category"] in ["Safe", "Benign or Informational"]
    assert result["confidence"] > 0.5

def test_classify_phishing_text():
    text = (
        "URGENT FINAL WARNING: Your Microsoft 365 mailbox has been suspended due to policy violations. "
        "Click here immediately to confirm your password and submit multi-factor authentication code: "
        "hxxp://login-verify-account[.]example[.]com/login.php"
    )
    result = threat_classifier.predict(text)
    assert result["predicted_category"] in ["Suspicious", "Phishing", "Credential Theft"]

def test_context_aware_educational_filtering():
    edu_text = (
        "Security Awareness Training Module 2: Recognizing Modern Phishing. "
        "For training purposes only. This educational example demonstrates how attackers craft deceptive lures: "
        "Subject: Urgent account verification required. "
        "Notice how the mismatched domain differs from legitimate corporate policy. "
        "Approved by corporate security policy committee."
    )
    analysis = ThreatEngine.analyze_document(
        filename="security_training.pdf",
        full_text=edu_text,
        pages=[{"page_number": 1, "text": edu_text}]
    )
    # Must NOT classify educational training as Critical attack
    assert analysis["overall_severity"] == "No significant indicators detected"
    assert analysis["is_educational"] is True
