import io
import pytest
from app.services.document_parser import DocumentParser

def test_extract_valid_txt():
    content = b"This is a legitimate corporate advisory regarding upcoming maintenance."
    success, text, meta = DocumentParser.parse_file("advisory.txt", content)
    assert success is True
    assert "legitimate corporate advisory" in text
    assert meta["file_type"] == "TXT"
    assert meta["page_count"] >= 1

def test_empty_document():
    success, text, meta = DocumentParser.parse_file("empty.txt", b"")
    assert success is False
    assert "error" in meta

def test_unsupported_file_extension():
    content = b"Binary executable code"
    success, text, meta = DocumentParser.parse_file("malicious.exe", content)
    assert success is False
    assert "Unsupported file type" in meta["error"]

def test_signature_mismatch_pdf():
    # File named .pdf but containing plain text without %PDF header
    content = b"Not a real pdf header at all"
    success, text, meta = DocumentParser.parse_file("fake.pdf", content)
    assert success is False
    assert "File signature mismatch" in meta["error"]

def test_valid_pdf_multi_page():
    from pathlib import Path
    sample_path = Path(__file__).resolve().parent.parent / "sample_documents" / "safe_company_policy.pdf"
    if sample_path.exists():
        with open(sample_path, "rb") as f:
            content = f.read()
        success, text, meta = DocumentParser.parse_file("safe_company_policy.pdf", content)
        assert success is True
        assert meta["file_type"] == "PDF"
        assert meta["page_count"] == 3
        assert len(meta["pages"]) == 3
        assert "Global Enterprise Information Security" in text
