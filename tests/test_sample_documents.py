import json
import pytest
from pathlib import Path
from app.services.document_parser import DocumentParser
from app.services.threat_engine import ThreatEngine

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_documents"
MANIFEST_PATH = SAMPLE_DIR / "test_manifest.json"

def test_all_sample_documents():
    assert MANIFEST_PATH.exists(), "test_manifest.json must exist."
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    docs = manifest.get("documents", [])
    assert len(docs) == 8, "Expected 8 sample test documents."

    results_summary = []
    false_positives = 0
    false_negatives = 0

    print("\n" + "=" * 70)
    print(" SAMPLE DOCUMENTS TEST RUN SUMMARY")
    print("=" * 70)

    for d in docs:
        filename = d["filename"]
        pdf_path = SAMPLE_DIR / filename
        assert pdf_path.exists(), f"Sample PDF {filename} does not exist."

        with open(pdf_path, "rb") as f:
            content = f.read()

        success, text, meta = DocumentParser.parse_file(filename, content)
        assert success is True, f"Failed to parse {filename}: {meta.get('error')}"
        assert meta["page_count"] == 3, f"Expected 3 pages for {filename}, got {meta['page_count']}"

        analysis = ThreatEngine.analyze_document(
            filename=filename,
            full_text=text,
            pages=meta.get("pages", [])
        )

        expected_sev = d.get("expected_severity")
        actual_sev = analysis["overall_severity"]

        # Track false positive / false negative
        is_safe_expected = (expected_sev == "No significant indicators detected")
        is_threat_actual = (actual_sev in ["High", "Critical"])

        if is_safe_expected and is_threat_actual:
            false_positives += 1
        elif not is_safe_expected and actual_sev == "No significant indicators detected":
            false_negatives += 1

        results_summary.append({
            "filename": filename,
            "category": d["category"],
            "expected_severity": expected_sev,
            "actual_severity": actual_sev,
            "finding_count": analysis["finding_count"],
            "predicted_category": analysis["predicted_category"]
        })

        print(f"[{'PASS' if actual_sev == expected_sev or (is_threat_actual and not is_safe_expected) else 'NOTE'}] "
              f"{filename:<32} | Expected: {expected_sev:<32} | Actual: {actual_sev}")

    print("-" * 70)
    print(f"Total documents tested:       {len(docs)}")
    print(f"Safe-document false positives: {false_positives}")
    print(f"Threat-document false negs:    {false_negatives}")
    print("=" * 70)

    # 4 safe documents should not be classified as High/Critical attacks
    assert false_positives == 0, f"Observed {false_positives} false positives in safe documents!"
    # 4 threat documents should not be missed as 'No significant indicators'
    assert false_negatives == 0, f"Observed {false_negatives} false negatives in threat documents!"
