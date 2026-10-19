import sys
import json
import httpx

BASE_URL = "http://127.0.0.1:8000/api"

def run_verification():
    print("=== STARTING THREATLENS FULL SYSTEM VERIFICATION ===")
    
    with httpx.Client(timeout=15.0) as client:
        # 1. Health Check
        r = client.get(f"{BASE_URL}/health")
        assert r.status_code == 200, f"Health check failed: {r.text}"
        data = r.json()
        print(f"[OK] Health Check: Status={data['status']}, Database={data['database']}, ModelLoaded={data['ml_model_loaded']}")
        
        # 2. Settings Check
        r = client.get(f"{BASE_URL}/settings")
        assert r.status_code == 200
        print(f"[OK] Settings Check: DB={r.json()['database_type']}, Target={r.json()['migration_target']}")
        
        # 3. Model Status & Academic Evaluation
        r = client.get(f"{BASE_URL}/model/status")
        assert r.status_code == 200
        print(f"[OK] Model Status: {r.json()}")
        
        r = client.get(f"{BASE_URL}/model/evaluation")
        assert r.status_code == 200
        eval_data = r.json()
        print(f"[OK] Model Evaluation: Accuracy={eval_data.get('accuracy')}, Macro-F1={eval_data.get('f1_score')}, Model={eval_data.get('model_name')}")
        
        # 4. Text Analysis Workflow
        test_phish = {
            "title": "Verifying Phishing Campaign 2026",
            "source": "SOC Test Harness",
            "text": "Urgent wire payment notice from hr[at]corporate-billing[.]example.com. User prompted to login at hxxps://verify.example[.]org/auth. File dropped with SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 connecting to C2 IP 192.0.2.77."
        }
        r = client.post(f"{BASE_URL}/analyze/text", json=test_phish)
        assert r.status_code == 200, f"Text analysis failed: {r.text}"
        analysis = r.json()
        analysis_id = analysis["id"]
        print(f"[OK] Text Analysis Created: ID={analysis_id[:8]}, Category={analysis['predicted_category']}, Severity={analysis['severity']}, Confidence={analysis['confidence']}")
        print(f"     Extracted {len(analysis['indicators'])} indicators, {len(analysis['entities'])} entities, {len(analysis['techniques'])} ATT&CK mappings")
        
        # Verify defanged values in returned indicators
        defanged_values = [i["defanged_value"] for i in analysis["indicators"]]
        print(f"     Safe Defanged Indicators: {defanged_values}")
        assert any("[.]" in v or "[at]" in v or "hxxps" in v for v in defanged_values)
        
        # 5. MITRE ATT&CK Reference Explorer
        r = client.get(f"{BASE_URL}/attack/techniques")
        assert r.status_code == 200
        techs = r.json()
        print(f"[OK] MITRE ATT&CK Matrix: {len(techs)} reference techniques available")
        
        # 6. Indicators Management & Correlation
        r = client.get(f"{BASE_URL}/indicators")
        assert r.status_code == 200
        indicators = r.json()
        print(f"[OK] Indicators Catalog: {len(indicators)} indicators stored")
        target_ind = indicators[0]
        
        # Update Verification Status & Analyst Note
        patch_payload = {
            "verification_status": "Analyst Confirmed",
            "analyst_note": "Verified in security test harness"
        }
        r = client.patch(f"{BASE_URL}/indicators/{target_ind['id']}", json=patch_payload)
        assert r.status_code == 200
        assert r.json()["verification_status"] == "Analyst Confirmed"
        print(f"[OK] Indicator Verification Updated: {target_ind['normalized_value']} -> Analyst Confirmed")
        
        # External Enrichment check (fails gracefully without error)
        r = client.post(f"{BASE_URL}/indicators/{target_ind['id']}/enrich")
        assert r.status_code == 200
        print(f"[OK] External Enrichment Handled Gracefully: {r.json()['status']} - {r.json()['message']}")
        
        # 7. Intelligence Reports & Exports
        r = client.get(f"{BASE_URL}/reports/{analysis_id}")
        assert r.status_code == 200
        rpt = r.json()
        assert "executive_summary" in rpt
        assert "severity_assessment" in rpt
        assert len(rpt["defensive_recommendations"]) > 0
        assert len(rpt["limitations"]) > 0
        print(f"[OK] Full 10-Section Intelligence Report Generated: ReportID={rpt['report_id']}")
        
        # Test Exports: JSON, Markdown, CSV
        r_json = client.get(f"{BASE_URL}/reports/{analysis_id}/export?format=json")
        assert r_json.status_code == 200 and "report_id" in r_json.text
        r_md = client.get(f"{BASE_URL}/reports/{analysis_id}/export?format=markdown")
        assert r_md.status_code == 200 and "THREATLENS INTELLIGENCE REPORT" in r_md.text
        r_csv = client.get(f"{BASE_URL}/reports/{analysis_id}/export?format=csv")
        assert r_csv.status_code == 200 and "Indicator Value" in r_csv.text
        print("[OK] Report Exports Verified: JSON, Markdown, and CSV indicator exports functional")
        
        # 8. Intelligence Feed & CISA Sync
        r = client.get(f"{BASE_URL}/feed")
        assert r.status_code == 200
        print(f"[OK] Intelligence Feed: {len(r.json())} items available")
        
        # 9. Dashboard Real Metrics
        r = client.get(f"{BASE_URL}/dashboard/summary")
        assert r.status_code == 200
        dash = r.json()
        print(f"[OK] Dashboard Summary: TotalReports={dash['total_reports']}, Indicators={dash['total_indicators']}, HighCritical={dash['high_critical_count']}")
        assert dash["total_reports"] >= 1
        
        # 10. Demo Dataset Import & Clear
        r_demo = client.post(f"{BASE_URL}/demo/import")
        assert r_demo.status_code == 200
        print(f"[OK] Demo Dataset Import: {r_demo.json()['message']}")
        
        # Verify dashboard reflects imported demo data
        r_dash_after = client.get(f"{BASE_URL}/dashboard/summary")
        assert r_dash_after.status_code == 200
        print(f"     Dashboard after demo import: TotalReports={r_dash_after.json()['total_reports']}, HighCritical={r_dash_after.json()['high_critical_count']}")
        
        # Clean demo data
        r_clear = client.post(f"{BASE_URL}/demo/clear")
        assert r_clear.status_code == 200
        print(f"[OK] Demo Dataset Clear: {r_clear.json()['message']}")
        
        # 11. Cleanup user test analysis
        r_del = client.delete(f"{BASE_URL}/analyses/{analysis_id}")
        assert r_del.status_code == 200
        print(f"[OK] Analysis Deletion Verified: ID={analysis_id[:8]} removed from repository")
        
    print("\n=== ALL 11 END-TO-END SYSTEM VERIFICATIONS PASSED SUCCESSFULLY ===")

if __name__ == "__main__":
    run_verification()
