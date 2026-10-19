from __future__ import annotations
import logging
import json
from typing import Dict, Any, List
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from app.models.entities import (
    Analysis, Indicator, AnalysisIndicator, ExtractedEntity,
    AttackTechnique, AnalysisTechnique, AnalystNote, AuditEvent, IntelligenceFeedItem
)
from app.services.ioc_extractor import IOCExtractor
from app.services.entity_extractor import entity_extractor
from app.services.threat_classifier import threat_classifier
from app.services.severity_engine import SeverityEngine
from app.services.attack_mapper import AttackMapper
from app.services.recommendation_engine import RecommendationEngine

logger = logging.getLogger(__name__)

# RFC 5737 and RFC 2606 compliant demonstration threat scenarios
DEMO_SCENARIOS = [
    {
        "title": "[DEMO] Urgent Wire Transfer Phishing Lure Targeting Finance",
        "source": "Demonstration Synthetic Feed",
        "category_expected": "Phishing",
        "text": """Employees received spearphishing emails originating from spoofed sender accounting[at]corporate-billing-portal[.]example.com.
The lure urges employees to review an attached remittance advisory or click hxxps://login.verify-portal.example[.]com/auth to verify urgent invoices.
The lure directs credentials to external server 192.0.2.45 and drops a macro document SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.
User execution triggers PowerShell credential harvesting script communicating with hxxp://c2.phishdelivery.example[.]net."""
    },
    {
        "title": "[DEMO] LockBit-Style Ransomware Outbreak with Shadow Copy Deletion",
        "source": "Demonstration Synthetic Feed",
        "category_expected": "Ransomware",
        "text": """Critical incident detected across multiple workstation subnets. Ransomware binary dropped ransom note RESTORE-FILES.txt.
Confirmed widespread active encryption of shared file shares with double extortion threats published on darknet leak site.
Adversaries executed 'vssadmin delete shadows /all /quiet' via PowerShell interpreter to eliminate backups.
Network beaconing identified connecting to C2 IP 198.51.100.77 on port 443. File hash identified as MD5 44d88612fea8a8f36de82e1278abb02f.
Domain controller compromise reported with ticket dumping."""
    },
    {
        "title": "[DEMO] Log4Shell Vulnerability Exploitation on Edge Apache Servers",
        "source": "Demonstration Synthetic Feed",
        "category_expected": "Vulnerability Exploitation",
        "text": """Public-facing Apache Solr web service exploited using CVE-2021-44228 (Log4Shell) unauthenticated remote code execution.
In the wild exploitation confirmed from external reconnaissance IP 203.0.113.15.
Adversary dropped persistent web shell on web server component and attempted privilege escalation.
Follow-on communication established to malicious host payload-delivery.example[.]org."""
    },
    {
        "title": "[DEMO] Privileged Credential Dumping via Mimikatz in Engineering",
        "source": "Demonstration Synthetic Feed",
        "category_expected": "Credential Theft",
        "text": """Endpoint detection alert triggered on engineering workstation for credential dumping activity.
Adversary executed Mimikatz to extract plaintext passwords and NTLM hashes from LSASS memory space.
Password spray and brute force activity subsequently detected targeting Active Directory Domain Admins.
Attacker established RDP lateral movement using stolen credentials to file server 192.0.2.110."""
    },
    {
        "title": "[DEMO] Scheduled Security Audit & Patch Baseline Notice",
        "source": "Demonstration Synthetic Feed",
        "category_expected": "Benign or Informational",
        "text": """This is a routine informational notice regarding scheduled maintenance and security patch deployment.
Internal systems will undergo authorized vulnerability scan and OS patching on Sunday at 02:00 UTC.
No malicious compromise has occurred. This advisory serves as general security baseline documentation."""
    }
]

class DemoDataService:
    """
    Manages importing and safely clearing demonstration intelligence records.
    All demonstration records are explicitly tagged with source 'Demonstration Synthetic Feed'.
    """

    @classmethod
    def import_demo_data(cls, db: Session) -> Dict[str, Any]:
        """Imports the standardized demo scenarios into the database."""
        imported_count = 0
        now = datetime.now(timezone.utc)

        for i, scenario in enumerate(DEMO_SCENARIOS):
            # Check if this demo record already exists
            existing = db.query(Analysis).filter(
                Analysis.title == scenario["title"],
                Analysis.source == scenario["source"]
            ).first()
            if existing:
                continue

            text = scenario["text"]
            # 1. Run extraction & classification
            iocs = IOCExtractor.extract_all(text)
            entities = entity_extractor.extract_entities(text)
            clf = threat_classifier.predict(text)
            severity_data = SeverityEngine.assess_severity(
                text=text,
                category=clf["predicted_category"],
                indicators=iocs,
                entities=entities,
                source=scenario["source"]
            )
            techniques = AttackMapper.map_techniques(text, db)
            recommendations = RecommendationEngine.generate_recommendations(clf["predicted_category"], iocs)

            # 2. Persist Analysis
            analysis = Analysis(
                title=scenario["title"],
                original_text=text,
                input_type="text",
                source=scenario["source"],
                predicted_category=clf["predicted_category"],
                confidence=clf["confidence"],
                prediction_method=clf["prediction_method"],
                model_version=clf.get("model_version"),
                is_uncertain=clf["is_uncertain"],
                severity=severity_data["severity"],
                severity_score=severity_data["severity_score"],
                severity_rationale=json.dumps(severity_data),
                defensive_recommendations=json.dumps(recommendations),
                status="Completed",
                created_at=now - timedelta(days=(len(DEMO_SCENARIOS) - i))
            )
            db.add(analysis)
            db.flush()

            # 3. Persist Indicators & Linkages
            for ioc in iocs:
                ind = db.query(Indicator).filter(Indicator.normalized_value == ioc["normalized_value"]).first()
                if not ind:
                    ind = Indicator(
                        normalized_value=ioc["normalized_value"],
                        original_value=ioc["original_value"],
                        indicator_type=ioc["indicator_type"],
                        reputation_status="Suspicious (Demo Dataset)",
                        reputation_source="Demo Synthetic Intelligence",
                        verification_status="Analyst Confirmed" if i < 3 else "Unverified",
                        first_observed=analysis.created_at,
                        last_observed=analysis.created_at
                    )
                    db.add(ind)
                    db.flush()

                # Link indicator to analysis
                link = AnalysisIndicator(
                    analysis_id=analysis.id,
                    indicator_id=ind.id,
                    evidence_snippet=ioc["evidence_snippet"],
                    extraction_method="Regex Engine",
                    extraction_confidence=ioc["confidence"],
                    source_start=ioc["start"],
                    source_end=ioc["end"]
                )
                db.add(link)

            # 4. Persist Entities
            for ent in entities:
                db_ent = ExtractedEntity(
                    analysis_id=analysis.id,
                    entity_type=ent["entity_type"],
                    entity_value=ent["entity_value"],
                    evidence_snippet=ent["evidence_snippet"],
                    confidence=ent["confidence"],
                    verification_status="Automated Detection"
                )
                db.add(db_ent)

            # 5. Persist Techniques
            for tech in techniques:
                db_tech = AnalysisTechnique(
                    analysis_id=analysis.id,
                    technique_id=tech["database_id"],
                    evidence=tech["evidence"],
                    mapping_confidence=tech["mapping_confidence"],
                    verification_status="Potential Mapping"
                )
                db.add(db_tech)

            # 6. Add demonstration feed item
            feed_item = IntelligenceFeedItem(
                title=scenario["title"],
                source=scenario["source"],
                publication_date=analysis.created_at,
                threat_category=clf["predicted_category"],
                severity=severity_data["severity"],
                indicators_json=json.dumps([ioc["normalized_value"] for ioc in iocs]),
                summary=text[:160] + "...",
                is_local=True
            )
            db.add(feed_item)

            imported_count += 1

        db.commit()
        return {
            "success": True,
            "imported_count": imported_count,
            "message": f"Successfully imported {imported_count} demonstration threat analysis records."
        }

    @classmethod
    def clear_demo_data(cls, db: Session) -> Dict[str, Any]:
        """Safely removes all demonstration intelligence records without affecting user submissions."""
        demo_analyses = db.query(Analysis).filter(Analysis.source == "Demonstration Synthetic Feed").all()
        removed_count = len(demo_analyses)

        for a in demo_analyses:
            db.delete(a)

        # Remove demo feed items
        db.query(IntelligenceFeedItem).filter(IntelligenceFeedItem.source == "Demonstration Synthetic Feed").delete()
        
        # Log audit event
        audit = AuditEvent(
            entity_type="SYSTEM",
            entity_id="DEMO_DATA",
            action="CLEAR_DEMO_RECORDS",
            details=f"Cleared {removed_count} demonstration analysis records."
        )
        db.add(audit)
        db.commit()

        return {
            "success": True,
            "removed_count": removed_count,
            "message": f"Successfully cleared {removed_count} demonstration intelligence records."
        }
