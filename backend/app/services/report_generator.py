import json
import csv
import io
from typing import Dict, Any, List
from datetime import datetime, timezone

class ReportGenerator:
    """
    Threat intelligence report generation engine.
    Formats structured intelligence reports and produces JSON, CSV, and formatted Markdown exports.
    """

    @classmethod
    def generate_full_report(cls, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assembles all sections into a comprehensive intelligence report schema."""
        title = analysis_data.get("title", "Threat Intelligence Assessment")
        analysis_id = analysis_data.get("id", "Unknown")
        created_at = analysis_data.get("created_at", datetime.now(timezone.utc).isoformat())
        category = analysis_data.get("predicted_category", "Unknown")
        severity = analysis_data.get("severity", "Informational")
        confidence = analysis_data.get("confidence", 0.0)
        method = analysis_data.get("prediction_method", "Rule-based Fallback")
        is_uncertain = analysis_data.get("is_uncertain", False)
        
        indicators = analysis_data.get("indicators", [])
        entities = analysis_data.get("entities", [])
        techniques = analysis_data.get("techniques", [])
        recommendations = analysis_data.get("recommendations") or analysis_data.get("defensive_recommendations", [])
        
        # Parse severity rationale
        rationale_raw = analysis_data.get("severity_rationale")
        rationale = json.loads(rationale_raw) if isinstance(rationale_raw, str) else (rationale_raw or {})
        
        # Build concise executive summary
        exec_summary = (
            f"ThreatLens analyzed report '{title}' and classified the activity under the {category} category "
            f"with an initial triage severity assessment of {severity}. "
            f"The extraction engine recovered {len(indicators)} technical indicators of compromise and "
            f"{len(entities)} contextual entities. "
            f"Identified {len(techniques)} potential MITRE ATT&CK technique mapping(s)."
        )

        limitations = [
            "Assessments are produced via automated natural language processing and technical heuristics.",
            "Absence of external detections does not guarantee an indicator is harmless.",
            "Triage determinations require validation against organization telemetry (EDR/SIEM logs)."
        ]
        if is_uncertain:
            limitations.append("Classification algorithm reported high uncertainty or limited category evidence.")

        report = {
            "report_id": f"TL-RPT-{analysis_id[:8].upper()}",
            "analysis_id": analysis_id,
            "title": title,
            "created_at": created_at,
            "source": analysis_data.get("source", "Manual Submission"),
            "status": analysis_data.get("status", "Completed"),
            "executive_summary": exec_summary,
            "classification": {
                "category": category,
                "confidence": confidence,
                "prediction_method": method,
                "model_version": analysis_data.get("model_version"),
                "is_uncertain": is_uncertain,
                "uncertainty_reason": analysis_data.get("uncertainty_reason")
            },
            "severity_assessment": {
                "severity": severity,
                "score": rationale.get("severity_score", 0.0),
                "triggered_rules": rationale.get("triggered_rules", []),
                "missing_information": rationale.get("missing_information", []),
                "recommended_investigation_steps": rationale.get("recommended_investigation_steps", [])
            },
            "indicators": indicators,
            "entities": entities,
            "attack_techniques": techniques,
            "defensive_recommendations": recommendations,
            "evidence_snippets": [
                {
                    "type": i.get("indicator_type"),
                    "indicator": i.get("defanged_value") or i.get("normalized_value"),
                    "snippet": i.get("evidence_snippet")
                }
                for i in indicators if i.get("evidence_snippet")
            ],
            "limitations": limitations
        }
        return report

    @classmethod
    def export_csv_indicators(cls, indicators: List[Dict[str, Any]]) -> str:
        """Exports extracted indicators of compromise to CSV format."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Indicator Value",
            "Defanged Value",
            "Type",
            "Reputation Status",
            "Verification Status",
            "Confidence",
            "Evidence Snippet"
        ])
        for ind in indicators:
            writer.writerow([
                ind.get("normalized_value", ""),
                ind.get("defanged_value", ""),
                ind.get("indicator_type", ""),
                ind.get("reputation_status", "Not checked"),
                ind.get("verification_status", "Unverified"),
                ind.get("extraction_confidence", ind.get("confidence", 1.0)),
                ind.get("evidence_snippet", "")
            ])
        return output.getvalue()

    @classmethod
    def export_markdown(cls, report: Dict[str, Any]) -> str:
        """Generates a professional GitHub-flavored Markdown report."""
        lines = [
            f"# THREATLENS INTELLIGENCE REPORT: {report['title']}",
            f"**Report ID**: `{report['report_id']}` | **Date**: {report['created_at']} | **Status**: {report['status']}",
            "",
            "## 1. Executive Summary",
            report['executive_summary'],
            "",
            "## 2. Threat Classification & Severity",
            f"- **Predicted Category**: {report['classification']['category']}",
            f"- **Confidence Score**: {report['classification']['confidence']}",
            f"- **Methodology**: {report['classification']['prediction_method']}",
            f"- **Assessed Severity**: {report['severity_assessment']['severity']} (Score: {report['severity_assessment']['score']}/10.0)",
            "",
            "### Triggered Severity Rules",
        ]

        for rule in report['severity_assessment']['triggered_rules']:
            lines.append(f"- **{rule.get('rule')}** (+{rule.get('weight')}): {rule.get('description')}")

        lines.extend([
            "",
            "## 3. Extracted Indicators of Compromise (IoCs)",
            "| Indicator (Defanged) | Type | Reputation | Verification Status |",
            "| :--- | :--- | :--- | :--- |"
        ])

        for ind in report['indicators']:
            val = ind.get('defanged_value') or ind.get('normalized_value')
            lines.append(f"| `{val}` | {ind.get('indicator_type')} | {ind.get('reputation_status', 'Not checked')} | {ind.get('verification_status', 'Unverified')} |")

        lines.extend([
            "",
            "## 4. Relevant MITRE ATT&CK Techniques",
            "| Technique ID | Name | Tactic | Confidence |",
            "| :--- | :--- | :--- | :--- |"
        ])

        for tech in report['attack_techniques']:
            lines.append(f"| `{tech.get('technique_id')}` | {tech.get('technique_name')} | {tech.get('tactic')} | {tech.get('mapping_confidence')} |")

        lines.extend([
            "",
            "## 5. Defensive Recommendations",
        ])

        for rec in report['defensive_recommendations']:
            lines.append(f"- **{rec.get('action')}**: {rec.get('detail')}")

        lines.extend([
            "",
            "## 6. Investigation Limitations & Missing Context",
        ])

        for lim in report['limitations']:
            lines.append(f"- {lim}")

        for miss in report['severity_assessment']['missing_information']:
            lines.append(f"- *Missing*: {miss}")

        return "\n".join(lines)
