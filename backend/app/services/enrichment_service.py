import logging
import httpx
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

class EnrichmentService:
    """
    Handles external threat intelligence lookups with strict error handling,
    transparent origin attribution, and graceful degradation when API keys are unconfigured.
    """

    @classmethod
    async def enrich_indicator(cls, indicator_value: str, indicator_type: str) -> Dict[str, Any]:
        """
        Enriches an individual indicator using configured providers.
        If no API keys are configured, returns an explicit unconfigured status.
        Never fabricates detection scores or external data.
        """
        now = datetime.now(timezone.utc).isoformat()

        # Check configuration
        vt_configured = bool(settings.VIRUSTOTAL_API_KEY and settings.VIRUSTOTAL_API_KEY.strip())
        otx_configured = bool(settings.ALIENVAULT_OTX_API_KEY and settings.ALIENVAULT_OTX_API_KEY.strip())

        if not vt_configured and not otx_configured:
            return {
                "success": False,
                "status": "Not configured",
                "message": "External threat intelligence integrations (VirusTotal / AlienVault OTX) are disabled or unconfigured. To enable live enrichment, provide API keys in backend configuration.",
                "reputation_status": "Not checked",
                "reputation_source": "Local System",
                "detections": None,
                "last_enriched_at": None,
                "provider_responses": {}
            }

        provider_responses = {}
        reputation_status = "Unknown"
        reputation_source = "External Providers"

        # 1. VirusTotal API v3
        if vt_configured:
            vt_res = await cls._lookup_virustotal(indicator_value, indicator_type)
            provider_responses["VirusTotal"] = vt_res
            if vt_res.get("success"):
                reputation_source = "VirusTotal v3"
                stats = vt_res.get("stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious > 0:
                    reputation_status = f"Malicious according to VirusTotal ({malicious} vendor detections)"
                elif suspicious > 0:
                    reputation_status = f"Suspicious according to VirusTotal ({suspicious} vendor flags)"
                else:
                    reputation_status = "No known detections reported by VirusTotal"

        # 2. AlienVault OTX
        if otx_configured and reputation_status == "Unknown":
            otx_res = await cls._lookup_alienvault_otx(indicator_value, indicator_type)
            provider_responses["AlienVault_OTX"] = otx_res
            if otx_res.get("success"):
                reputation_source = "AlienVault OTX"
                pulse_count = otx_res.get("pulse_count", 0)
                if pulse_count > 0:
                    reputation_status = f"Reported in {pulse_count} AlienVault OTX Pulses"
                else:
                    reputation_status = "No known detections reported by AlienVault OTX"

        return {
            "success": True,
            "status": "Enriched",
            "reputation_status": reputation_status,
            "reputation_source": reputation_source,
            "provider_responses": provider_responses,
            "last_enriched_at": now
        }

    @classmethod
    async def _lookup_virustotal(cls, value: str, ioc_type: str) -> Dict[str, Any]:
        """Queries VirusTotal API v3 based on indicator type."""
        endpoint = ""
        if ioc_type in ("ipv4", "ip"):
            endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
        elif ioc_type == "domain":
            endpoint = f"https://www.virustotal.com/api/v3/domains/{value}"
        elif ioc_type in ("md5", "sha1", "sha256"):
            endpoint = f"https://www.virustotal.com/api/v3/files/{value}"
        else:
            return {"success": False, "message": f"VirusTotal enrichment unsupported for type: {ioc_type}"}

        headers = {
            "x-apikey": settings.VIRUSTOTAL_API_KEY.strip(),
            "Accept": "application/json"
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(endpoint, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    return {
                        "success": True,
                        "stats": stats,
                        "raw": data.get("data", {}).get("attributes", {})
                    }
                elif res.status_code == 404:
                    return {"success": True, "stats": {"malicious": 0, "suspicious": 0, "undetected": 0}, "message": "Item not found in VirusTotal dataset."}
                elif res.status_code == 429:
                    return {"success": False, "message": "VirusTotal API rate limit exceeded."}
                else:
                    return {"success": False, "message": f"VirusTotal returned HTTP status {res.status_code}"}
        except Exception as e:
            logger.error(f"Error querying VirusTotal: {e}")
            return {"success": False, "message": f"Connection error: {str(e)}"}

    @classmethod
    async def _lookup_alienvault_otx(cls, value: str, ioc_type: str) -> Dict[str, Any]:
        """Queries AlienVault OTX Direct Indicators API."""
        type_path = "IPv4" if ioc_type in ("ipv4", "ip") else "domain" if ioc_type == "domain" else "file"
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/{type_path}/{value}/general"
        headers = {
            "X-OTX-API-KEY": settings.ALIENVAULT_OTX_API_KEY.strip(),
            "Accept": "application/json"
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(endpoint, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    pulse_info = data.get("pulse_info", {})
                    count = pulse_info.get("count", 0)
                    return {"success": True, "pulse_count": count}
                elif res.status_code == 404:
                    return {"success": True, "pulse_count": 0, "message": "Not found in AlienVault OTX pulses."}
                else:
                    return {"success": False, "message": f"AlienVault OTX returned HTTP status {res.status_code}"}
        except Exception as e:
            logger.error(f"Error querying AlienVault OTX: {e}")
            return {"success": False, "message": f"Connection error: {str(e)}"}

    @classmethod
    async def fetch_cisa_advisories(cls) -> Dict[str, Any]:
        """
        Retrieves real public CISA security advisories from CISA automated feed.
        Returns gracefully with informative status on network timeout or failure.
        """
        cisa_feed_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(cisa_feed_url)
                if res.status_code == 200:
                    data = res.json()
                    vulns = data.get("vulnerabilities", [])[:10]  # Take latest 10 advisories
                    items = []
                    for v in vulns:
                        items.append({
                            "title": f"CISA KEV: {v.get('cveID')} - {v.get('vulnerabilityName')}",
                            "source": "CISA Known Exploited Vulnerabilities",
                            "threat_category": "Vulnerability Exploitation",
                            "severity": "High",
                            "summary": v.get("shortDescription", "Actively exploited security vulnerability."),
                            "indicators": [v.get("cveID")],
                            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                            "publication_date": v.get("dateAdded")
                        })
                    return {"success": True, "advisories": items}
                else:
                    return {"success": False, "message": f"CISA feed returned status {res.status_code}", "advisories": []}
        except Exception as e:
            logger.warning(f"Unable to reach CISA public feed: {e}")
            return {
                "success": False,
                "message": f"Public CISA feed endpoint unreachable ({str(e)}). Using local intelligence records.",
                "advisories": []
            }
