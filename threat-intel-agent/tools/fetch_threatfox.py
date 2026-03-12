"""
Fetch Indicators of Compromise (IOCs) from abuse.ch ThreatFox.
Free API — no key required.

ThreatFox provides IOCs (IP addresses, domains, URLs, hashes) associated
with malware, botnets, and other threats.

API Docs: https://threatfox.abuse.ch/api/
"""

import json
from datetime import datetime, timezone
from typing import Optional

import httpx
from langchain_core.tools import tool

from config import THREATFOX_API_URL, CVE_LOOKBACK_DAYS, DATA_DIR


@tool
def fetch_threatfox_iocs(lookback_days: Optional[int] = None) -> str:
    """Fetch recent Indicators of Compromise (IOCs) from ThreatFox (abuse.ch).

    Returns IP addresses, domains, URLs, and file hashes associated with
    active malware campaigns and botnets.

    Args:
        lookback_days: Fetch IOCs from the last N days (max 7, default from config).

    Returns:
        JSON string with list of IOCs.
    """
    days = min(lookback_days or CVE_LOOKBACK_DAYS, 7)  # API max is 7 days

    payload = {
        "query": "get_iocs",
        "days": days,
    }

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(THREATFOX_API_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as e:
        return json.dumps({"error": f"ThreatFox API failed: {str(e)}", "iocs": []})

    if data.get("query_status") != "ok":
        return json.dumps({
            "error": f"ThreatFox query error: {data.get('query_status', 'unknown')}",
            "iocs": [],
        })

    raw_iocs = data.get("data", []) or []

    iocs = []
    for ioc in raw_iocs[:100]:  # Limit to keep output manageable
        iocs.append({
            "id": ioc.get("id", ""),
            "ioc_type": ioc.get("ioc_type", ""),
            "ioc_value": ioc.get("ioc", ""),
            "threat_type": ioc.get("threat_type", ""),
            "malware": ioc.get("malware_printable", ""),
            "malware_alias": ioc.get("malware_alias", ""),
            "confidence_level": ioc.get("confidence_level", 0),
            "first_seen": ioc.get("first_seen_utc", ""),
            "last_seen": ioc.get("last_seen_utc", ""),
            "tags": ioc.get("tags", []),
            "reference": ioc.get("reference", ""),
        })

    # Group by threat type for quick analysis
    threat_types = {}
    for ioc in iocs:
        tt = ioc["threat_type"]
        threat_types[tt] = threat_types.get(tt, 0) + 1

    result = {
        "source": "ThreatFox (abuse.ch)",
        "lookback_days": days,
        "total_iocs": len(iocs),
        "threat_type_summary": threat_types,
        "iocs": iocs,
    }

    # Persist
    now = datetime.now(timezone.utc)
    outpath = DATA_DIR / f"threatfox_iocs_{now.strftime('%Y%m%d_%H%M%S')}.json"
    outpath.write_text(json.dumps(result, indent=2))

    return json.dumps(result, indent=2)
