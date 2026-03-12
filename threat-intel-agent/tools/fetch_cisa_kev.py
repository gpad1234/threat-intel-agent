"""
Fetch CISA Known Exploited Vulnerabilities (KEV) catalog.
Free JSON feed — no key required.

This is the list of CVEs that CISA has confirmed are being actively exploited
in the wild. Extremely high-signal data source.

Feed: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from langchain_core.tools import tool

from config import CISA_KEV_URL, CVE_LOOKBACK_DAYS, DATA_DIR


@tool
def fetch_cisa_kev(lookback_days: Optional[int] = None) -> str:
    """Fetch CISA Known Exploited Vulnerabilities catalog.

    These are CVEs confirmed to be actively exploited in the wild.
    This is the highest-signal threat intelligence feed available for free.

    Args:
        lookback_days: Only return entries added/modified in the last N days (default from config).

    Returns:
        JSON string with list of actively exploited vulnerabilities.
    """
    days = lookback_days or CVE_LOOKBACK_DAYS
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as e:
        return json.dumps({"error": f"CISA KEV fetch failed: {str(e)}", "vulnerabilities": []})

    catalog_version = data.get("catalogVersion", "unknown")
    all_vulns = data.get("vulnerabilities", [])

    # Filter to recent entries
    recent = []
    for vuln in all_vulns:
        date_added = vuln.get("dateAdded", "")
        try:
            added_dt = datetime.fromisoformat(date_added).replace(tzinfo=timezone.utc)
            if added_dt >= cutoff:
                recent.append({
                    "cve_id": vuln.get("cveID", ""),
                    "vendor": vuln.get("vendorProject", ""),
                    "product": vuln.get("product", ""),
                    "vulnerability_name": vuln.get("vulnerabilityName", ""),
                    "description": vuln.get("shortDescription", ""),
                    "date_added": date_added,
                    "due_date": vuln.get("dueDate", ""),
                    "required_action": vuln.get("requiredAction", ""),
                    "known_ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                    "notes": vuln.get("notes", ""),
                })
        except (ValueError, TypeError):
            continue

    # Sort by date added, most recent first
    recent.sort(key=lambda v: v["date_added"], reverse=True)

    result = {
        "source": "CISA KEV",
        "catalog_version": catalog_version,
        "total_in_catalog": len(all_vulns),
        "recent_count": len(recent),
        "lookback_days": days,
        "vulnerabilities": recent,
    }

    # Persist
    now = datetime.now(timezone.utc)
    outpath = DATA_DIR / f"cisa_kev_{now.strftime('%Y%m%d_%H%M%S')}.json"
    outpath.write_text(json.dumps(result, indent=2))

    return json.dumps(result, indent=2)
