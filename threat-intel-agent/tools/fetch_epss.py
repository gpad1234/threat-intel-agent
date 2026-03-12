"""
Fetch Exploit Prediction Scoring System (EPSS) data.
Free API — no key required.

EPSS gives each CVE a probability score (0-1) indicating the likelihood
it will be exploited in the next 30 days. Excellent for prioritization.

API Docs: https://www.first.org/epss/api
"""

import json
from datetime import datetime, timezone
from typing import Optional

import httpx
from langchain_core.tools import tool

from config import EPSS_API_BASE, DATA_DIR


@tool
def fetch_epss_scores(cve_ids: Optional[list[str]] = None) -> str:
    """Fetch EPSS exploit probability scores for specific CVEs or recent high-risk CVEs.

    EPSS scores range from 0 to 1, where higher = more likely to be exploited
    in the next 30 days. Use this to prioritize which CVEs to act on.

    Args:
        cve_ids: List of CVE IDs to look up (e.g. ["CVE-2024-1234", "CVE-2024-5678"]).
                 If None, fetches the top most likely-to-be-exploited CVEs.

    Returns:
        JSON string with EPSS scores for each CVE.
    """
    try:
        with httpx.Client(timeout=30.0) as client:
            if cve_ids:
                # Batch lookup — API supports comma-separated CVE IDs
                cve_param = ",".join(cve_ids[:100])  # API limit
                resp = client.get(EPSS_API_BASE, params={"cve": cve_param})
            else:
                # Get top high-risk CVEs (sorted by EPSS score descending)
                resp = client.get(
                    EPSS_API_BASE,
                    params={"order": "!epss", "limit": 30},
                )
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as e:
        return json.dumps({"error": f"EPSS API request failed: {str(e)}", "scores": []})

    raw_scores = data.get("data", [])

    scores = []
    for entry in raw_scores:
        scores.append({
            "cve_id": entry.get("cve", ""),
            "epss_score": float(entry.get("epss", 0)),
            "epss_percentile": float(entry.get("percentile", 0)),
            "date": entry.get("date", ""),
        })

    # Sort by EPSS score descending
    scores.sort(key=lambda s: s["epss_score"], reverse=True)

    result = {
        "source": "EPSS (FIRST.org)",
        "count": len(scores),
        "queried_cves": cve_ids or "top-risk",
        "scores": scores,
    }

    # Persist
    now = datetime.now(timezone.utc)
    outpath = DATA_DIR / f"epss_scores_{now.strftime('%Y%m%d_%H%M%S')}.json"
    outpath.write_text(json.dumps(result, indent=2))

    return json.dumps(result, indent=2)
