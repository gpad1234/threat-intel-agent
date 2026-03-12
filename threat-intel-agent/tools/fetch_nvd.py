"""
Fetch recent CVEs from the NIST National Vulnerability Database (NVD).
Free API — no key required (rate limited to ~5 requests per 30 seconds).
With an API key, rate limit increases to 50 requests per 30 seconds.

API Docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from langchain_core.tools import tool

from config import NVD_API_BASE, CVE_LOOKBACK_DAYS, MAX_CVES_PER_RUN, MIN_CVSS_SCORE, DATA_DIR


def _parse_cve(item: dict) -> dict:
    """Extract the useful fields from a raw NVD CVE item."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    # Description
    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "No description",
    )

    # CVSS score — try v3.1 first, fallback to v3.0, then v2.0
    metrics = cve.get("metrics", {})
    cvss_score = 0.0
    cvss_vector = ""
    severity = "UNKNOWN"

    for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(version_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            cvss_vector = cvss_data.get("vectorString", "")
            severity = metric_list[0].get("baseSeverity",
                       cvss_data.get("baseSeverity", "UNKNOWN"))
            break

    # Affected products (CPE matches)
    affected = []
    configurations = cve.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    affected.append(match.get("criteria", ""))

    # References
    references = [
        ref.get("url", "") for ref in cve.get("references", [])[:5]
    ]

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "affected_cpe": affected[:10],  # Limit to keep output manageable
        "references": references,
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
    }


@tool
def fetch_nvd_cves(
    lookback_days: Optional[int] = None,
    keyword: Optional[str] = None,
) -> str:
    """Fetch recent CVEs from the NIST National Vulnerability Database.

    Args:
        lookback_days: Number of days back to search (default from config).
        keyword: Optional keyword to filter CVEs (e.g. 'linux', 'apache').

    Returns:
        JSON string with list of parsed CVE records.
    """
    days = lookback_days or CVE_LOOKBACK_DAYS
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": min(MAX_CVES_PER_RUN, 100),
    }
    if keyword:
        params["keywordSearch"] = keyword

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(NVD_API_BASE, params=params)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as e:
        return json.dumps({"error": f"NVD API request failed: {str(e)}", "cves": []})

    raw_items = data.get("vulnerabilities", [])
    parsed = [_parse_cve(item) for item in raw_items]

    # Filter by minimum CVSS score
    filtered = [c for c in parsed if c["cvss_score"] >= MIN_CVSS_SCORE]

    # Sort by severity descending
    filtered.sort(key=lambda c: c["cvss_score"], reverse=True)

    result = {
        "source": "NVD",
        "query_period": f"{start.date()} to {now.date()}",
        "total_returned": len(raw_items),
        "after_cvss_filter": len(filtered),
        "min_cvss_threshold": MIN_CVSS_SCORE,
        "cves": filtered[:MAX_CVES_PER_RUN],
    }

    # Persist to data dir
    outpath = DATA_DIR / f"nvd_cves_{now.strftime('%Y%m%d_%H%M%S')}.json"
    outpath.write_text(json.dumps(result, indent=2))

    return json.dumps(result, indent=2)
