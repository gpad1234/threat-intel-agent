"""
Fetch security advisories from the GitHub Advisory Database.
Free API — uses the public REST endpoint (no auth needed for public advisories).

Covers: npm, pip, Go, Rust, Maven, NuGet, and more.

Docs: https://docs.github.com/en/rest/security-advisories/global-advisories
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from langchain_core.tools import tool

from config import GITHUB_ADVISORIES_API, CVE_LOOKBACK_DAYS, DATA_DIR


@tool
def fetch_github_advisories(
    lookback_days: Optional[int] = None,
    ecosystem: Optional[str] = None,
) -> str:
    """Fetch recent security advisories from the GitHub Advisory Database.

    Args:
        lookback_days: How many days back to search (default from config).
        ecosystem: Filter by package ecosystem — one of:
                   'pip', 'npm', 'go', 'maven', 'nuget', 'rust', 'rubygems'.
                   If None, returns all ecosystems.

    Returns:
        JSON string with list of security advisories.
    """
    days = lookback_days or CVE_LOOKBACK_DAYS
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    params = {
        "per_page": 50,
        "sort": "updated",
        "direction": "desc",
        "type": "reviewed",
    }
    if ecosystem:
        params["ecosystem"] = ecosystem

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(GITHUB_ADVISORIES_API, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPError as e:
        return json.dumps({"error": f"GitHub Advisory API failed: {str(e)}", "advisories": []})

    advisories = []
    for adv in data:
        # Filter by date
        updated = adv.get("updated_at", "")
        try:
            updated_dt = datetime.fromisoformat(updated.replace("Z", "+00:00"))
            cutoff_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
            if updated_dt < cutoff_dt:
                continue
        except (ValueError, TypeError):
            pass

        # Extract affected packages
        affected_pkgs = []
        for vuln in adv.get("vulnerabilities", []):
            pkg = vuln.get("package", {})
            affected_pkgs.append({
                "ecosystem": pkg.get("ecosystem", ""),
                "name": pkg.get("name", ""),
                "vulnerable_range": vuln.get("vulnerable_version_range", ""),
                "first_patched": vuln.get("first_patched_version", ""),
            })

        advisories.append({
            "ghsa_id": adv.get("ghsa_id", ""),
            "cve_id": adv.get("cve_id", ""),
            "summary": adv.get("summary", ""),
            "description": (adv.get("description", "") or "")[:500],
            "severity": adv.get("severity", "unknown"),
            "cvss_score": (adv.get("cvss", {}) or {}).get("score", 0),
            "affected_packages": affected_pkgs,
            "published_at": adv.get("published_at", ""),
            "updated_at": updated,
            "url": adv.get("html_url", ""),
        })

    result = {
        "source": "GitHub Advisory Database",
        "ecosystem_filter": ecosystem or "all",
        "lookback_days": days,
        "count": len(advisories),
        "advisories": advisories,
    }

    # Persist
    now = datetime.now(timezone.utc)
    outpath = DATA_DIR / f"github_advisories_{now.strftime('%Y%m%d_%H%M%S')}.json"
    outpath.write_text(json.dumps(result, indent=2))

    return json.dumps(result, indent=2)
