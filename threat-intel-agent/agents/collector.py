"""
Collector Subagent — gathers threat intelligence from all free OSINT sources.

This is the first stage of the pipeline. It fetches data from:
- NVD (CVEs)
- CISA KEV (actively exploited vulns)
- EPSS (exploit probability scores)
- GitHub Advisories
- ThreatFox (IOCs)
- Security RSS feeds

All data is stored in the agent's virtual file system for downstream analysis.
"""

from deepagents import create_deep_agent

from tools.fetch_nvd import fetch_nvd_cves
from tools.fetch_cisa_kev import fetch_cisa_kev
from tools.fetch_epss import fetch_epss_scores
from tools.fetch_github_advisories import fetch_github_advisories
from tools.fetch_threatfox import fetch_threatfox_iocs
from tools.fetch_rss_feeds import fetch_security_rss

from config import LLM_MODEL


COLLECTOR_INSTRUCTIONS = """\
You are a Threat Intelligence Collector. Your job is to gather the latest
threat data from all available free OSINT sources.

Execute the following collection plan:

1. Fetch recent CVEs from NVD (National Vulnerability Database)
2. Fetch the CISA Known Exploited Vulnerabilities catalog for active threats
3. Fetch EPSS scores for any high-severity CVEs found in steps 1-2
4. Fetch GitHub Security Advisories (focus on pip and npm ecosystems)
5. Fetch recent IOCs from ThreatFox
6. Fetch security news from RSS feeds

For each source:
- Call the appropriate tool
- Write the results to a file in the virtual filesystem (e.g. /data/nvd_cves.json)
- Note any errors or rate-limiting issues

After all collections complete, write a summary file at /data/collection_summary.md
listing:
- Each source queried
- Number of items retrieved
- Any errors encountered
- Timestamp of collection

Be thorough but respect rate limits. If a source fails, log the error and
continue with other sources — do not abort the entire collection.
"""


def create_collector_agent():
    """Create the Collector subagent with all feed-fetching tools."""
    return create_deep_agent(
        model=LLM_MODEL,
        tools=[
            fetch_nvd_cves,
            fetch_cisa_kev,
            fetch_epss_scores,
            fetch_github_advisories,
            fetch_threatfox_iocs,
            fetch_security_rss,
        ],
        system_prompt=COLLECTOR_INSTRUCTIONS,
    )
