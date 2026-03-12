"""
Analyzer Subagent — cross-references threat data against local system inventory.

This is the second stage of the pipeline. It:
1. Reads collected threat data (CVEs, CISA KEV, EPSS, advisories)
2. Scans the local system for installed packages, ports, services
3. Cross-references to determine which threats are RELEVANT to this system
4. Assigns a priority score combining CVSS + EPSS + CISA KEV status
5. Generates specific mitigation recommendations

When LOCAL_MONITORING_ENABLED=true, it also analyzes local log patterns
and correlates them with known threat activity.
"""

from deepagents import create_deep_agent

from tools.scan_local_system import (
    scan_local_packages,
    scan_docker_images,
    scan_open_ports,
    scan_system_services,
    get_full_system_inventory,
)
from tools.monitor_logs import scan_local_logs
from tools.fetch_epss import fetch_epss_scores

from config import LLM_MODEL, LOCAL_MONITORING_ENABLED, PROTECTED_SERVICES, PROTECTED_PORTS


ANALYZER_INSTRUCTIONS = """\
You are a Threat Intelligence Analyzer. Your job is to determine which
collected threats are relevant to THIS specific system and prioritize them.

## ⚠️  CRITICAL SAFETY CONSTRAINT
This server has PROTECTED SERVICES:
- **nginx on port 80** — serves a valuable production application
- Flag nginx-related CVEs as relevant but mark them "PROTECTED — MANUAL REVIEW"
- NEVER include remediation that would restart or modify nginx
- All other services can be handled normally

## Analysis Workflow

1. **System Inventory**: Run `get_full_system_inventory` to snapshot what
   software, services, and ports are running on this system.

2. **Read Collected Data**: Read the threat data files from the virtual
   filesystem (/data/) that the Collector has gathered:
   - NVD CVEs
   - CISA KEV entries
   - GitHub Advisories
   - ThreatFox IOCs
   - Security RSS news

3. **Relevance Matching**: For each CVE/advisory, check if ANY of the
   affected packages/products match what's installed locally:
   - Match apt package names against CPE product names in CVEs
   - Match pip/npm packages against GitHub advisory affected packages
   - Check if affected services (nginx, apache, sshd, etc.) are running
   - Check if affected ports are open

4. **Priority Scoring**: For relevant threats, compute a priority score:
   - CVSS score (0-10): base severity
   - EPSS score (0-1): probability of exploitation in next 30 days
   - CISA KEV flag: +3 if on the CISA KEV list (actively exploited)
   - Local exposure: +2 if the affected service is internet-facing (listening on 0.0.0.0)
   
   Formula: priority = CVSS + (EPSS * 5) + KEV_bonus + exposure_bonus
   Scale: 0-20, where >=15 is CRITICAL, >=10 is HIGH, >=5 is MEDIUM, <5 is LOW

5. **Mitigation Recommendations**: For each relevant threat, provide:
   - Specific `apt upgrade` or `pip install --upgrade` commands
   - Configuration changes if applicable
   - Workarounds if no patch is available
   - Whether a service restart is required

{log_analysis_section}

6. **Write Analysis Report**: Save the analysis to /data/analysis_results.json with:
   - All relevant CVEs with priority scores
   - All relevant advisories
   - IOC watchlist
   - Mitigation action items (sorted by priority)
   - System summary statistics

Be precise. If a CVE doesn't match anything installed on this system, mark it
as "not relevant" and don't include it in the priority list. We want signal, not noise.
"""

LOG_ANALYSIS_SECTION = """
5b. **Local Log Analysis** (LOCAL_MONITORING_ENABLED=true):
   - Run `scan_local_logs` to check for suspicious patterns
   - Cross-reference any source IPs from log findings against IOCs
   - If SSH brute force IPs match known ThreatFox IOCs, flag as CRITICAL
   - Include log findings in the analysis report with correlation notes
"""

NO_LOG_SECTION = """
Note: Local log monitoring is disabled. The analysis will focus on
vulnerability/patch relevance only. To enable log analysis, set
LOCAL_MONITORING_ENABLED=true in .env.
"""


def create_analyzer_agent():
    """Create the Analyzer subagent with system scanning and EPSS lookup tools."""
    # Choose the right instructions based on log monitoring config
    log_section = LOG_ANALYSIS_SECTION if LOCAL_MONITORING_ENABLED else NO_LOG_SECTION
    instructions = ANALYZER_INSTRUCTIONS.format(log_analysis_section=log_section)

    tools = [
        scan_local_packages,
        scan_docker_images,
        scan_open_ports,
        scan_system_services,
        get_full_system_inventory,
        fetch_epss_scores,
        scan_local_logs,
    ]

    return create_deep_agent(
        model=LLM_MODEL,
        tools=tools,
        system_prompt=instructions
    )
