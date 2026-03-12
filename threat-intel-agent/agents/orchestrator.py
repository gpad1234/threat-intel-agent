"""
Orchestrator Agent — the top-level Deep Agent that plans and coordinates
the entire threat intelligence pipeline.

This is the main entry point. The orchestrator:
1. Plans the daily workflow
2. Delegates to Collector → Analyzer → Reporter subagents
3. Manages the virtual file system for data passing between stages
4. Handles errors and retries
"""

from deepagents import create_deep_agent

from agents.collector import create_collector_agent
from agents.analyzer import create_analyzer_agent
from agents.reporter import create_reporter_agent

from config import LLM_MODEL, LOCAL_MONITORING_ENABLED


ORCHESTRATOR_INSTRUCTIONS = """\
You are the Threat Intelligence Orchestrator — the top-level coordinator
for a daily security intelligence pipeline running on an Ubuntu server.

## Your Mission
Produce a comprehensive, actionable daily security briefing by coordinating
three specialist subagents.

## Pipeline Plan

### Step 1: Collect Threat Intelligence
Delegate to the **Collector** subagent with this task:
"Collect the latest threat intelligence from all available OSINT sources:
NVD CVEs, CISA KEV, EPSS scores, GitHub Advisories, ThreatFox IOCs,
and security RSS feeds. Store all data in /data/ and write a collection
summary to /data/collection_summary.md."

### Step 2: Analyze & Cross-Reference
Delegate to the **Analyzer** subagent with this task:
"Analyze the collected threat data against this system's inventory.
Read the data from /data/, scan the local system for installed packages
and running services, cross-reference for relevance, compute priority
scores, and write results to /data/analysis_results.json.{log_task}"

### Step 3: Generate Report
Delegate to the **Reporter** subagent with this task:
"Read the analysis results from /data/analysis_results.json and generate
a polished daily security briefing. Write the Markdown report to
/reports/briefing_YYYYMMDD.md."

### Step 4: Verify & Summarize
After all subagents complete:
1. Read the generated report from /reports/
2. Verify it contains all expected sections
3. Write a brief completion log to /data/pipeline_log.txt with:
   - Timestamp
   - Each stage's status (success/failure)
   - Total CVEs collected, relevant CVEs found, report path
4. Output a brief summary to the user

## Error Handling
- If the Collector fails on one source, it should continue with others
- If the Analyzer can't scan the local system (permissions), note it and
  analyze based on threat data alone
- If any subagent fails entirely, log the error and report what you can

## Important
- Execute steps sequentially — each depends on the previous step's output
- Be patient with API calls — some feeds have rate limits
- The goal is actionable intelligence, not just data dumps
"""

LOG_TASK_ADDON = (
    " Also scan local logs for suspicious activity patterns and correlate "
    "with known IOCs."
)


def create_orchestrator_agent():
    """Create the top-level Orchestrator agent that runs the full pipeline."""
    log_task = LOG_TASK_ADDON if LOCAL_MONITORING_ENABLED else ""
    instructions = ORCHESTRATOR_INSTRUCTIONS.format(log_task=log_task)

    # Build subagents as CompiledSubAgent dicts.
    # Each must have 'name', 'description', and 'runnable' (a LangGraph Runnable).
    collector = {
        "name": "collector",
        "description": (
            "Collects threat intelligence from OSINT sources: NVD CVEs, "
            "CISA KEV, EPSS scores, GitHub Advisories, ThreatFox IOCs, "
            "and security RSS feeds. Stores data in /data/."
        ),
        "runnable": create_collector_agent(),
    }
    analyzer = {
        "name": "analyzer",
        "description": (
            "Analyzes collected threat data against this system's inventory. "
            "Scans local packages, services, open ports, and Docker images. "
            "Cross-references and scores threats. Writes results to "
            "/data/analysis_results.json."
        ),
        "runnable": create_analyzer_agent(),
    }
    reporter = {
        "name": "reporter",
        "description": (
            "Generates a polished Markdown security briefing from analysis "
            "results. Produces actionable remediation commands. Writes "
            "the report to /reports/."
        ),
        "runnable": create_reporter_agent(),
    }

    return create_deep_agent(
        model=LLM_MODEL,
        tools=[],
        system_prompt=instructions,
        subagents=[collector, analyzer, reporter],
        name="threat-intel-orchestrator",
    )
