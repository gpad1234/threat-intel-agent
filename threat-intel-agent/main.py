#!/usr/bin/env python3
"""
Threat Intelligence Analyst Agent — Main Entry Point
=====================================================

Run the full threat intelligence pipeline:
  python main.py

Run a single stage for testing:
  python main.py --stage collect
  python main.py --stage analyze
  python main.py --stage report

Run in one-shot mode (single agent, no subagent orchestration — good for MVP):
  python main.py --mvp
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from config import DATA_DIR, REPORTS_DIR, LLM_MODEL, LOCAL_MONITORING_ENABLED


def _invoke_agent(agent, user_message: str) -> str:
    """Invoke a deep agent with a user message and return the final response text.

    Deep agents are LangGraph CompiledStateGraphs. Input is a dict with
    'messages' list, output is a state dict with 'messages' list.
    """
    result = agent.invoke(
        {"messages": [{"role": "user", "content": user_message}]}
    )
    # The last message in the output state is the agent's final response
    messages = result.get("messages", [])
    if messages:
        last = messages[-1]
        return last.content if hasattr(last, "content") else str(last)
    return "(no response)"


def run_full_pipeline():
    """Run the complete orchestrated pipeline: Collect → Analyze → Report."""
    from agents.orchestrator import create_orchestrator_agent

    print("=" * 60)
    print("  Threat Intelligence Analyst Agent")
    print(f"  Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  Model: {LLM_MODEL}")
    print(f"  Local monitoring: {'ENABLED' if LOCAL_MONITORING_ENABLED else 'disabled'}")
    print("=" * 60)
    print()

    orchestrator = create_orchestrator_agent()
    result = _invoke_agent(
        orchestrator,
        "Execute the daily threat intelligence pipeline. "
        "Collect from all OSINT sources, analyze against this system, "
        "and generate today's security briefing."
    )

    print("\n" + "=" * 60)
    print("  Pipeline Complete")
    print("=" * 60)
    print(result)


def run_stage(stage: str):
    """Run a single pipeline stage for testing/debugging."""
    if stage == "collect":
        from agents.collector import create_collector_agent
        agent = create_collector_agent()
        result = _invoke_agent(
            agent,
            "Collect the latest threat intelligence from all OSINT sources. "
            "Store results in /data/ and write a collection summary."
        )

    elif stage == "analyze":
        from agents.analyzer import create_analyzer_agent
        agent = create_analyzer_agent()
        result = _invoke_agent(
            agent,
            "Analyze threat data from /data/ against this system's inventory. "
            "Write analysis results to /data/analysis_results.json."
        )

    elif stage == "report":
        from agents.reporter import create_reporter_agent
        agent = create_reporter_agent()
        result = _invoke_agent(
            agent,
            "Read analysis from /data/analysis_results.json and generate "
            "today's security briefing at /reports/briefing.md."
        )
    else:
        print(f"Unknown stage: {stage}. Use: collect, analyze, report")
        sys.exit(1)

    print(result)


def run_mvp():
    """
    MVP mode — single-agent, no subagent orchestration.
    Directly calls tools and produces a simple report.
    Good for quick testing or when you want minimal LLM token usage.
    """
    from deepagents import create_deep_agent
    from tools.fetch_nvd import fetch_nvd_cves
    from tools.fetch_cisa_kev import fetch_cisa_kev
    from tools.fetch_epss import fetch_epss_scores
    from tools.scan_local_system import scan_local_packages
    from tools.monitor_logs import scan_local_logs

    print("=" * 60)
    print("  Threat Intel Agent — MVP Mode (single agent)")
    print(f"  Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 60)
    print()

    mvp_instructions = """\
You are a security analyst. Perform a quick threat assessment:

1. Fetch recent high-severity CVEs from NVD
2. Check CISA KEV for actively exploited vulnerabilities
3. Get EPSS scores for any critical CVEs found
4. Scan local packages to check for relevance
5. If local monitoring is enabled, scan logs too
6. Write a brief Markdown report to /reports/briefing_mvp.md with:
   - Top threats found
   - Which are relevant to this system
   - Specific remediation commands

Keep it concise and actionable.
"""

    tools = [
        fetch_nvd_cves,
        fetch_cisa_kev,
        fetch_epss_scores,
        scan_local_packages,
        scan_local_logs,
    ]

    agent = create_deep_agent(
        model=LLM_MODEL,
        tools=tools,
        system_prompt=mvp_instructions,
    )

    result = _invoke_agent(
        agent,
        "Run a quick threat assessment. Fetch NVD CVEs and CISA KEV, "
        "scan local packages, cross-reference, and produce a brief report."
    )

    print(result)


def main():
    parser = argparse.ArgumentParser(
        description="Threat Intelligence Analyst Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--stage",
        choices=["collect", "analyze", "report"],
        help="Run a single pipeline stage instead of the full pipeline.",
    )
    parser.add_argument(
        "--mvp",
        action="store_true",
        help="Run in MVP mode (single agent, no subagent orchestration).",
    )

    args = parser.parse_args()

    if args.mvp:
        run_mvp()
    elif args.stage:
        run_stage(args.stage)
    else:
        run_full_pipeline()


if __name__ == "__main__":
    main()
