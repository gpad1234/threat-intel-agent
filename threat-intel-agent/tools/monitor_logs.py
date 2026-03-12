"""
Optional local log monitoring tool — activated when LOCAL_MONITORING_ENABLED=true.

When the server has activity, this tool scans local log files for suspicious
patterns: failed SSH logins, privilege escalation attempts, unusual processes,
high error rates, etc.

This is the "if we are able to get activity" enhancement — it turns the
passive threat intel agent into an active log-based intrusion detector.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from langchain_core.tools import tool

from config import LOCAL_MONITORING_ENABLED, ACTIVE_LOG_PATHS, DATA_DIR


# ─── Suspicious patterns to search for in logs ───────────────────────────────
SUSPICIOUS_PATTERNS = [
    {
        "name": "ssh_brute_force",
        "description": "Failed SSH login attempts (potential brute force)",
        "pattern": r"Failed password for .+ from (\S+)",
        "log_files": ["/var/log/auth.log"],
        "severity": "HIGH",
    },
    {
        "name": "ssh_invalid_user",
        "description": "SSH login attempts with invalid/unknown usernames",
        "pattern": r"Invalid user (\S+) from (\S+)",
        "log_files": ["/var/log/auth.log"],
        "severity": "HIGH",
    },
    {
        "name": "sudo_failures",
        "description": "Failed sudo/privilege escalation attempts",
        "pattern": r"sudo:.+authentication failure|FAILED su for",
        "log_files": ["/var/log/auth.log", "/var/log/syslog"],
        "severity": "CRITICAL",
    },
    {
        "name": "kernel_segfault",
        "description": "Kernel segmentation faults (potential exploit attempts)",
        "pattern": r"segfault at|general protection fault",
        "log_files": ["/var/log/kern.log", "/var/log/syslog"],
        "severity": "MEDIUM",
    },
    {
        "name": "oom_killer",
        "description": "Out-of-memory kills (potential DoS or resource abuse)",
        "pattern": r"Out of memory: Killed process|oom-kill|oom_reaper",
        "log_files": ["/var/log/kern.log", "/var/log/syslog"],
        "severity": "MEDIUM",
    },
    {
        "name": "service_failures",
        "description": "Service start/restart failures",
        "pattern": r"Failed to start|service .+ failed|entered failed state",
        "log_files": ["/var/log/syslog"],
        "severity": "LOW",
    },
    {
        "name": "web_suspicious_paths",
        "description": "Web requests to suspicious paths (scanners, exploit probes)",
        "pattern": r'(?:GET|POST) .+(?:/wp-admin|/phpmyadmin|/\.env|/actuator|/config\.php|/shell|/eval)',
        "log_files": ["/var/log/nginx/access.log", "/var/log/apache2/access.log"],
        "severity": "MEDIUM",
    },
    {
        "name": "web_high_error_rate",
        "description": "HTTP 4xx/5xx error responses",
        "pattern": r'" (?:4\d{2}|5\d{2}) ',
        "log_files": ["/var/log/nginx/access.log", "/var/log/apache2/access.log"],
        "severity": "LOW",
    },
    {
        "name": "disk_errors",
        "description": "Disk I/O errors (potential hardware compromise or failure)",
        "pattern": r"I/O error|Medium Error|disk error|read error",
        "log_files": ["/var/log/kern.log", "/var/log/syslog"],
        "severity": "HIGH",
    },
]


def _tail_file(filepath: str, max_lines: int = 5000) -> list[str]:
    """Read the last N lines from a file. Returns empty list if file doesn't exist."""
    try:
        path = Path(filepath)
        if not path.exists():
            return []
        # Use deque for efficient tail reading
        from collections import deque
        with open(path, "r", errors="ignore") as f:
            return list(deque(f, maxlen=max_lines))
    except (PermissionError, OSError):
        return []


@tool
def scan_local_logs(max_lines_per_file: Optional[int] = None) -> str:
    """Scan local system logs for suspicious activity patterns.

    Only works when LOCAL_MONITORING_ENABLED=true in config.
    Searches auth logs, syslog, kernel logs, and web server logs for:
    - SSH brute force / invalid user attempts
    - Failed sudo / privilege escalation
    - Kernel segfaults (potential exploits)
    - OOM kills (potential DoS)
    - Suspicious web requests (scanner probes)
    - Disk errors

    Args:
        max_lines_per_file: How many recent log lines to scan per file (default 5000).

    Returns:
        JSON string with findings organized by severity.
    """
    if not LOCAL_MONITORING_ENABLED:
        return json.dumps({
            "source": "local_log_monitor",
            "enabled": False,
            "message": (
                "Local log monitoring is disabled. Set LOCAL_MONITORING_ENABLED=true "
                "in .env to enable. This feature works best on servers with active "
                "services generating logs."
            ),
            "findings": [],
        })

    if not ACTIVE_LOG_PATHS:
        return json.dumps({
            "source": "local_log_monitor",
            "enabled": True,
            "message": "No accessible log files found on this system.",
            "findings": [],
        })

    max_lines = max_lines_per_file or 5000
    findings = []
    files_scanned = []

    for pattern_def in SUSPICIOUS_PATTERNS:
        regex = re.compile(pattern_def["pattern"], re.IGNORECASE)
        matches_for_pattern = []

        for log_file in pattern_def["log_files"]:
            if log_file not in ACTIVE_LOG_PATHS:
                continue

            lines = _tail_file(log_file, max_lines)
            if not lines:
                continue

            if log_file not in files_scanned:
                files_scanned.append(log_file)

            for line in lines:
                match = regex.search(line)
                if match:
                    matches_for_pattern.append({
                        "file": log_file,
                        "line": line.strip()[:300],  # Truncate long lines
                        "matched_groups": match.groups()[:3],
                    })

        if matches_for_pattern:
            # Extract unique source IPs for network-based attacks
            source_ips = set()
            for m in matches_for_pattern:
                for group in m.get("matched_groups", []):
                    if group and re.match(r"\d+\.\d+\.\d+\.\d+", str(group)):
                        source_ips.add(str(group))

            findings.append({
                "pattern_name": pattern_def["name"],
                "description": pattern_def["description"],
                "severity": pattern_def["severity"],
                "match_count": len(matches_for_pattern),
                "source_ips": list(source_ips)[:20],
                "sample_matches": matches_for_pattern[:5],  # Keep top 5 samples
            })

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    result = {
        "source": "local_log_monitor",
        "enabled": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_scanned": files_scanned,
        "total_findings": len(findings),
        "severity_summary": {
            sev: sum(1 for f in findings if f["severity"] == sev)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        },
        "findings": findings,
    }

    # Persist
    now = datetime.now(timezone.utc)
    outpath = DATA_DIR / f"log_findings_{now.strftime('%Y%m%d_%H%M%S')}.json"
    outpath.write_text(json.dumps(result, indent=2))

    return json.dumps(result, indent=2)
