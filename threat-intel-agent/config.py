"""
Configuration and environment settings for the Threat Intel Agent.
Loads from .env file or environment variables.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
_project_root = Path(__file__).parent
load_dotenv(_project_root / ".env")

# ─── LLM Provider ────────────────────────────────────────────────────────────
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")  # "anthropic" or "openai"
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
#--LLM_MODEL = os.getenv("LLM_MODEL", "claude-sonnet-4-20250514")
LLM_MODEL = os.getenv("LLM_MODEL", "claude-sonnet-4-20250514")

# ─── Optional: Tavily for web search enrichment ──────────────────────────────
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")

# ─── Paths ────────────────────────────────────────────────────────────────────
DATA_DIR = _project_root / "data"
REPORTS_DIR = _project_root / "reports"
DATA_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# ─── Free OSINT Feed URLs (no API keys required) ─────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
GITHUB_ADVISORIES_API = "https://api.github.com/advisories"

# ─── RSS Feeds for Security News ──────────────────────────────────────────────
SECURITY_RSS_FEEDS = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "CISA Alerts", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
    {"name": "US-CERT", "url": "https://www.us-cert.gov/ncas/current-activity.xml"},
]

# ─── Agent Settings ───────────────────────────────────────────────────────────
# How many days back to look for CVEs on each run
CVE_LOOKBACK_DAYS = int(os.getenv("CVE_LOOKBACK_DAYS", "3"))

# Maximum CVEs to process per run (NVD rate-limits to ~5 req/30s without key)
MAX_CVES_PER_RUN = int(os.getenv("MAX_CVES_PER_RUN", "50"))

# Minimum CVSS score to include in analysis (0.0 - 10.0)
MIN_CVSS_SCORE = float(os.getenv("MIN_CVSS_SCORE", "5.0"))

# ─── Email (Optional) ────────────────────────────────────────────────────────
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
EMAIL_TO = os.getenv("EMAIL_TO", "")

# ─── Target Deployment Host ────────────────────────────────────────────────────
# DigitalOcean droplet — nginx on port 80 serves an existing app.
# ⚠️  SAFETY: This agent is READ-ONLY. It must NEVER modify, restart, or
#    interfere with nginx or any service on port 80.
DEPLOY_HOST = os.getenv("DEPLOY_HOST", "143.198.110.70")

# ─── Local Activity Monitoring ────────────────────────────────────────────────
# Enabled by default for this droplet — nginx is actively serving traffic.
LOCAL_MONITORING_ENABLED = os.getenv("LOCAL_MONITORING_ENABLED", "true").lower() == "true"
LOG_PATHS = [
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/kern.log",
    "/var/log/nginx/access.log",   # ← Active: existing app on port 80
    "/var/log/nginx/error.log",    # ← Active: existing app on port 80
]
# Apache logs omitted — this droplet uses nginx only
# Only monitor logs that actually exist on this system
ACTIVE_LOG_PATHS = [p for p in LOG_PATHS if Path(p).exists()]

# ─── Safety: Services the agent must NEVER touch ──────────────────────────────
# These are off-limits for any remediation actions. The reporter will flag
# vulnerabilities but will NOT suggest restarting or modifying these.
PROTECTED_SERVICES = [
    "nginx",       # Existing app on port 80 — do not touch
]
PROTECTED_PORTS = [
    80,            # nginx — existing app
    443,           # HTTPS if configured
]
