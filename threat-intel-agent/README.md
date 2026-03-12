# Threat Intelligence Analyst Agent

A **LangChain Deep Agents** application that monitors free OSINT threat intelligence feeds, analyzes vulnerabilities against your Ubuntu server's actual software inventory, and produces actionable daily security briefings.

## What It Does

```
┌──────────────────────────────────────────────────────────┐
│                  Orchestrator Agent                       │
│                                                          │
│  ┌────────────┐  ┌─────────────┐  ┌────────────────┐    │
│  │  Collector  │→ │  Analyzer   │→ │   Reporter     │    │
│  │  (6 feeds)  │  │ (CVE↔local) │  │ (briefing.md)  │    │
│  └────────────┘  └─────────────┘  └────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

1. **Collector Subagent** — Fetches threat data from 7 free OSINT sources
2. **Analyzer Subagent** — Scans your system and cross-references for relevance
3. **Reporter Subagent** — Generates a polished, actionable security briefing

### Data Sources (All Free, No API Keys Required)

| Source | What It Provides |
|--------|-----------------|
| NVD (NIST) | Latest CVEs with CVSS scores |
| CISA KEV | Actively exploited vulnerabilities |
| EPSS (FIRST.org) | Exploit probability scores (0-1) |
| GitHub Advisories | Package-level security advisories |
| ThreatFox (abuse.ch) | Indicators of Compromise (IOCs) |
| Security RSS | News from BleepingComputer, Hacker News, CISA |

### Optional: Local Activity Monitoring

For servers with active services, enable `LOCAL_MONITORING_ENABLED=true` to also scan:
- SSH brute force / invalid user attempts
- Failed sudo / privilege escalation
- Kernel segfaults (potential exploits)
- Suspicious web requests (scanner probes)
- OOM kills, disk errors, service failures

## Quick Start

### 1. Clone & Configure

```bash
cd /opt
git clone <this-repo> threat-intel-agent
cd threat-intel-agent

# Set up environment
cp .env.example .env
nano .env  # Add your LLM API key (Anthropic or OpenAI)
```

### 2. Install Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Run

```bash
# MVP mode — single agent, quick test (~2 min, minimal tokens)
python main.py --mvp

# Full pipeline — orchestrator + 3 subagents (~5-10 min)
python main.py

# Individual stages for debugging
python main.py --stage collect
python main.py --stage analyze
python main.py --stage report
```

### 4. Read Your Briefing

Reports are saved to `reports/briefing_YYYYMMDD.md`

## Production Deployment (Ubuntu)

```bash
# One-command deploy with systemd timer
chmod +x deploy/deploy.sh
sudo ./deploy/deploy.sh

# Then edit your API keys
sudo nano /opt/threat-intel-agent/.env

# Test it
sudo -u threat-intel /opt/threat-intel-agent/venv/bin/python /opt/threat-intel-agent/main.py --mvp

# Enable the daily timer (runs at 6:00 AM UTC)
sudo systemctl start threat-intel-agent.timer
sudo systemctl status threat-intel-agent.timer
```

### Enable Local Log Monitoring (Active Servers)

```bash
# In .env:
LOCAL_MONITORING_ENABLED=true

# Grant the service user read access to logs:
sudo usermod -aG adm threat-intel
```

## Project Structure

```
threat-intel-agent/
├── main.py                      # Entry point (full, MVP, or single-stage)
├── config.py                    # Configuration & environment loading
├── requirements.txt             # Python dependencies
├── .env.example                 # Template for API keys & settings
├── agents/
│   ├── orchestrator.py          # Top-level planner & coordinator
│   ├── collector.py             # OSINT feed collection subagent
│   ├── analyzer.py              # Threat-to-system cross-reference subagent
│   └── reporter.py              # Briefing generation subagent
├── tools/
│   ├── fetch_nvd.py             # NVD CVE feed tool
│   ├── fetch_cisa_kev.py        # CISA KEV catalog tool
│   ├── fetch_epss.py            # EPSS exploit scoring tool
│   ├── fetch_github_advisories.py # GitHub Advisory DB tool
│   ├── fetch_threatfox.py       # abuse.ch IOC feed tool
│   ├── fetch_rss_feeds.py       # Security news RSS parser
│   ├── scan_local_system.py     # Local package/port/service scanner
│   └── monitor_logs.py          # Local log activity monitor (optional)
├── deploy/
│   ├── deploy.sh                # Ubuntu deployment script
│   ├── threat-intel-agent.service # systemd service unit
│   └── threat-intel-agent.timer   # systemd daily timer
├── data/                        # Collected threat data (gitignored)
├── reports/                     # Generated briefings (gitignored)
└── tests/                       # Test suite
```

## How It Works

### Priority Scoring Formula

Each CVE relevant to your system gets a composite priority score:

```
priority = CVSS + (EPSS × 5) + KEV_bonus + exposure_bonus
```

| Component | Range | Description |
|-----------|-------|-------------|
| CVSS | 0-10 | Base severity score |
| EPSS × 5 | 0-5 | Exploit probability weight |
| KEV bonus | +3 | On CISA actively-exploited list |
| Exposure | +2 | Service listening on 0.0.0.0 |

**Priority levels:** ≥15 CRITICAL · ≥10 HIGH · ≥5 MEDIUM · <5 LOW

### Example Briefing Output

```markdown
# 🔒 Daily Threat Intelligence Briefing
**Date:** 2026-03-11 | **System:** prod-web-01

## Executive Summary
Collected 47 CVEs from NVD, 3 from CISA KEV. 5 are relevant to this system.
1 CRITICAL action required: OpenSSH vulnerability actively exploited in the wild.

## 🔴 Critical Actions Required
- **CVE-2026-XXXX** | OpenSSH 9.6 | Priority: 17.2
  → `sudo apt update && sudo apt upgrade openssh-server`
  → `sudo systemctl restart sshd`
```

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_PROVIDER` | `anthropic` | LLM provider (`anthropic` or `openai`) |
| `LLM_MODEL` | `claude-sonnet-4-20250514` | Model to use |
| `CVE_LOOKBACK_DAYS` | `3` | Days of CVE history to fetch |
| `MAX_CVES_PER_RUN` | `50` | Max CVEs per NVD query |
| `MIN_CVSS_SCORE` | `5.0` | Minimum CVSS to include |
| `LOCAL_MONITORING_ENABLED` | `false` | Enable local log scanning |
| `EMAIL_ENABLED` | `false` | Email daily briefings |

## License

MIT
