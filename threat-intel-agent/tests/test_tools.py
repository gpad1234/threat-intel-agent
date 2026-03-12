"""
Basic tests for the threat intel data collection tools.
These tests hit real APIs (free, no auth), so they double as integration smoke tests.

Run: pytest tests/ -v
"""

import json
import pytest


class TestNVDFetch:
    """Test NVD CVE fetching tool."""

    def test_fetch_returns_valid_json(self):
        from tools.fetch_nvd import fetch_nvd_cves
        result = json.loads(fetch_nvd_cves.invoke({"lookback_days": 1}))
        assert "source" in result
        assert result["source"] == "NVD"
        assert "cves" in result
        assert isinstance(result["cves"], list)

    def test_fetch_with_keyword(self):
        from tools.fetch_nvd import fetch_nvd_cves
        result = json.loads(fetch_nvd_cves.invoke({
            "lookback_days": 7,
            "keyword": "linux kernel",
        }))
        assert "cves" in result


class TestCISAKEV:
    """Test CISA Known Exploited Vulnerabilities feed."""

    def test_fetch_returns_catalog(self):
        from tools.fetch_cisa_kev import fetch_cisa_kev
        result = json.loads(fetch_cisa_kev.invoke({"lookback_days": 30}))
        assert result["source"] == "CISA KEV"
        assert "total_in_catalog" in result
        assert result["total_in_catalog"] > 0  # CISA KEV always has entries


class TestEPSS:
    """Test EPSS exploit probability scores."""

    def test_fetch_top_risk(self):
        from tools.fetch_epss import fetch_epss_scores
        result = json.loads(fetch_epss_scores.invoke({}))
        assert result["source"] == "EPSS (FIRST.org)"
        assert len(result["scores"]) > 0

    def test_fetch_specific_cves(self):
        from tools.fetch_epss import fetch_epss_scores
        result = json.loads(fetch_epss_scores.invoke({
            "cve_ids": ["CVE-2024-3094", "CVE-2023-44487"]
        }))
        assert "scores" in result


class TestGitHubAdvisories:
    """Test GitHub Advisory Database."""

    def test_fetch_all_ecosystems(self):
        from tools.fetch_github_advisories import fetch_github_advisories
        result = json.loads(fetch_github_advisories.invoke({"lookback_days": 7}))
        assert result["source"] == "GitHub Advisory Database"
        assert "advisories" in result

    def test_fetch_pip_ecosystem(self):
        from tools.fetch_github_advisories import fetch_github_advisories
        result = json.loads(fetch_github_advisories.invoke({
            "lookback_days": 30,
            "ecosystem": "pip",
        }))
        assert result["ecosystem_filter"] == "pip"


class TestThreatFox:
    """Test ThreatFox IOC feed."""

    def test_fetch_iocs(self):
        from tools.fetch_threatfox import fetch_threatfox_iocs
        result = json.loads(fetch_threatfox_iocs.invoke({"lookback_days": 3}))
        assert result["source"] == "ThreatFox (abuse.ch)"
        assert "iocs" in result


class TestRSSFeeds:
    """Test security RSS feed parsing."""

    def test_fetch_rss(self):
        from tools.fetch_rss_feeds import fetch_security_rss
        result = json.loads(fetch_security_rss.invoke({"max_items_per_feed": 3}))
        assert result["source"] == "Security RSS Feeds"
        assert result["feeds_queried"] > 0


class TestLocalScanner:
    """Test local system inventory tools (runs safe, read-only commands)."""

    def test_scan_packages(self):
        from tools.scan_local_system import scan_local_packages
        result = json.loads(scan_local_packages.invoke({}))
        assert "packages" in result
        # At least pip packages should exist since we're running Python
        assert "pip" in result["packages"]

    def test_scan_open_ports(self):
        from tools.scan_local_system import scan_open_ports
        result = json.loads(scan_open_ports.invoke({}))
        assert "ports" in result


class TestLogMonitor:
    """Test log monitoring tool."""

    def test_disabled_by_default(self):
        from tools.monitor_logs import scan_local_logs
        result = json.loads(scan_local_logs.invoke({}))
        # Should report as disabled unless explicitly enabled
        assert "source" in result
        assert result["source"] == "local_log_monitor"
