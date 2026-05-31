"""Tests for tools/harvester.py"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from tools.harvester import HarvesterAdapter
from config import Config


@pytest.fixture
def adapter():
    return HarvesterAdapter()


# ═══════════ parse_line ═══════════

class TestParseLine:
    def test_email_section_detected(self, adapter):
        ctx = {}
        result = adapter.parse_line("[*] Emails found: 5", ctx)
        assert result == []
        assert ctx["section"] == "emails"

    def test_email_section_regex_variant(self, adapter):
        ctx = {}
        adapter.parse_line("[*] Email found:", ctx)
        assert ctx["section"] == "emails"

    def test_host_section_detected(self, adapter):
        ctx = {}
        adapter.parse_line("[*] Hosts found:", ctx)
        assert ctx["section"] == "hosts"

    def test_ip_section_detected(self, adapter):
        ctx = {}
        adapter.parse_line("[*] IPs found:", ctx)
        assert ctx["section"] == "hosts"

    def test_valid_email_extracted(self, adapter):
        ctx = {"section": "emails"}
        result = adapter.parse_line("admin@example.com", ctx)
        assert len(result) == 1
        assert result[0]["value"] == "admin@example.com"
        assert result[0]["type"] == "email"
        assert result[0]["source"] == "theHarvester"

    def test_ignored_email_filtered(self, adapter):
        ctx = {"section": "emails"}
        result = adapter.parse_line("cmartorella@edge-security.com", ctx)
        assert len(result) == 0

    def test_subdomain_extracted(self, adapter):
        ctx = {"section": "hosts"}
        # Hosts are buffered during streaming, then emitted by finalize()
        adapter.parse_line("mail.example.com:93.184.216.34", ctx)
        result = adapter.finalize(ctx)
        assert len(result) == 1
        assert result[0]["value"] == "mail.example.com"
        assert result[0]["type"] == "subdomain"
        assert "93.184.216.34" in result[0]["extra"]

    def test_subdomain_without_ip(self, adapter):
        ctx = {"section": "hosts"}
        adapter.parse_line("cdn.example.com", ctx)
        result = adapter.finalize(ctx)
        assert len(result) == 1
        assert result[0]["value"] == "cdn.example.com"

    def test_subdomain_ip_aggregation(self, adapter):
        """Same host with multiple IPs collapses to one result, IPs aggregated."""
        ctx = {"section": "hosts"}
        adapter.parse_line("asac.example.com:1.1.1.1", ctx)
        adapter.parse_line("asac.example.com:2.2.2.2", ctx)
        adapter.parse_line("asac.example.com:3.3.3.3", ctx)
        result = adapter.finalize(ctx)
        assert len(result) == 1
        assert result[0]["value"] == "asac.example.com"
        for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
            assert ip in result[0]["extra"]

    def test_bare_ip_classified_as_ip(self, adapter):
        """A bare IP with no hostname is type 'ip', not 'subdomain'."""
        ctx = {"section": "hosts"}
        adapter.parse_line("8.8.8.8", ctx)
        adapter.parse_line("real.example.com:9.9.9.9", ctx)
        results = adapter.finalize(ctx)
        by_val = {r["value"]: r for r in results}
        assert by_val["8.8.8.8"]["type"] == "ip"
        assert by_val["real.example.com"]["type"] == "subdomain"

    def test_empty_line(self, adapter):
        ctx = {}
        assert adapter.parse_line("", ctx) == []

    def test_blank_line(self, adapter):
        ctx = {}
        assert adapter.parse_line("   ", ctx) == []

    def test_warning_line(self, adapter):
        ctx = {}
        result = adapter.parse_line("[!] Warning: Something bad", ctx)
        assert result == []
        assert ctx.get("_log") is not None
        assert ctx["_log"][0] == "warn"

    def test_info_line_resets_section(self, adapter):
        ctx = {"section": "emails"}
        adapter.parse_line("[*] Something else:", ctx)
        assert ctx["section"] is None

    def test_email_in_random_line(self, adapter):
        """Emails found outside email section should still be caught"""
        ctx = {"section": None}
        result = adapter.parse_line("Found: user@domain.org in results", ctx)
        assert len(result) == 1
        assert result[0]["value"] == "user@domain.org"

    def test_confidence_returned(self, adapter):
        ctx = {"section": "emails"}
        result = adapter.parse_line("test@valid.com", ctx)
        assert result[0]["confidence"] > 0


# ═══════════ build_command ═══════════

class TestBuildCommand:
    def test_source_all(self, adapter):
        cmd = adapter.build_command("example.com", source="all")
        assert cmd[0] == "theHarvester"
        assert "-d" in cmd
        assert "example.com" in cmd
        # All free sources joined
        sources_arg = cmd[cmd.index("-b") + 1]
        for src in Config.FREE_SOURCES[:3]:
            assert src in sources_arg

    def test_specific_source(self, adapter):
        cmd = adapter.build_command("example.com", source="crtsh")
        assert "crtsh" in cmd

    def test_limit_passed(self, adapter):
        cmd = adapter.build_command("example.com", limit="100")
        assert "-l" in cmd
        assert "100" in cmd

    def test_tor_prepends_proxychains(self, adapter):
        cmd = adapter.build_command("example.com", tor=True)
        assert cmd[0] == "proxychains4"
        assert cmd[1] == "-q"
        assert "theHarvester" in cmd

    def test_tor_false_no_proxychains(self, adapter):
        cmd = adapter.build_command("example.com", tor=False)
        assert cmd[0] == "theHarvester"


# ═══════════ should_ignore ═══════════

class TestShouldIgnore:
    def test_ignored_emails(self, adapter):
        for email in Config.IGNORE_EMAILS:
            assert adapter.should_ignore(email) is True

    def test_normal_email_not_ignored(self, adapter):
        assert adapter.should_ignore("admin@example.com") is False
