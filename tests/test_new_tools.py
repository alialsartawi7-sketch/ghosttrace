"""Tests for DNS, SSL, Dorks, Whois, Phone, Differ modules"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from unittest.mock import patch


# ═══════════ DNS Records ═══════════

class TestDNSRecords:
    @pytest.fixture
    def adapter(self):
        from tools.dns_records import DNSRecordsAdapter
        return DNSRecordsAdapter()

    def test_build_command(self, adapter):
        cmd = adapter.build_command("example.com")
        assert cmd[0] == "dig"
        assert "example.com" in cmd

    def test_parse_mx_record(self, adapter):
        ctx = {}
        result = adapter.parse_line(
            "example.com.\t\t300\tIN\tMX\t10 mail.example.com.", ctx)
        assert len(result) == 1
        assert result[0]["type"] == "dns"
        assert result[0]["extra"] == "MX"
        assert result[0]["confidence"] == 0.95

    def test_parse_txt_spf(self, adapter):
        ctx = {}
        result = adapter.parse_line(
            'example.com.\t\t300\tIN\tTXT\t"v=spf1 include:_spf.google.com ~all"', ctx)
        assert len(result) == 1
        assert result[0]["extra"] == "TXT"

    def test_parse_ignores_comments(self, adapter):
        ctx = {}
        result = adapter.parse_line("; this is a comment", ctx)
        assert result == []

    def test_parse_ignores_empty(self, adapter):
        ctx = {}
        assert adapter.parse_line("", ctx) == []


# ═══════════ SSL Cert ═══════════

class TestSSLCert:
    @pytest.fixture
    def adapter(self):
        from tools.ssl_cert import SSLCertAdapter
        return SSLCertAdapter()

    def test_build_command(self, adapter):
        cmd = adapter.build_command("example.com")
        assert cmd[0] == "openssl"
        assert "s_client" in cmd

    def test_build_command_custom_port(self, adapter):
        cmd = adapter.build_command("example.com", port="8443")
        assert "example.com:8443" in cmd

    def test_parse_line_returns_empty(self, adapter):
        """parse_cert is the entry point, not parse_line"""
        result = adapter.parse_line("any line", {})
        assert result == []


# ═══════════ Google Dorks ═══════════

class TestGoogleDorks:
    @pytest.fixture
    def adapter(self):
        from tools.google_dorks import GoogleDorksAdapter
        return GoogleDorksAdapter()

    def test_generate_returns_queries(self, adapter):
        dorks = adapter.generate("example.com")
        assert len(dorks) > 20  # Should have ~28 dorks

    def test_generate_substitutes_target(self, adapter):
        dorks = adapter.generate("test.com")
        for d in dorks:
            assert "test.com" in d["value"]
            assert "{target}" not in d["value"]

    def test_generate_has_categories(self, adapter):
        dorks = adapter.generate("example.com")
        cats = set(d.get("extra", "").split(":")[0] for d in dorks)
        assert "Sensitive Files" in cats
        assert "Admin & Login Pages" in cats

    def test_generate_includes_url(self, adapter):
        dorks = adapter.generate("example.com")
        for d in dorks:
            assert d.get("url", "").startswith("https://www.google.com/search")


# ═══════════ Whois ═══════════

class TestWhois:
    @pytest.fixture
    def adapter(self):
        from tools.whois_tool import WhoisAdapter
        return WhoisAdapter()

    def test_build_command(self, adapter):
        cmd = adapter.build_command("example.com")
        assert cmd == ["whois", "example.com"]

    def test_parse_registrar(self, adapter):
        ctx = {}
        result = adapter.parse_line("Registrar: GoDaddy.com, LLC", ctx)
        assert len(result) == 1
        assert "Registrar" in result[0]["value"]
        assert result[0]["extra"] == "Registrar"

    def test_parse_dedups(self, adapter):
        ctx = {}
        adapter.parse_line("Registrar: GoDaddy", ctx)
        result = adapter.parse_line("Registrar: GoDaddy", ctx)  # Same again
        assert len(result) == 0  # Deduped

    def test_parse_ignores_comments(self, adapter):
        ctx = {}
        assert adapter.parse_line("% This is a comment", ctx) == []
        assert adapter.parse_line("# Another comment", ctx) == []


# ═══════════ PhoneInfoga ═══════════

class TestPhoneInfoga:
    @pytest.fixture
    def adapter(self):
        from tools.phoneinfoga_tool import PhoneInfogaAdapter
        return PhoneInfogaAdapter()

    def test_build_command(self, adapter):
        cmd = adapter.build_command("+1234567890")
        assert cmd == ["phoneinfoga", "scan", "-n", "+1234567890"]

    def test_parse_carrier(self, adapter):
        ctx = {}
        result = adapter.parse_line("Carrier: Vodafone", ctx)
        # Should extract carrier
        assert any("Carrier" in r["value"] for r in result)

    def test_parse_empty(self, adapter):
        ctx = {}
        assert adapter.parse_line("", ctx) == []


# ═══════════ Differ ═══════════

class TestDiffer:
    @patch("core.differ.ResultDB.get_by_scan")
    @patch("core.differ.ScanDB.get")
    def test_diff_detects_added(self, mock_scan, mock_results):
        from core.differ import diff_scans
        mock_scan.return_value = {"id": "x", "target": "test.com"}
        mock_results.side_effect = [
            {"items": [{"value": "a@test.com", "type": "email"}]},  # old
            {"items": [{"value": "a@test.com", "type": "email"},
                      {"value": "b@test.com", "type": "email"}]},  # new
        ]
        result = diff_scans("old_id", "new_id")
        assert result["summary"]["added"] == 1
        assert result["summary"]["removed"] == 0
        assert result["summary"]["common"] == 1

    @patch("core.differ.ResultDB.get_by_scan")
    @patch("core.differ.ScanDB.get")
    def test_diff_detects_removed(self, mock_scan, mock_results):
        from core.differ import diff_scans
        mock_scan.return_value = {"id": "x"}
        mock_results.side_effect = [
            {"items": [{"value": "a@test.com", "type": "email"},
                      {"value": "b@test.com", "type": "email"}]},
            {"items": [{"value": "a@test.com", "type": "email"}]},
        ]
        result = diff_scans("old_id", "new_id")
        assert result["summary"]["removed"] == 1
        assert result["summary"]["added"] == 0
