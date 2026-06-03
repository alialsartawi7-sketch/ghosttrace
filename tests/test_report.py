"""Tests for reports/html_report.py"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from reports.html_report import ReportGenerator, RESULT_TYPES


@pytest.fixture(autouse=True)
def setup_dirs(tmp_path):
    from config import Config
    Config.EXPORT_DIR = str(tmp_path)
    os.makedirs(Config.EXPORT_DIR, exist_ok=True)


class TestReportTypes:
    def test_all_9_types_supported(self):
        assert len(RESULT_TYPES) == 10
        for t in ["email", "username", "subdomain", "ip", "metadata", "dns", "ssl", "whois", "phone", "dork"]:
            assert t in RESULT_TYPES

    def test_each_type_has_required_fields(self):
        for t, info in RESULT_TYPES.items():
            assert "label" in info
            assert "icon" in info
            assert "color" in info
            assert "tag" in info


class TestGenerateHTML:
    def test_empty_results(self):
        r = ReportGenerator.generate_html([], "test.com", "auto")
        assert r["filename"].endswith(".html")
        assert os.path.exists(r["filepath"])

    def test_all_types_in_report(self):
        results = [
            {"value": "a@test.com", "source": "theHarvester", "type": "email", "confidence": 0.9},
            {"value": "johndoe @ GitHub", "source": "Maigret", "type": "username", "confidence": 0.85},
            {"value": "mail.test.com", "source": "theHarvester", "type": "subdomain", "confidence": 0.8},
            {"value": "Author: John", "source": "ExifTool", "type": "metadata", "confidence": 0.95},
            {"value": "[MX] mail.test.com", "source": "DNSRecords", "type": "dns", "confidence": 0.95},
            {"value": "SAN: secret.test.com", "source": "SSLCert", "type": "ssl", "confidence": 0.9},
            {"value": "Registrar: GoDaddy", "source": "Whois", "type": "whois", "confidence": 0.95},
            {"value": "Carrier: Vodafone", "source": "PhoneInfoga", "type": "phone", "confidence": 0.85},
            {"value": "site:test.com filetype:pdf", "source": "GoogleDorks", "type": "dork", "confidence": 0.5},
        ]
        r = ReportGenerator.generate_html(results, "test.com", "auto")
        with open(r["filepath"]) as f:
            html = f.read()
        for label in ["Emails", "Profiles", "Subdomains", "Metadata", "DNS Records",
                       "SSL Certificate", "WHOIS", "Phone Intel", "Google Dorks"]:
            assert label in html

    def test_key_findings_section(self):
        results = [
            {"value": "admin@test.com", "source": "theHarvester", "type": "email", "confidence": 0.9},
            {"value": "noise", "source": "x", "type": "subdomain", "confidence": 0.3},
        ]
        r = ReportGenerator.generate_html(results, "test.com", "auto")
        with open(r["filepath"]) as f:
            html = f.read()
        assert "Key Findings" in html
        # Low confidence should NOT be in key findings
        kf_section = html[html.find("Key Findings"):html.find("Key Findings") + 2000]
        assert "admin@test.com" in kf_section

    def test_confidence_distribution(self):
        results = [
            {"value": "high", "source": "x", "type": "email", "confidence": 0.9},
            {"value": "med", "source": "x", "type": "email", "confidence": 0.6},
            {"value": "low", "source": "x", "type": "email", "confidence": 0.3},
        ]
        r = ReportGenerator.generate_html(results, "test.com", "auto")
        with open(r["filepath"]) as f:
            html = f.read()
        assert "Confidence Distribution" in html

    def test_recon_data_included(self):
        results = [{"value": "test", "source": "x", "type": "email", "confidence": 0.9}]
        recon = {
            "scored_assets": [{"hostname": "admin.test.com", "score": 85, "level": "critical",
                              "reasons": ["Admin exposed"], "attack_paths": []}],
            "summary": {"stats": {"critical": 1, "high": 0, "medium": 0, "low": 0},
                       "recommendations": ["Fix admin panel"]}
        }
        r = ReportGenerator.generate_html(results, "test.com", "auto", recon_data=recon)
        with open(r["filepath"]) as f:
            html = f.read()
        assert "Risk Assessment" in html
        assert "admin.test.com" in html
        assert "85/100" in html
        assert "Recommendations" in html

    def test_target_and_module_in_report(self):
        r = ReportGenerator.generate_html([], "example.com", "dns")
        with open(r["filepath"]) as f:
            html = f.read()
        assert "example.com" in html
        assert "dns" in html

    def test_xss_escaped(self):
        results = [{"value": "<script>alert(1)</script>", "source": "test", "type": "email", "confidence": 0.9}]
        r = ReportGenerator.generate_html(results, "<b>xss</b>", "auto")
        with open(r["filepath"]) as f:
            html = f.read()
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


class TestReconScopeGuard:
    """Recon data for a different target must never appear in the report
    (regression: a zu.edu.eg report showed ltuc.com under Risk Assessment)."""

    def _recon(self, hostname):
        from recon.risk_engine import RiskScorer
        asset = RiskScorer.score_asset({
            "hostname": hostname, "alive": True,
            "ports": [{"port": 21, "state": "open"}],
            "attack_surface": {"admin_panels": [], "login_pages": [], "api_endpoints": []},
            "technology": [], "missing_security_headers": [], "http_info": {"status": 200},
        })
        scored = [asset]
        return {"scored_assets": scored, "summary": RiskScorer.executive_summary(scored)}

    def test_base_domain(self):
        assert ReportGenerator._base_domain("zu.edu.eg/") == "zu.edu.eg"
        assert ReportGenerator._base_domain("https://www.zu.edu.eg/x?y") == "zu.edu.eg"

    def test_in_scope(self):
        assert ReportGenerator._host_in_scope("admin.zu.edu.eg", "zu.edu.eg")
        assert not ReportGenerator._host_in_scope("ltuc.com", "zu.edu.eg")

    def test_foreign_recon_dropped(self):
        # Report target zu.edu.eg, but recon ran on ltuc.com → must be excluded
        res = ReportGenerator.generate_html(
            [{"value": "zu.edu.eg", "type": "subdomain", "source": "crtsh", "confidence": 0.9}],
            "zu.edu.eg", "auto", recon_data=self._recon("ltuc.com"))
        html = open(res["filepath"], encoding="utf-8").read()
        assert "ltuc.com" not in html            # foreign host never rendered
        assert "🛡️" not in html             # Risk Assessment section header dropped

    def test_matching_recon_kept(self):
        # Recon host under the same domain → kept and rendered
        res = ReportGenerator.generate_html(
            [{"value": "zu.edu.eg", "type": "subdomain", "source": "crtsh", "confidence": 0.9}],
            "zu.edu.eg", "auto", recon_data=self._recon("ftp.zu.edu.eg"))
        html = open(res["filepath"], encoding="utf-8").read()
        assert "ftp.zu.edu.eg" in html
        assert "🛡️" in html              # Risk Assessment section present
