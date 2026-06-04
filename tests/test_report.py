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


class TestSensitiveSubdomainMatching:
    """Two-tier subdomain flagging: STRONG keywords match as substring (don't
    miss admin panels), NOISY keywords match only as an exact label (no
    false positives). Generic rules — no target-specific examples."""

    def _flag(self, *names):
        cats = {"subdomain": [{"value": n, "type": "subdomain",
                               "source": "theHarvester", "confidence": 0.7}
                              for n in names]}
        hits = ReportGenerator._analyze_osint(cats)["sensitive_subs"]
        return {h for h, _ in hits}

    # STRONG → substring: real admin variants must NOT be missed
    def test_admin_substring_variants_caught(self):
        flagged = self._flag("adminsci.eps.zu.edu.eg", "facadmin.zu.edu.eg",
                             "zuadmin1.zu.edu.eg", "adminmilitaryeducation.zu.edu.eg")
        assert flagged == {"adminsci.eps.zu.edu.eg", "facadmin.zu.edu.eg",
                           "zuadmin1.zu.edu.eg", "adminmilitaryeducation.zu.edu.eg"}

    def test_vpn_internal_substring_caught(self):
        assert self._flag("vpngateway.example.com") == {"vpngateway.example.com"}
        assert self._flag("internal-api.example.com") == {"internal-api.example.com"}

    # NOISY → exact label only: avoid false positives
    def test_noisy_substring_not_flagged(self):
        # "dr" inside "studreg", "test" inside "latest", "db" inside "database"
        assert self._flag("hostelstudreg.zu.edu.eg") == set()
        assert self._flag("latest.example.com") == set()
        assert self._flag("database-info.example.com") == set()

    def test_noisy_exact_label_flagged(self):
        assert self._flag("staging.example.com") == {"staging.example.com"}
        assert self._flag("dev.example.com") == {"dev.example.com"}
        assert self._flag("test.example.com") == {"test.example.com"}

    def test_clean_subdomains_not_flagged(self):
        assert self._flag("arts.zu.edu.eg", "library.zu.edu.eg",
                          "moodle.zu.edu.eg") == set()


class TestAccessAndEmailSignals:
    """Capture-expansion: remote-access subdomains + admin-hosted emails."""

    def _subs(self, *names):
        cats = {"subdomain": [{"value": n, "type": "subdomain",
                               "source": "x", "confidence": 0.7} for n in names]}
        return {h for h, _ in ReportGenerator._analyze_osint(cats)["sensitive_subs"]}

    def _emails(self, *vals):
        cats = {"email": [{"value": v, "type": "email",
                           "source": "x", "confidence": 0.8} for v in vals]}
        return ReportGenerator._analyze_osint(cats)["admin_emails"]

    # access points (exact-label) are now caught
    def test_access_points_caught(self):
        assert self._subs("portal.example.com") == {"portal.example.com"}
        assert self._subs("remote.example.com") == {"remote.example.com"}
        assert self._subs("owa.example.com") == {"owa.example.com"}
        assert self._subs("sso.example.com") == {"sso.example.com"}

    # citrix is distinctive → substring
    def test_citrix_substring(self):
        assert self._subs("citrixgw.example.com") == {"citrixgw.example.com"}

    # "remote" must NOT fire as a substring (university noise like remote-learning)
    def test_remote_not_substring(self):
        assert self._subs("remotelearning.example.com") == set()
        assert self._subs("lesson.example.com") == set()  # "sso" is substring of "lesson", not a label

    # admin-hosted emails
    def test_admin_email_flagged(self):
        assert self._emails("isa@admin.example.com") == ["isa@admin.example.com"]
        assert self._emails("ceo@internal.example.com") == ["ceo@internal.example.com"]

    def test_normal_email_not_flagged(self):
        assert self._emails("info@example.com", "hr@example.com") == []
