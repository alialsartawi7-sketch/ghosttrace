"""Tests for recon/risk_engine.py"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from recon.risk_engine import RiskScorer, RiskLevel, AttackPathGenerator


def _make_asset(**overrides):
    """Helper to build a test asset dict"""
    base = {
        "hostname": "test.example.com",
        "alive": True,
        "ports": [],
        "attack_surface": {"admin_panels": [], "login_pages": [], "api_endpoints": []},
        "technology": [],
        "missing_security_headers": [],
        "http_info": {"status": 200},
    }
    base.update(overrides)
    return base


# ═══════════ RiskLevel ═══════════

class TestRiskLevel:
    @pytest.mark.parametrize("score,expected", [
        (90, "critical"), (85, "critical"),
        (70, "high"), (65, "high"),
        (50, "medium"), (40, "medium"),
        (25, "low"), (20, "low"),
        (10, "info"), (0, "info"),
    ])
    def test_from_score(self, score, expected):
        assert RiskLevel.from_score(score) == expected


# ═══════════ RiskScorer ═══════════

class TestRiskScorer:
    def test_dead_host_zero(self):
        asset = _make_asset(alive=False)
        result = RiskScorer.score_asset(asset)
        assert result["score"] == 0
        assert result["level"] == "info"

    def test_alive_base_score(self):
        asset = _make_asset()
        result = RiskScorer.score_asset(asset)
        assert result["score"] >= 10  # alive = +10

    def test_admin_panel_adds_20(self):
        asset = _make_asset(attack_surface={
            "admin_panels": [{"path": "/admin", "status": 200}],
            "login_pages": [], "api_endpoints": []
        })
        result = RiskScorer.score_asset(asset)
        assert result["score"] >= 30  # 10 alive + 20 admin
        assert any("Admin panel" in r for r in result["reasons"])

    def test_rdp_adds_25(self):
        asset = _make_asset(ports=[{"port": 3389, "state": "open", "service": "RDP"}])
        result = RiskScorer.score_asset(asset)
        assert result["score"] >= 35  # 10 alive + 25 RDP
        assert any("RDP" in r for r in result["reasons"])

    def test_score_capped_at_100(self):
        asset = _make_asset(
            ports=[
                {"port": 23, "state": "open"}, {"port": 3389, "state": "open"},
                {"port": 6379, "state": "open"}, {"port": 27017, "state": "open"},
            ],
            attack_surface={
                "admin_panels": [{"path": "/admin", "status": 200}],
                "login_pages": [{"path": "/login", "status": 200}],
                "api_endpoints": [{"path": "/api", "status": 200}]
            },
            technology=["WordPress", "PHP"],
            missing_security_headers=["strict-transport-security", "content-security-policy", "x-frame-options"],
            hostname="staging.admin.dev.example.com"
        )
        result = RiskScorer.score_asset(asset)
        assert result["score"] == 100

    def test_staging_subdomain_adds_points(self):
        asset = _make_asset(hostname="staging.example.com")
        result = RiskScorer.score_asset(asset)
        assert any("Staging" in r for r in result["reasons"])

    def test_missing_hsts_adds_points(self):
        asset = _make_asset(missing_security_headers=["strict-transport-security"])
        result = RiskScorer.score_asset(asset)
        assert any("HSTS" in r for r in result["reasons"])

    def test_attack_paths_included(self):
        asset = _make_asset(attack_surface={
            "admin_panels": [{"path": "/admin", "status": 200}],
            "login_pages": [], "api_endpoints": []
        })
        result = RiskScorer.score_asset(asset)
        assert "attack_paths" in result


# ═══════════ AttackPathGenerator ═══════════

class TestAttackPathGenerator:
    def test_empty_asset_no_paths(self):
        asset = _make_asset()
        scored = {"score": 10, "level": "info", "reasons": []}
        paths = AttackPathGenerator.generate(asset, scored)
        assert paths == []

    def test_rule1_brute_force(self):
        asset = _make_asset(
            ports=[{"port": 22, "state": "open"}],
            attack_surface={"admin_panels": [], "api_endpoints": [],
                           "login_pages": [{"path": "/login", "status": 200}]}
        )
        scored = {"score": 30, "level": "low", "reasons": ["SSH"]}
        paths = AttackPathGenerator.generate(asset, scored)
        names = [p["path"] for p in paths]
        assert "Brute Force Candidate" in names

    def test_rule2_admin_panel(self):
        asset = _make_asset(attack_surface={
            "admin_panels": [{"path": "/admin", "status": 200}],
            "login_pages": [], "api_endpoints": []
        })
        scored = {"score": 70, "level": "high", "reasons": ["admin"]}
        paths = AttackPathGenerator.generate(asset, scored)
        admin_path = [p for p in paths if p["path"] == "Admin Panel Exposed"]
        assert len(admin_path) == 1
        assert admin_path[0]["severity"] == "critical"  # score >= 65

    def test_rule2_admin_high_when_low_score(self):
        asset = _make_asset(attack_surface={
            "admin_panels": [{"path": "/admin", "status": 403}],
            "login_pages": [], "api_endpoints": []
        })
        scored = {"score": 30, "level": "low", "reasons": ["admin"]}
        paths = AttackPathGenerator.generate(asset, scored)
        admin_path = [p for p in paths if p["path"] == "Admin Panel Exposed"]
        assert admin_path[0]["severity"] == "high"  # score < 65

    def test_rule4_ftp(self):
        asset = _make_asset(ports=[{"port": 21, "state": "open"}])
        scored = {"score": 20, "level": "low", "reasons": ["FTP"]}
        paths = AttackPathGenerator.generate(asset, scored)
        names = [p["path"] for p in paths]
        assert "Legacy Service Exploitation" in names

    def test_rule5_chained(self):
        scored = {"score": 80, "level": "high", "reasons": ["a", "b", "c", "d"]}
        asset = _make_asset()
        paths = AttackPathGenerator.generate(asset, scored)
        chained = [p for p in paths if "Chained" in p["path"]]
        assert len(chained) == 1
        assert chained[0]["severity"] == "critical"

    def test_rule5_not_triggered_low_score(self):
        scored = {"score": 30, "level": "low", "reasons": ["a", "b", "c", "d"]}
        asset = _make_asset()
        paths = AttackPathGenerator.generate(asset, scored)
        chained = [p for p in paths if "Chained" in p["path"]]
        assert len(chained) == 0
