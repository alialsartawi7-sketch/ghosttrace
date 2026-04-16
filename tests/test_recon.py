"""Tests for recon modules (DNS resolver, data quality)"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from unittest.mock import patch, MagicMock
from recon import DNSResolver, DataQuality, AttackSurfaceDetector
from recon.risk_engine import RiskScorer, RiskLevel


# ═══════════ DataQuality ═══════════

class TestDataQuality:
    @pytest.mark.parametrize("ip,expected", [
        ("10.0.0.1", True),
        ("192.168.1.1", True),
        ("172.16.5.10", True),
        ("172.20.1.1", True),
        ("127.0.0.1", True),
        ("0.0.0.0", True),
        ("169.254.1.1", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("193.227.29.12", False),
    ])
    def test_is_private_ip(self, ip, expected):
        assert DataQuality.is_private_ip(ip) == expected

    def test_filter_removes_private_ips(self):
        results = [
            {"value": "admin.test.com (1.2.3.4)", "type": "subdomain", "confidence": 0.8},
            {"value": "internal.test.com (10.0.0.5)", "type": "subdomain", "confidence": 0.8},
            {"value": "test@test.com", "type": "email", "confidence": 0.9},
        ]
        filtered = DataQuality.filter_results(results, domain=None)
        # Private IP entry filtered out
        assert len(filtered) == 2
        assert all("10.0.0.5" not in r["value"] for r in filtered)

    def test_filter_dedups(self):
        results = [
            {"value": "test@test.com", "type": "email", "confidence": 0.9},
            {"value": "test@test.com", "type": "email", "confidence": 0.7},  # duplicate
            {"value": "other@test.com", "type": "email", "confidence": 0.8},
        ]
        filtered = DataQuality.filter_results(results, domain=None)
        assert len(filtered) == 2


# ═══════════ DNSResolver ═══════════

class TestDNSResolver:
    def test_resolve_invalid_hostname(self):
        result = DNSResolver.resolve("invalid.nonexistent.domain.local.fake", timeout=2)
        assert result is not None
        assert result["alive"] is False

    def test_resolve_empty_hostname(self):
        result = DNSResolver.resolve("", timeout=2)
        assert result is None

    def test_resolve_cleans_parenthesis_format(self):
        """Should handle 'host (ip)' format by taking only host"""
        result = DNSResolver.resolve("example.com (192.0.2.1)", timeout=2)
        # Should strip the "(ip)" part
        assert result is None or result["hostname"] in ("example.com", "")

    def test_bulk_resolve_empty(self):
        results = DNSResolver.bulk_resolve([], max_workers=1)
        assert results == {}


# ═══════════ AttackSurfaceDetector ═══════════

class TestAttackSurfaceDetector:
    def test_admin_paths_defined(self):
        assert len(AttackSurfaceDetector.ADMIN_PATHS) > 0
        assert "/admin" in AttackSurfaceDetector.ADMIN_PATHS

    def test_login_paths_defined(self):
        assert len(AttackSurfaceDetector.LOGIN_PATHS) > 0
        assert "/login" in AttackSurfaceDetector.LOGIN_PATHS

    def test_api_paths_defined(self):
        assert len(AttackSurfaceDetector.API_PATHS) > 0
        assert "/api" in AttackSurfaceDetector.API_PATHS

    def test_detect_structure(self):
        """Mock _check_path to avoid network calls"""
        with patch.object(AttackSurfaceDetector, "_check_path", return_value=None):
            result = AttackSurfaceDetector.detect("example.com", timeout=1)
            assert "admin_panels" in result
            assert "login_pages" in result
            assert "api_endpoints" in result
            assert result["hostname"] == "example.com"


# ═══════════ Risk Level ═══════════

class TestRiskLevelBoundaries:
    """Test exact boundaries"""
    @pytest.mark.parametrize("score,expected", [
        (100, "critical"), (85, "critical"),
        (84, "high"), (65, "high"),
        (64, "medium"), (40, "medium"),
        (39, "low"), (20, "low"),
        (19, "info"), (0, "info"),
    ])
    def test_boundaries(self, score, expected):
        assert RiskLevel.from_score(score) == expected

    def test_color_returns_hex(self):
        for level in ["critical", "high", "medium", "low", "info"]:
            c = RiskLevel.color(level)
            assert c.startswith("#")
            assert len(c) == 7
