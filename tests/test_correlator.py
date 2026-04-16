"""Tests for intelligence/correlator.py"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from unittest.mock import patch, MagicMock
from intelligence.correlator import Scorer


# Mock ResultDB.count_value to avoid DB calls
@pytest.fixture(autouse=True)
def mock_db():
    with patch("database.manager.ResultDB.count_value", return_value=0) as mock:
        yield mock


# ═══════════ Scorer.calculate ═══════════

class TestScorerCalculate:
    def test_known_source_weight(self):
        """crtsh has weight 0.9 in Config"""
        score = Scorer.calculate("test@test.com", "crtsh", "email")
        # 0.9 * 1.0 * 0.9 = 0.81
        assert score == 0.81

    def test_unknown_source_defaults_05(self):
        """Unknown source should default to 0.5 base"""
        score = Scorer.calculate("val", "unknownsource", "email")
        # 0.5 * 1.0 * 0.9 = 0.45
        assert score == 0.45

    def test_email_type_multiplier(self):
        """Email type mult = 0.9"""
        score = Scorer.calculate("x@y.com", "crtsh", "email")
        assert score == round(0.9 * 1.0 * 0.9, 2)

    def test_metadata_type_multiplier(self):
        """Metadata type mult = 0.95"""
        score = Scorer.calculate("Author: John", "ExifTool", "metadata")
        # ExifTool weight=0.95, type=0.95 → 0.95*1.0*0.95 = 0.9025 → 0.9
        assert score == 0.9

    def test_subdomain_type_multiplier(self):
        """Subdomain type mult = 0.85"""
        score = Scorer.calculate("sub.test.com", "crtsh", "subdomain")
        # 0.9 * 1.0 * 0.85 = 0.765 → 0.76 or 0.77 (rounding)
        assert score in (0.76, 0.77)

    def test_username_type_multiplier(self):
        """Username type mult = 0.8"""
        score = Scorer.calculate("user @ GitHub", "GitHub", "username")
        # GitHub not in SOURCE_WEIGHTS → 0.5 * 1.0 * 0.8 = 0.4
        assert score == 0.4

    def test_score_capped_at_1(self):
        """Score should never exceed 1.0"""
        # Force high corroboration
        with patch("database.manager.ResultDB.count_value", return_value=100):
            score = Scorer.calculate("val", "crtsh", "metadata")
            assert score <= 1.0

    def test_corroboration_increases_score(self, mock_db):
        """Existing results should boost score"""
        mock_db.return_value = 0
        score_new = Scorer.calculate("val", "crtsh", "email")

        mock_db.return_value = 5
        score_seen = Scorer.calculate("val", "crtsh", "email")
        assert score_seen > score_new


# ═══════════ Scorer.corroboration_bonus ═══════════

class TestCorroborationBonus:
    def test_zero_existing(self):
        with patch("database.manager.ResultDB.count_value", return_value=0):
            assert Scorer.corroboration_bonus("newvalue") == 0.0

    def test_one_existing(self):
        with patch("database.manager.ResultDB.count_value", return_value=1):
            assert Scorer.corroboration_bonus("seenonce") == 0.05

    def test_two_existing(self):
        with patch("database.manager.ResultDB.count_value", return_value=2):
            assert Scorer.corroboration_bonus("seentwice") == 0.05

    def test_three_plus_existing(self):
        with patch("database.manager.ResultDB.count_value", return_value=3):
            assert Scorer.corroboration_bonus("seenmany") == 0.15

    def test_ten_existing(self):
        with patch("database.manager.ResultDB.count_value", return_value=10):
            assert Scorer.corroboration_bonus("seenlots") == 0.15
