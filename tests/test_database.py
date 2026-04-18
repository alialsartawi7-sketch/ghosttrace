"""Tests for database/manager.py — ScanDB + ResultDB"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from database.manager import Database, ScanDB, ResultDB


@pytest.fixture(autouse=True)
def fresh_db(tmp_path):
    """Use temp DB for each test"""
    from config import Config
    Config.BASE_DIR = str(tmp_path)
    Config.DB_PATH = str(tmp_path / "test.db")
    Config.init()
    Database.init()
    yield
    Database.close()


class TestScanDB:
    def test_create_scan(self):
        sid = ScanDB.create("email", "test.com", "theHarvester")
        assert sid is not None
        assert len(sid) > 10

    def test_get_scan(self):
        sid = ScanDB.create("email", "test.com", "theHarvester")
        scan = ScanDB.get(sid)
        assert scan is not None
        assert scan["target"] == "test.com"
        assert scan["module"] == "email"
        assert scan["status"] == "running"

    def test_finish_scan(self):
        sid = ScanDB.create("email", "test.com", "theHarvester")
        ScanDB.finish(sid, "complete", 42)
        scan = ScanDB.get(sid)
        assert scan["status"] == "complete"
        assert scan["total_results"] == 42

    def test_delete_scan(self):
        sid = ScanDB.create("email", "test.com", "theHarvester")
        ScanDB.delete(sid)
        scan = ScanDB.get(sid)
        assert scan is None

    def test_save_and_get_notes(self):
        sid = ScanDB.create("email", "test.com", "theHarvester")
        ScanDB.save_notes(sid, "Important findings here")
        notes = ScanDB.get_notes(sid)
        assert notes == "Important findings here"

    def test_notes_truncated(self):
        sid = ScanDB.create("email", "test.com", "theHarvester")
        long_note = "A" * 3000
        ScanDB.save_notes(sid, long_note)
        notes = ScanDB.get_notes(sid)
        assert len(notes) <= 2000

    def test_get_notes_empty(self):
        sid = ScanDB.create("email", "test.com", "theHarvester")
        notes = ScanDB.get_notes(sid)
        assert notes == ""


class TestResultDB:
    def test_add_result(self):
        sid = ScanDB.create("email", "test.com", "theHarvester")
        added = ResultDB.add(sid, "admin@test.com", "theHarvester", "email", 0.9)
        assert added is True

    def test_add_duplicate_rejected(self):
        sid = ScanDB.create("email", "test.com", "theHarvester")
        ResultDB.add(sid, "admin@test.com", "theHarvester", "email", 0.9)
        added = ResultDB.add(sid, "admin@test.com", "theHarvester", "email", 0.9)
        assert added is False

    def test_get_by_scan(self):
        sid = ScanDB.create("email", "test.com", "theHarvester")
        ResultDB.add(sid, "a@test.com", "theHarvester", "email", 0.9)
        ResultDB.add(sid, "b@test.com", "theHarvester", "email", 0.8)
        results = ResultDB.get_by_scan(sid)
        assert len(results["items"]) == 2

    def test_count_value(self):
        sid = ScanDB.create("email", "test.com", "theHarvester")
        ResultDB.add(sid, "admin@test.com", "theHarvester", "email", 0.9)
        count = ResultDB.count_value("admin@test.com")
        assert count >= 1

    def test_search(self):
        sid = ScanDB.create("email", "test.com", "theHarvester")
        ResultDB.add(sid, "admin@test.com", "theHarvester", "email", 0.9)
        ResultDB.add(sid, "info@test.com", "theHarvester", "email", 0.6)
        results = ResultDB.search("admin")
        assert any("admin" in r["value"] for r in results)
