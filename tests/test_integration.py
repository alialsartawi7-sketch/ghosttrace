"""Integration tests — full pipeline: app boot, routes, scan flow"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
import json
from app import create_app
from config import Config


@pytest.fixture
def app():
    app = create_app()
    app.config['TESTING'] = True
    return app


@pytest.fixture
def client(app):
    c = app.test_client()
    # Authenticate the session so endpoint tests work whether or not a
    # password is configured on the machine running the tests. Without this,
    # a machine that has run `app.py --setup` redirects every API call to
    # /login (302) and the integration suite fails for environment reasons.
    with c.session_transaction() as sess:
        sess["auth"] = True
    return c


class TestAppBoot:
    def test_app_creates(self, app):
        assert app is not None

    def test_all_blueprints_registered(self, app):
        bp_names = [bp.name for bp in app.blueprints.values()]
        for expected in ['scans', 'history', 'exports', 'system', 'recon']:
            assert expected in bp_names, f"Blueprint '{expected}' not registered"

    def test_route_count(self, app):
        rules = [r.rule for r in app.url_map.iter_rules() if '/api/' in r.rule]
        assert len(rules) >= 25


class TestSystemRoutes:
    def test_check_tools(self, client):
        r = client.get('/api/check-tools')
        assert r.status_code == 200
        data = r.get_json()
        assert 'theHarvester' in data
        assert 'ExifTool' in data

    def test_settings_get(self, client):
        r = client.get('/api/settings')
        assert r.status_code == 200
        data = r.get_json()
        assert 'api_keys' in data

    def test_entities_timeline(self, client):
        r = client.get('/api/entities')
        assert r.status_code == 200
        data = r.get_json()
        assert isinstance(data, list)


class TestHistoryRoutes:
    def test_history_empty(self, client):
        r = client.get('/api/history')
        assert r.status_code == 200

    def test_search_empty(self, client):
        r = client.get('/api/search?q=test')
        assert r.status_code == 200

    def test_stats(self, client):
        r = client.get('/api/stats')
        assert r.status_code == 200


class TestScanRoutes:
    def test_auto_detect_domain(self, client):
        r = client.get('/api/auto-detect?input=example.com')
        assert r.status_code == 200
        data = r.get_json()
        assert data['type'] == 'domain'
        assert data['cleaned'] == 'example.com'

    def test_auto_detect_email(self, client):
        r = client.get('/api/auto-detect?input=admin@example.com')
        assert r.status_code == 200
        data = r.get_json()
        assert data['type'] == 'email'

    def test_auto_detect_phone(self, client):
        r = client.get('/api/auto-detect?input=%2B1234567890')
        assert r.status_code == 200
        data = r.get_json()
        assert data['type'] == 'phone'

    def test_auto_detect_username(self, client):
        r = client.get('/api/auto-detect?input=johndoe')
        assert r.status_code == 200
        data = r.get_json()
        assert data['type'] == 'username'

    def test_auto_detect_empty(self, client):
        r = client.get('/api/auto-detect?input=')
        assert r.status_code == 400

    def test_scan_email_validates_domain(self, client):
        """Invalid domain should return SSE error"""
        r = client.get('/api/scan/email?domain=')
        assert r.status_code == 200  # SSE stream starts
        data = r.data.decode()
        assert 'error' in data.lower() or 'empty' in data.lower()

    def test_scan_dorks(self, client):
        """Dorks should return results without external tool"""
        r = client.get('/api/scan/dorks?domain=example.com')
        assert r.status_code == 200
        data = r.data.decode()
        assert 'site:example.com' in data


class TestExportRoutes:
    def test_export_empty(self, client):
        r = client.post('/api/export',
                       json={"results": [], "format": "json"},
                       headers={"X-CSRF-Token": "test"})
        # May fail CSRF in test — that's expected behavior
        assert r.status_code in (200, 403)

    def test_report_download_invalid(self, client):
        r = client.get('/api/report/download/nonexistent.html')
        assert r.status_code in (400, 404)


class TestGraphRoute:
    def test_graph_returns_json(self, client):
        r = client.get('/api/graph')
        assert r.status_code == 200
        data = r.get_json()
        assert 'nodes' in data
        assert 'edges' in data


class TestValidation:
    """Test that invalid input is properly rejected"""

    def test_dns_empty_domain(self, client):
        r = client.get('/api/scan/dns?domain=')
        data = r.data.decode()
        assert 'error' in data.lower() or 'empty' in data.lower()

    def test_ssl_empty_domain(self, client):
        r = client.get('/api/scan/ssl?domain=')
        data = r.data.decode()
        assert 'error' in data.lower() or 'empty' in data.lower()

    def test_phone_empty(self, client):
        r = client.get('/api/scan/phone?phone=')
        data = r.data.decode()
        assert 'error' in data.lower() or 'empty' in data.lower()

    def test_metadata_traversal(self, client):
        r = client.get('/api/scan/metadata?filepath=../../etc/passwd')
        data = r.data.decode()
        assert 'denied' in data.lower() or 'traversal' in data.lower() or 'error' in data.lower()


class TestSSLTimeout:
    """The TLS connect timeout must follow the user's per-scan setting
    (was fixed at 10s while the rest of the scan honoured 240s)."""

    def _patch_capture(self, monkeypatch):
        captured = {}
        from tools.ssl_cert import SSLCertAdapter

        def fake_parse_cert(self, target, port="443", timeout=10):
            captured["timeout"] = timeout
            return [{"value": "Common Name: x", "source": "SSLCert",
                     "type": "ssl", "confidence": 0.9, "extra": "CN"}]

        monkeypatch.setattr(SSLCertAdapter, "parse_cert", fake_parse_cert)
        return captured

    def test_user_timeout_is_forwarded(self, client, monkeypatch):
        captured = self._patch_capture(monkeypatch)
        r = client.get("/api/scan/ssl?domain=example.com&timeout=300")
        r.get_data(as_text=True)  # drain the SSE stream
        assert captured.get("timeout") == 300

    def test_timeout_is_clamped(self, client, monkeypatch):
        captured = self._patch_capture(monkeypatch)
        r = client.get("/api/scan/ssl?domain=example.com&timeout=99999")
        r.get_data(as_text=True)
        assert captured.get("timeout") == 1800  # clamped to the 1800s ceiling

    def test_default_when_absent(self, client, monkeypatch):
        captured = self._patch_capture(monkeypatch)
        r = client.get("/api/scan/ssl?domain=example.com")
        r.get_data(as_text=True)
        assert captured.get("timeout") == 10  # falls back to the 10s default


class TestSettingsMasking:
    """The settings GET must never leak plaintext keys; an unchanged masked field
    on save must keep the stored secret; clearing a field still works; and the
    theHarvester sync must always receive plaintext, never the mask sentinel."""

    def _isolate(self, tmp_path, monkeypatch):
        # point at-rest storage at a temp dir and capture (don't write) sync calls
        monkeypatch.setattr(Config, "CONFIG_FILE", str(tmp_path / "config.json"))
        monkeypatch.setattr(Config, "KEYFILE", str(tmp_path / ".keyfile"))
        synced = []
        monkeypatch.setattr(Config, "sync_harvester_keys",
                            lambda keys=None: synced.append(keys))
        return synced

    def test_masked_loader_hides_secret(self, tmp_path, monkeypatch):
        self._isolate(tmp_path, monkeypatch)
        Config.save_api_keys({"shodan": "SECRET123", "hunter": ""})
        masked = Config.load_api_keys_masked()
        assert masked["shodan"] == Config.KEY_MASK    # set   -> mask
        assert masked["hunter"] == ""                 # unset -> empty
        assert "SECRET123" not in masked.values()     # secret never present

    def test_get_route_returns_no_plaintext(self, client, tmp_path, monkeypatch):
        self._isolate(tmp_path, monkeypatch)
        Config.save_api_keys({"shodan": "TOPSECRET"})
        data = client.get('/api/settings').get_json()
        assert data["api_keys"]["shodan"] == Config.KEY_MASK
        assert "TOPSECRET" not in json.dumps(data)

    def test_unchanged_mask_keeps_stored_key(self, tmp_path, monkeypatch):
        self._isolate(tmp_path, monkeypatch)
        Config.save_api_keys({"shodan": "ORIGINAL"})
        Config.save_api_keys({"shodan": Config.KEY_MASK})   # UI echoes mask back
        assert Config.load_api_keys()["shodan"] == "ORIGINAL"

    def test_new_value_replaces_key(self, tmp_path, monkeypatch):
        self._isolate(tmp_path, monkeypatch)
        Config.save_api_keys({"shodan": "ORIGINAL"})
        Config.save_api_keys({"shodan": "REPLACED"})
        assert Config.load_api_keys()["shodan"] == "REPLACED"

    def test_empty_clears_key(self, tmp_path, monkeypatch):
        self._isolate(tmp_path, monkeypatch)
        Config.save_api_keys({"shodan": "ORIGINAL"})
        Config.save_api_keys({"shodan": ""})                # clearing still works
        assert Config.load_api_keys().get("shodan", "") == ""

    def test_sync_gets_plaintext_never_mask(self, tmp_path, monkeypatch):
        synced = self._isolate(tmp_path, monkeypatch)
        Config.save_api_keys({"shodan": "ORIGINAL"})
        Config.save_api_keys({"shodan": Config.KEY_MASK})   # untouched on 2nd save
        assert synced[-1]["shodan"] == "ORIGINAL"           # real key reaches sync
        assert Config.KEY_MASK not in synced[-1].values()
