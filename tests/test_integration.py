"""Integration tests — full pipeline: app boot, routes, scan flow"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
import json
from app import create_app


@pytest.fixture
def app():
    app = create_app()
    app.config['TESTING'] = True
    return app


@pytest.fixture
def client(app):
    return app.test_client()


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
