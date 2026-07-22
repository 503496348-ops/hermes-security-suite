"""Tests for p1-1: provider URL honor — OSVClient accepts custom api_url."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detector.modules.osv_client import OSVClient


class TestOSVClientProviderURL:
    """OSVClient should honor custom provider URLs."""

    def test_default_url_unchanged(self):
        client = OSVClient()
        assert client.api_url == "https://api.osv.dev/v1"

    def test_constructor_api_url_override(self):
        custom = "https://custom-osv.example.com/v2"
        client = OSVClient(api_url=custom)
        assert client.api_url == custom

    def test_env_var_osv_api_url(self):
        custom = "https://env-osv.example.com/v1"
        with patch.dict(os.environ, {"OSV_API_URL": custom}):
            client = OSVClient()
            assert client.api_url == custom

    def test_constructor_overrides_env(self):
        env_url = "https://env-osv.example.com/v1"
        ctor_url = "https://ctor-osv.example.com/v1"
        with patch.dict(os.environ, {"OSV_API_URL": env_url}):
            client = OSVClient(api_url=ctor_url)
            assert client.api_url == ctor_url

    def test_curl_uses_custom_url(self):
        custom = "https://my-osv.dev/v1"
        client = OSVClient(api_url=custom)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="")
            client._curl("query", '{"package":{"name":"test"}}')
            cmd = mock_run.call_args[0][0]
            assert any(custom in arg for arg in cmd), f"Expected {custom} in {cmd}"

    def test_offline_returns_none_even_with_custom_url(self):
        client = OSVClient(offline=True, api_url="https://custom.dev/v1")
        assert client._curl("query") is None


class TestBridgeProviderURL:
    """Bridge should pass osv_api_url through to scan_with_osv_lookup."""

    def test_bridge_passes_osv_api_url(self):
        import scripts.skillspector_bridge as bridge
        payload = bridge._sample_payload()
        custom_url = "https://bridge-test-osv.dev/v1"
        with patch("scripts.skillspector_bridge.scan_with_osv_lookup") as mock_scan:
            mock_scan.return_value = []
            bridge._run_bridge(payload, sample=True, project_path="/tmp", osv_api_url=custom_url)
            mock_scan.assert_called_once()
            _, kwargs = mock_scan.call_args
            assert kwargs.get("osv_api_url") == custom_url

    def test_bridge_default_url_is_none(self):
        import scripts.skillspector_bridge as bridge
        payload = bridge._sample_payload()
        with patch("scripts.skillspector_bridge.scan_with_osv_lookup") as mock_scan:
            mock_scan.return_value = []
            bridge._run_bridge(payload, sample=True, project_path="/tmp")
            _, kwargs = mock_scan.call_args
            assert kwargs.get("osv_api_url") is None
