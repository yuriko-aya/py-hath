"""Tests for hath.paths helpers."""

import config_manager
from hath.paths import get_cert_path, get_config_dir, get_data_dir, get_key_path, get_p12_path, get_stats_sock_path


def test_ssl_paths_under_data_dir():
    config_manager.Config.data_dir = 'custom-data'
    assert get_data_dir() == 'custom-data'
    assert get_cert_path() == 'custom-data/client.crt'
    assert get_key_path() == 'custom-data/client.key'
    assert get_p12_path() == 'custom-data/client.p12'


def test_stats_sock_path(monkeypatch):
    monkeypatch.delenv('HATH_STATS_SOCK', raising=False)
    config_manager.Config.config_dir = 'config'
    assert get_stats_sock_path() == 'config/hath-stats.sock'
    monkeypatch.setenv('HATH_STATS_SOCK', '/tmp/hath-stats.sock')
    assert get_stats_sock_path() == '/tmp/hath-stats.sock'
    assert get_config_dir() == 'config'
