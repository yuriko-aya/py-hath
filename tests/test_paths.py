"""Tests for hath.paths helpers."""

import config_manager
from hath.paths import get_cert_path, get_data_dir, get_key_path, get_p12_path


def test_ssl_paths_under_data_dir():
    config_manager.Config.data_dir = 'custom-data'
    assert get_data_dir() == 'custom-data'
    assert get_cert_path() == 'custom-data/client.crt'
    assert get_key_path() == 'custom-data/client.key'
    assert get_p12_path() == 'custom-data/client.p12'
