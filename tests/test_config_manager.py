import hashlib
import json
import logging
import os

from hath.config import (
    Config,
    generate_actkey,
    get_client_ip,
    get_config,
    get_current_acttime,
    is_verify_cache_requested,
    replace_config,
)


def test_generate_actkey():
    replace_config(Config(client_id="99", client_key="key", time_difference=0))
    actkey = generate_actkey("test_act", "add")
    current = get_current_acttime()
    expected = hashlib.sha1(
        f"hentai@home-test_act-add-99-{current}-key".encode()
    ).hexdigest()
    assert actkey == expected


def test_get_client_ip_direct():
    replace_config(Config(trust_x_forwarded_for=False))
    environ = {'REMOTE_ADDR': '203.0.113.1'}
    assert get_client_ip(environ) == '203.0.113.1'


def test_get_client_ip_forwarded():
    replace_config(Config(trust_x_forwarded_for=True))
    environ = {
        'HTTP_X_FORWARDED_FOR': '198.51.100.2, 203.0.113.1',
        'REMOTE_ADDR': '127.0.0.1',
    }
    assert get_client_ip(environ) == '198.51.100.2'


def test_is_verify_cache_requested():
    replace_config(Config(server={'verify_cache': 'true'}))
    assert is_verify_cache_requested() is True

    get_config().server = {'verify_cache': 'false'}
    assert is_verify_cache_requested() is False

    get_config().server = {}
    assert is_verify_cache_requested() is False


def test_hot_reload_throttle_and_log_level(tmp_path):
    replace_config(Config(
        data_dir="sticky-data",
        cache_dir="sticky-cache",
        download_dir="sticky-download",
        config_dir=str(tmp_path),
        log_dir="sticky-log",
        hath_port=8443,
        cert_file="sticky-data/client.crt",
        key_file="sticky-data/client.key",
        server={"throttle_bytes": "1000"},
        client_id="1",
        client_key="secret",
        loaded_mtime=1.0,
    ))
    payload = {
        "config": {"throttle_bytes": "8192", "disable_logging": "true"},
        "rpc_server_ips": ["198.51.100.8"],
        "static_range": ["abcd"],
        "static_range_count": 1,
        "client_id": "1",
        "client_key": "secret",
        "server_time": 10,
        "time_difference": 2,
        "data_dir": "other-data",
        "hath_port": 9,
        "cert_file": "nope",
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload))
    os.utime(path, (10, 10))

    root = logging.getLogger()
    previous = root.level
    try:
        root.setLevel(logging.DEBUG)
        reloaded = get_config()
        assert reloaded.server["throttle_bytes"] == "8192"
        assert root.level == logging.WARNING
        assert reloaded.data_dir == "sticky-data"
        assert reloaded.cache_dir == "sticky-cache"
        assert reloaded.log_dir == "sticky-log"
        assert reloaded.hath_port == 8443
        assert reloaded.cert_file == "sticky-data/client.crt"
        assert reloaded.key_file == "sticky-data/client.key"
        assert reloaded.rpc_server_ips == ["198.51.100.8"]
    finally:
        root.setLevel(previous)
        replace_config(Config())
