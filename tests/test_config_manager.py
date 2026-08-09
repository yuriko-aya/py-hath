import hashlib

import config_manager


def test_generate_actkey():
    config_manager.Config.client_id = "99"
    config_manager.Config.client_key = "key"
    config_manager.Config.time_difference = 0
    actkey = config_manager.generate_actkey("test_act", "add")
    current = config_manager.get_current_acttime()
    expected = hashlib.sha1(
        f"hentai@home-test_act-add-99-{current}-key".encode()
    ).hexdigest()
    assert actkey == expected


def test_get_client_ip_direct():
    environ = {'REMOTE_ADDR': '203.0.113.1'}
    config_manager.Config.trust_x_forwarded_for = False
    assert config_manager.get_client_ip(environ) == '203.0.113.1'


def test_get_client_ip_forwarded():
    environ = {
        'HTTP_X_FORWARDED_FOR': '198.51.100.2, 203.0.113.1',
        'REMOTE_ADDR': '127.0.0.1',
    }
    config_manager.Config.trust_x_forwarded_for = True
    assert config_manager.get_client_ip(environ) == '198.51.100.2'


def test_is_verify_cache_requested():
    config_manager.Config.config = {'verify_cache': 'true'}
    assert config_manager.is_verify_cache_requested() is True

    config_manager.Config.config = {'verify_cache': 'false'}
    assert config_manager.is_verify_cache_requested() is False

    config_manager.Config.config = {}
    assert config_manager.is_verify_cache_requested() is False
