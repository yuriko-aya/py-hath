from hath.validation import validate_proxy_url, validate_startup_config


def test_validate_startup_config_ok():
    assert validate_startup_config({
        'workers': 4,
        'log_level': 'INFO',
        'data_dir': 'data',
        'cache_dir': 'cache',
        'log_dir': 'log',
        'config_dir': 'config',
    }) == []


def test_validate_startup_config_bad_workers():
    errors = validate_startup_config({'workers': 0})
    assert any('workers' in e for e in errors)


def test_validate_proxy_url():
    assert validate_proxy_url('socks5://127.0.0.1:1080', 'rpc_proxy') == []
    assert len(validate_proxy_url('ftp://127.0.0.1:1080', 'rpc_proxy')) == 1


def test_is_sha1_hex():
    from hath.validation import file_id_hash_part, is_sha1_hex

    valid = 'a' * 40
    assert is_sha1_hex(valid)
    assert file_id_hash_part(f'{valid}-org') == valid
    assert file_id_hash_part(valid) == valid

    assert not is_sha1_hex('g' * 40)
    assert not is_sha1_hex('abc')
    assert file_id_hash_part('not-a-sha1-org') is None
