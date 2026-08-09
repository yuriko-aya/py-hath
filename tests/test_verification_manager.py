import hashlib
import time

import config_manager
import verification_manager


def test_verify_servercmd_key():
    config_manager.Config.client_id = "12345"
    config_manager.Config.client_key = "secret"
    time_param = "1000000"
    command = "still_alive"
    additional = ""
    data = f"hentai@home-servercmd-{command}-{additional}-12345-{time_param}-secret"
    key = hashlib.sha1(data.encode()).hexdigest()
    assert verification_manager.verify_servercmd_key(command, additional, time_param, key)


def test_verify_h_endpoint_auth_valid():
    config_manager.Config.client_key = "secret"
    keystamp = str(int(time.time()))
    file_id = "abc123def456"
    hash_data = f"{keystamp}-{file_id}-secret-hotlinkthis"
    expected = hashlib.sha1(hash_data.encode()).hexdigest()[:10]
    assert verification_manager.verify_h_endpoint_auth(keystamp, expected, file_id)


def test_verify_h_endpoint_auth_expired():
    config_manager.Config.client_key = "secret"
    keystamp = str(int(time.time()) - 1000)
    assert not verification_manager.verify_h_endpoint_auth(keystamp, "0000000000", "abc")
