"""Mocked /h/ and /servercmd request flows."""

import hashlib
import time
from unittest.mock import MagicMock, patch

from hath.config import Config, replace_config
from hath.http.app import app
from hath.paths import cache_file_path

FILE_ID = "a" * 40


def _keystamp(client_key: str, file_id: str) -> str:
    stamp = str(int(time.time()))
    digest = hashlib.sha1(f"{stamp}-{file_id}-{client_key}-hotlinkthis".encode()).hexdigest()[:10]
    return f"{stamp}-{digest}"


def _server_key(command: str, additional: str, client_id: str, client_key: str, time_param: str) -> str:
    data = f"hentai@home-servercmd-{command}-{additional}-{client_id}-{time_param}-{client_key}"
    return hashlib.sha1(data.encode()).hexdigest()


def _ready_config(**kwargs):
    defaults = dict(client_id="12345", client_key="secret", rpc_server_ips=["127.0.0.1"])
    defaults.update(kwargs)
    return replace_config(Config(**defaults))


def test_cache_hit_updates_last_access(tmp_path):
    _ready_config(cache_dir=str(tmp_path))
    file_path = cache_file_path(FILE_ID)
    import os
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "wb") as f:
        f.write(b"cached-image")

    stamp = _keystamp("secret", FILE_ID)
    url = f"/h/{FILE_ID}/keystamp={stamp};fileindex=1;xres=org/page.jpg"
    with patch("hath.http.files.db.update_last_access") as update_last_access, patch(
        "hath.http.files.cache.fetch_remote_file"
    ) as fetch_remote:
        response = app.test_client().get(url)

    assert response.status_code == 200
    assert response.data == b"cached-image"
    update_last_access.assert_called_once_with(FILE_ID[:4])
    fetch_remote.assert_not_called()


def test_cache_miss_streams_remote_file(tmp_path):
    _ready_config(cache_dir=str(tmp_path))
    remote = MagicMock()
    remote.headers = {"Content-Length": "5"}
    remote.iter_content.return_value = [b"hello"]
    stamp = _keystamp("secret", FILE_ID)
    url = f"/h/{FILE_ID}/keystamp={stamp};fileindex=9;xres=org/page.jpg"

    with patch("hath.http.files.cache.fetch_remote_file", return_value=(True, remote)) as fetch_remote, patch(
        "hath.cache._record_cached_file", return_value=True
    ):
        response = app.test_client().get(url)

    assert response.status_code == 200
    assert response.data == b"hello"
    fetch_remote.assert_called_once_with("9", "org", FILE_ID)


def test_servercmd_rejects_non_rpc_ip():
    _ready_config(rpc_server_ips=["203.0.113.9"], disable_ip_check=False)
    now = str(int(time.time()))
    key = _server_key("still_alive", "", "12345", "secret", now)
    response = app.test_client().get(f"/servercmd/still_alive/{now}/{key}")
    assert response.status_code == 403


def test_servercmd_rejects_bad_key():
    _ready_config()
    now = str(int(time.time()))
    response = app.test_client().get(f"/servercmd/still_alive/{now}/{'0' * 40}")
    assert response.status_code == 403


def test_servercmd_still_alive():
    _ready_config()
    now = str(int(time.time()))
    key = _server_key("still_alive", "", "12345", "secret", now)
    response = app.test_client().get(f"/servercmd/still_alive/{now}/{key}")
    assert response.status_code == 200
    assert b"still alive" in response.data


def test_servercmd_start_downloader():
    _ready_config()
    now = str(int(time.time()))
    key = _server_key("start_downloader", "", "12345", "secret", now)
    with patch("hath.http.servercmd.trigger_download") as trigger:
        response = app.test_client().get(f"/servercmd/start_downloader/{now}/{key}")
    assert response.status_code == 200
    trigger.assert_called_once_with()
