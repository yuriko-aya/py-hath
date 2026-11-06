import hashlib
from unittest.mock import MagicMock, patch

import config_manager
from hath.rpc_protocol import (
    FatalStartupError,
    contained_gallery_path,
    parse_signed_response,
    raise_if_fatal_login,
    rpc_url_path,
    sha1_hex,
)


def _signed_ok(client_key: str, body_lines: list[str], response_time: str = "1700000000") -> str:
    checked = f"{response_time}-{client_key}"
    for line in body_lines:
        checked += f"\n{line}"
    header = f"OK-{response_time}-{sha1_hex(checked)}"
    if body_lines:
        return header + "\n" + "\n".join(body_lines)
    return header


def test_parse_signed_ok_with_body():
    key = "secretclientkey12345"
    body = ["host=1.2.3.4", "port=443"]
    text = _signed_ok(key, body)
    result = parse_signed_response(text, key)
    assert result.ok
    assert result.body_lines == body


def test_parse_signed_ok_empty_body():
    key = "secretclientkey12345"
    text = _signed_ok(key, [])
    result = parse_signed_response(text, key)
    assert result.ok
    assert result.body_lines == []


def test_parse_signed_rejects_tampered_body():
    key = "secretclientkey12345"
    text = _signed_ok(key, ["host=1.2.3.4"])
    tampered = text + "\nport=1"
    result = parse_signed_response(tampered, key)
    assert not result.ok
    assert result.fail_code == "RESPONSE_HASH_FAILED"


def test_parse_signed_key_expired():
    result = parse_signed_response("KEY_EXPIRED", "key")
    assert not result.ok
    assert result.key_expired
    assert result.fail_code == "KEY_EXPIRED"


def test_rpc_url_path_uses_api_16():
    path = rpc_url_path(
        "client_login",
        "",
        client_build="181",
        client_id="99",
        acttime=1,
        actkey="abc",
    )
    assert path.startswith("/16/rpc?")
    assert "clientbuild=181" in path
    assert "act=client_login" in path


def test_fatal_startup_codes():
    try:
        raise_if_fatal_login("FAIL_STARTUP_LOOP")
        assert False, "expected FatalStartupError"
    except FatalStartupError as e:
        assert e.code.startswith("FAIL_STARTUP_LOOP")

    try:
        raise_if_fatal_login("FAIL_UNSUPPORTED_LOCATION")
        assert False, "expected FatalStartupError"
    except FatalStartupError as e:
        assert e.code.startswith("FAIL_UNSUPPORTED_LOCATION")

    raise_if_fatal_login("FAIL_OTHER")


def test_get_client_config_exits_on_startup_loop():
    from hath.rpc_protocol import SignedRpcResult

    config_manager.Config.client_id = "1"
    config_manager.Config.client_key = "key"
    fail = SignedRpcResult(ok=False, fail_code="FAIL_STARTUP_LOOP")
    with patch("rpc_manager.call_rpc", return_value=fail):
        try:
            config_manager.get_client_config()
            assert False, "expected FatalStartupError"
        except FatalStartupError:
            pass


def test_contained_gallery_path_blocks_traversal(tmp_path):
    dest = tmp_path / "gallery"
    dest.mkdir()
    assert contained_gallery_path(dest, "page01", "jpg").parent == dest.resolve()
    assert contained_gallery_path(dest, "..", "jpg") is None
    assert contained_gallery_path(dest, "../escape", "jpg") is None
    assert contained_gallery_path(dest, "ok", "exe") is None


def test_call_rpc_retries_key_expired():
    from hath.rpc_protocol import SignedRpcResult
    import rpc_manager

    key = "secretclientkey12345"
    config_manager.Config.client_key = key
    ok_text = _signed_ok(key, ["still_alive"])

    expired = MagicMock()
    expired.text = "KEY_EXPIRED"
    ok_resp = MagicMock()
    ok_resp.text = ok_text

    with patch("config_manager.rpc_path", return_value="/16/rpc?act=still_alive"), patch(
        "config_manager.get_server_time", return_value=True
    ), patch("rpc_manager._make_rpc_request", side_effect=[expired, ok_resp]):
        result = rpc_manager.call_rpc("still_alive")
    assert result.ok
    assert result.body_lines == ["still_alive"]


def test_generate_actkey_uses_explicit_acttime():
    config_manager.Config.client_id = "99"
    config_manager.Config.client_key = "key"
    config_manager.Config.time_difference = 0
    actkey = config_manager.generate_actkey("test_act", "add", acttime=42)
    expected = hashlib.sha1(b"hentai@home-test_act-add-99-42-key").hexdigest()
    assert actkey == expected
