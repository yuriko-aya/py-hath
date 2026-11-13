from hath import download as download_manager
from hath.config import Config, replace_config
from hath.rpc_protocol import gallery_list_hash


def _metadata(client_key: str, filename: str = "page01", filetype: str = "jpg") -> str:
    file_line = f"1 100 1280 abcdefabcdefabcdefabcdefabcdefabcdefabcd {filetype} {filename}"
    dlhash = gallery_list_hash(client_key, [file_line])
    return "\n".join(
        [
            "GID 123",
            "FILECOUNT 1",
            "MINXRES 1280",
            f"DLHASH {dlhash}",
            "TITLE Example Gallery",
            "FILELIST",
            file_line,
            "INFORMATION",
            "notes",
        ]
    )


def test_parse_metadata_accepts_matching_dlhash():
    key = "secretclientkey12345"
    replace_config(Config(client_key=key))
    ok, info, text = download_manager.parse_metadata(_metadata(key))
    assert ok
    assert info["gid"] == 123
    assert info["files"][0]["file_name"] == "page01"
    assert "notes" in text


def test_parse_metadata_rejects_bad_dlhash():
    key = "secretclientkey12345"
    replace_config(Config(client_key=key))
    meta = _metadata(key).replace(
        gallery_list_hash(key, ["1 100 1280 abcdefabcdefabcdefabcdefabcdefabcdefabcd jpg page01"]),
        "0" * 40,
    )
    ok, info, _text = download_manager.parse_metadata(meta)
    assert not ok
    assert info == {}


def test_parse_metadata_rejects_path_traversal_filename():
    key = "secretclientkey12345"
    replace_config(Config(client_key=key))
    ok, info, _text = download_manager.parse_metadata(_metadata(key, filename="../passwd"))
    assert not ok
    assert info == {}


def test_parse_metadata_rejects_bad_filetype():
    key = "secretclientkey12345"
    replace_config(Config(client_key=key))
    ok, info, _text = download_manager.parse_metadata(_metadata(key, filetype="exe"))
    assert not ok
    assert info == {}
