import hashlib

import cache_manager


def test_verify_file_integrity(tmp_path):
    content = b"hello cache"
    file_hash = hashlib.sha1(content).hexdigest()
    file_id = f"{file_hash}-org"
    file_path = tmp_path / "sample"
    file_path.write_bytes(content)
    assert cache_manager.verify_file_integrity(str(file_path), file_id)


def test_verify_file_integrity_fails(tmp_path):
    file_path = tmp_path / "bad"
    file_path.write_bytes(b"wrong content")
    assert not cache_manager.verify_file_integrity(str(file_path), "0000000000000000000000000000000000000000")
