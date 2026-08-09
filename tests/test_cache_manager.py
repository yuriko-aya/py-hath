import hashlib
from unittest.mock import MagicMock

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


def test_record_cached_file_rejects_corrupt_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cache_manager.db, 'update_last_access', MagicMock())
    monkeypatch.setattr(cache_manager.db, 'update_file_size', MagicMock())

    file_path = tmp_path / "corrupt"
    file_path.write_bytes(b"bad data")
    file_id = f"{'a' * 40}-org"

    assert cache_manager._record_cached_file(str(file_path), file_id) is False
    assert not file_path.exists()
    cache_manager.db.update_last_access.assert_not_called()


def test_generate_and_cache_verifies_after_write(tmp_path, monkeypatch):
    monkeypatch.setattr(cache_manager, '_record_cached_file', MagicMock(return_value=True))

    content = b"cached-bytes"
    response = MagicMock()
    response.iter_content.return_value = [content]
    file_path = tmp_path / "aa" / "bb" / "file"

    chunks = list(cache_manager.generate_and_cache(str(file_path), "file-id", response, len(content)))

    assert chunks == [content]
    cache_manager._record_cached_file.assert_called_once_with(str(file_path), "file-id", len(content))
