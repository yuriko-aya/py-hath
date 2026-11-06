"""Hentai@Home RPC protocol helpers (API 16 / client build 181)."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

RPC_API = "16"
GALLERY_FILENAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,250}$")
GALLERY_FILETYPE_RE = re.compile(r"^(jpg|gif|png|webp)$")
DLHASH_RE = re.compile(r"^[a-f0-9]{40}$")


class FatalStartupError(Exception):
    """Server rejected startup in a way that must terminate the client."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class SignedRpcResult:
    ok: bool
    fail_code: Optional[str] = None
    body_lines: list[str] = field(default_factory=list)
    key_expired: bool = False

    @property
    def body_text(self) -> str:
        return "\n".join(self.body_lines)


def sha1_hex(data: str) -> str:
    return hashlib.sha1(data.encode("utf-8")).hexdigest()


def rpc_url_path(
    act: str,
    add: str = "",
    *,
    endpoint: str = "rpc",
    client_build: str,
    client_id: str,
    acttime: int,
    actkey: str,
) -> str:
    return (
        f"/{RPC_API}/{endpoint}?clientbuild={client_build}&act={act}"
        f"&add={add}&cid={client_id}&acttime={acttime}&actkey={actkey}"
    )


def parse_signed_response(text: str, client_key: str) -> SignedRpcResult:
    """Verify an API-16 `OK-{time}-{sha1}` RPC envelope (Java ServerResponse)."""
    if text is None:
        return SignedRpcResult(ok=False, fail_code="NO_RESPONSE")

    split = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if not split or split[0] == "":
        return SignedRpcResult(ok=False, fail_code="NO_RESPONSE")

    first = split[0]
    if first.startswith("TEMPORARILY_UNAVAILABLE"):
        return SignedRpcResult(ok=False, fail_code="TEMPORARILY_UNAVAILABLE")

    if first.startswith("OK-"):
        header = first.split("-")
        if len(header) < 3:
            return SignedRpcResult(ok=False, fail_code=first)
        response_time = header[1]
        expected_hash = header[2]
        body_lines = split[1:]
        checked = f"{response_time}-{client_key}"
        for line in body_lines:
            checked += f"\n{line}"
        if sha1_hex(checked) == expected_hash:
            return SignedRpcResult(ok=True, body_lines=body_lines)
        return SignedRpcResult(ok=False, fail_code="RESPONSE_HASH_FAILED")

    if first == "KEY_EXPIRED":
        return SignedRpcResult(ok=False, fail_code="KEY_EXPIRED", key_expired=True)

    return SignedRpcResult(ok=False, fail_code=first, body_lines=split[1:])


def raise_if_fatal_login(fail_code: str) -> None:
    code = fail_code or ""
    if code.startswith("FAIL_STARTUP_LOOP"):
        raise FatalStartupError(
            code,
            "The client has failed too many recent startup attempts; wait 15 minutes and try again.",
        )
    if code.startswith("FAIL_UNSUPPORTED_LOCATION"):
        raise FatalStartupError(
            code,
            "The client appears to be located in a country that H@H does not support.",
        )


def gallery_list_hash(client_key: str, filelist_lines: list[str]) -> str:
    checked = client_key
    for line in filelist_lines:
        checked += f"\n{line}"
    return sha1_hex(checked)


def is_safe_gallery_filename(filename: str) -> bool:
    return bool(filename) and ".." not in filename and bool(GALLERY_FILENAME_RE.match(filename))


def is_allowed_gallery_filetype(filetype: str) -> bool:
    return bool(filetype) and bool(GALLERY_FILETYPE_RE.match(filetype))


def is_allowed_download_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def contained_gallery_path(dir_path: str | Path, filename: str, filetype: str) -> Optional[Path]:
    if not is_safe_gallery_filename(filename) or not is_allowed_gallery_filetype(filetype):
        return None
    dest_dir = Path(dir_path).resolve()
    candidate = (dest_dir / f"{filename}.{filetype}").resolve()
    if candidate.parent != dest_dir:
        return None
    return candidate
