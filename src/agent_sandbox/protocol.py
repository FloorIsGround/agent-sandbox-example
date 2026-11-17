# SPDX-License-Identifier: Apache-2.0
# Adapted with changes from Tylenol Taker Python.
"""Bounded authenticated owned-stdio frames; no authority comes from payload IDs."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path

MAX_FRAME = 1_048_576
MAX_WIRE = 4_194_304
MAX_FRAMES = 128


class ProtocolError(ValueError):
    pass


def file_name(name: str) -> str:
    if (
        not isinstance(name, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,59}\.(txt|csv|json)", name)
        or ".." in name
    ):
        raise ProtocolError("Unsafe selected name")
    return name


def text_bytes(data: bytes, limit: int) -> str:
    if not isinstance(data, bytes) or (
        len(data) > limit
        or b"\0" in data
        or data.startswith((b"PK\x03\x04", b"\x1f\x8b"))
        or data[257:262] == b"ustar"
    ):
        raise ProtocolError("File size/type denied")
    try:
        return data.decode("utf-8", "strict")
    except UnicodeError:
        raise ProtocolError("Only UTF-8 text/CSV/JSON supported") from None


class StreamBuffer:
    """Coalesce arbitrary pipe fragmentation before UTF-8 decode/frame emission."""

    def __init__(self) -> None:
        self.raw = bytearray()

    def feed(self, chunk: bytes) -> None:
        if len(self.raw) + len(chunk) > 65_536:
            raise ProtocolError("Stream output limit")
        self.raw.extend(chunk)

    def text(self) -> str:
        try:
            return self.raw.decode("utf-8", "strict")
        except UnicodeError:
            raise ProtocolError("Invalid stream UTF-8") from None


def selected_bytes(root: Path, name: str) -> bytes:
    """Container filesystem enforcement; receiver independently validates bytes."""
    file_name(name)
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 262144:
            raise ValueError("Unsafe selected file")
        data = stream.read(262145)
    text_bytes(data, 262144)
    return data


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise ProtocolError("Duplicate frame field")
        result[key] = value
    return result


def _constant(_: str) -> object:
    raise ProtocolError("Nonfinite frame value")


def dumps(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def loads(raw: bytes) -> dict[str, object]:
    if len(raw) > MAX_FRAME:
        raise ProtocolError("Frame overflow")
    try:
        value = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=_pairs, parse_constant=_constant
        )
    except (ValueError, UnicodeError, RecursionError):
        raise ProtocolError("Invalid frame") from None
    if not isinstance(value, dict):
        raise ProtocolError("Frame must be an object")
    return value


class Codec:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ProtocolError("Invalid execution key")
        self.key = key
        self.sent = self.received = self.written = self.read = 0

    def encode(self, data: dict[str, object]) -> bytes:
        seq = self.sent + 1
        payload = dumps({"seq": seq, "data": data})
        frame = (
            dumps(
                {
                    "seq": seq,
                    "data": data,
                    "mac": hmac.new(self.key, payload, hashlib.sha256).hexdigest(),
                }
            )
            + b"\n"
        )
        if len(frame) > MAX_FRAME or seq > MAX_FRAMES or self.written + len(frame) > MAX_WIRE:
            raise ProtocolError("Frame output limit")
        self.sent, self.written = seq, self.written + len(frame)
        return frame

    def decode(self, raw: bytes) -> dict[str, object]:
        if not raw.endswith(b"\n") or self.read + len(raw) > MAX_WIRE:
            raise ProtocolError("Frame input limit")
        value = loads(raw)
        if set(value) != {"seq", "data", "mac"}:
            raise ProtocolError("Invalid envelope")
        seq, data, mac = value["seq"], value["data"], value["mac"]
        if type(seq) is not int or seq != self.received + 1 or seq > MAX_FRAMES:
            raise ProtocolError("Frame replay/order denial")
        if (
            not isinstance(data, dict)
            or not isinstance(mac, str)
            or not re.fullmatch(r"[0-9a-f]{64}", mac)
        ):
            raise ProtocolError("Invalid envelope")
        expected = hmac.new(self.key, dumps({"seq": seq, "data": data}), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            raise ProtocolError("Frame authentication denial")
        self.received, self.read = seq, self.read + len(raw)
        return data
