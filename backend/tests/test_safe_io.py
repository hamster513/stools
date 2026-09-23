"""Распаковка с потолком (аудит H2): gzip и члены zip со счётчиком байт."""
from __future__ import annotations

import gzip
import io
import zipfile

import pytest

from kbaudit.safe_io import MB, check_zip_sizes, decompress_gzip, read_zip_member


def test_gzip_within_limit() -> None:
    data = b"abc" * 1000
    assert decompress_gzip(gzip.compress(data), MB) == data


def test_gzip_bomb_stops_at_limit() -> None:
    bomb = gzip.compress(b"\0" * (10 * MB))
    assert len(bomb) < 64 * 1024
    with pytest.raises(ValueError, match=r"распакованный размер больше лимита \(1 МБ\)"):
        decompress_gzip(bomb, MB)


def test_broken_gzip_still_raises_os_error() -> None:
    with pytest.raises((OSError, EOFError)):
        decompress_gzip(b"\x1f\x8bnot gzip", MB)


def _zip(members: dict[str, bytes]) -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return zipfile.ZipFile(io.BytesIO(buf.getvalue()))


def test_zip_member_within_limit() -> None:
    with _zip({"a.txt": b"hello"}) as zf:
        assert read_zip_member(zf, "a.txt", MB) == b"hello"
        assert read_zip_member(zf, zf.getinfo("a.txt"), MB) == b"hello"


def test_zip_member_over_limit_rejected_by_header() -> None:
    with (
        _zip({"big.xml": b" " * (2 * MB)}) as zf,
        pytest.raises(ValueError, match="big.xml: распакованный размер больше лимита"),
    ):
        read_zip_member(zf, "big.xml", MB)


def test_check_zip_sizes_member_and_total() -> None:
    with _zip({"a": b" " * MB, "b": b" " * MB}) as zf:
        check_zip_sizes(zf, max_member=MB, max_total=2 * MB)
        with pytest.raises(ValueError, match="a: распакованный размер больше лимита"):
            check_zip_sizes(zf, max_member=MB - 1, max_total=2 * MB)
        with pytest.raises(ValueError, match=r"архив: распакованный размер больше лимита \(1 МБ\)"):
            check_zip_sizes(zf, max_member=MB, max_total=MB)
