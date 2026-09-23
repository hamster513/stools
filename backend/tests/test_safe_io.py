"""Распаковка с потолком (аудит H2): gzip и члены zip со счётчиком байт."""
from __future__ import annotations

import gzip
import io
import tracemalloc
import zipfile
from collections.abc import Callable

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


# ---- Пик памяти ≈ размер результата (финальное ревью, I2) -------------------


def _peak(func: Callable[[], object]) -> tuple[int, int]:
    """(пик выделенной памяти во время вызова, размер результата)."""
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        result = func()
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert isinstance(result, bytes | bytearray)
    return peak, len(result)


def test_gzip_peak_memory_close_to_output() -> None:
    """Куски не копятся списком и не склеиваются в конце: иначе на пике в
    памяти два результата сразу."""
    packed = gzip.compress(bytes(range(256)) * (64 * 1024 * 4))  # 64 МБ
    peak, size = _peak(lambda: decompress_gzip(packed, 128 * MB))
    assert size == 64 * MB
    assert peak < 1.4 * size, f"пик {peak / MB:.0f} МБ при результате {size / MB:.0f} МБ"


def test_zip_member_peak_memory_close_to_output() -> None:
    zf = _zip({"big.xml": bytes(range(256)) * (64 * 1024 * 4)})
    peak, size = _peak(lambda: read_zip_member(zf, "big.xml", 128 * MB))
    assert size == 64 * MB
    assert peak < 1.4 * size, f"пик {peak / MB:.0f} МБ при результате {size / MB:.0f} МБ"


def test_unpack_caps_fit_container_memory() -> None:
    """Потолки распаковки AD/KSC и члена zip — 512 МБ: контейнер API ограничен
    2 ГБ, а разбор JSON добавляет к распакованным байтам ещё кратно больше."""
    from api.modules.ad.core import export as ad_export
    from api.modules.ksc.core import export as ksc_export
    from kbaudit import safe_io

    assert ad_export.MAX_UNPACKED == 512 * MB
    assert ksc_export.MAX_UNPACKED == 512 * MB
    assert safe_io.ZIP_MEMBER_LIMIT <= 512 * MB
