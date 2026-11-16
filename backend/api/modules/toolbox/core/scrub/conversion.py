"""Bounded file queue client. Conversion runs in a separate networkless container."""
from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path

from .documents import DocumentError, LEGACY, LIMIT


class ConversionUnavailable(ValueError):
    pass


def convert(data: bytes, suffix: str) -> bytes:
    root = os.environ.get('STOOLS_DOCUMENT_QUEUE')
    if not root or not Path(root).is_dir():
        raise ConversionUnavailable('конвертер документов недоступен; запустите сервис document-converter')
    request = Path(tempfile.mkdtemp(prefix='job-', dir=root))
    try:
        (request / ('input' + suffix)).write_bytes(data)
        (request / 'ready').touch()
        end = time.monotonic() + 100
        while time.monotonic() < end:
            if (request / 'failed').exists():
                raise DocumentError('конвертация не удалась: файл повреждён, зашифрован или формат не поддержан')
            result = request / ('result' + LEGACY[suffix])
            if (request / 'done').exists():
                if not result.is_file() or result.stat().st_size > LIMIT:
                    raise DocumentError('некорректный размер результата конвертации')
                return result.read_bytes()
            time.sleep(0.2)
        raise ConversionUnavailable('конвертер документов не ответил за 100 секунд')
    finally:
        shutil.rmtree(request, ignore_errors=True)
