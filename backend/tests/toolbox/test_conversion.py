"""Conversion client boundaries: availability, errors, size limits, scratch cleanup."""
from pathlib import Path

import pytest

from api.modules.toolbox.core.scrub import conversion
from api.modules.toolbox.core.scrub.documents import DocumentError, LIMIT


def test_converter_is_required(monkeypatch):
    monkeypatch.delenv('STOOLS_DOCUMENT_QUEUE', raising=False)
    with pytest.raises(conversion.ConversionUnavailable, match='недоступен'):
        conversion.convert(b'legacy', '.doc')


@pytest.mark.parametrize('outcome', ['done', 'failed', 'oversized'])
def test_queue_protocol_and_cleanup(tmp_path, monkeypatch, outcome):
    monkeypatch.setenv('STOOLS_DOCUMENT_QUEUE', str(tmp_path))
    def worker_tick(_):
        request = next(tmp_path.iterdir())
        assert (request / 'ready').is_file()
        assert (request / 'input.doc').read_bytes() == b'legacy'
        if outcome == 'failed':
            (request / 'failed').touch()
        else:
            result = request / 'result.docx'
            if outcome == 'oversized':
                with result.open('wb') as out:
                    out.truncate(LIMIT + 1)
            else:
                result.write_bytes(b'converted')
            (request / 'done').touch()
    monkeypatch.setattr(conversion.time, 'sleep', worker_tick)
    if outcome == 'done':
        assert conversion.convert(b'legacy', '.doc') == b'converted'
    else:
        with pytest.raises(DocumentError):
            conversion.convert(b'legacy', '.doc')
    assert list(tmp_path.iterdir()) == []


def test_converter_timeout_cleans_request(tmp_path, monkeypatch):
    monkeypatch.setenv('STOOLS_DOCUMENT_QUEUE', str(tmp_path))
    ticks = iter([0, 101])
    monkeypatch.setattr(conversion.time, 'monotonic', lambda: next(ticks))
    with pytest.raises(conversion.ConversionUnavailable, match='100 секунд'):
        conversion.convert(b'legacy', '.doc')
    assert list(tmp_path.iterdir()) == []
