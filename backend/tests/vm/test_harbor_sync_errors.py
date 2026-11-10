"""Failure summaries must be useful without exposing Harbor responses or secrets."""
import json

import pytest

from api.hosts import NO_LINK, TLS_FAILED
from api.modules.vm.core.harbor import BAD_FORMAT, HarborError
from api.modules.vm.services.harbor_sync_errors import describe_error, errors_text, read_errors


@pytest.mark.parametrize("kind,status,expected", [
    (NO_LINK, None, "Нет связи"),
    (TLS_FAILED, None, "TLS"),
    (BAD_FORMAT, None, "формат"),
    ("HTTP 404", 404, "не найден"),
    ("HTTP 429", 429, "частоту"),
    ("upstream returned robot:top-secret at https://private.example", 418, "Не удалось"),
])
def test_details_roundtrip_without_raw_errors(kind: str, status: int | None, expected: str) -> None:
    detail = describe_error("project/repo", "artifacts", HarborError(kind, status))
    assert expected in (detail.reason or "")
    encoded = errors_text([detail.target], [detail])
    assert encoded and "top-secret" not in encoded and "private.example" not in encoded
    names, details = read_errors(encoded)
    assert names == [detail.target] and details == [detail]
    assert details[0].http_status == status


def test_corrupted_details_fall_back_without_losing_targets() -> None:
    names, details = read_errors(json.dumps({"errors": ["project"], "details": [{"stage": "invalid"}]}))
    assert names == ["project"]
    assert len(details) == 1 and details[0].reason is None
    assert "Повторите синхронизацию" in details[0].hint


def test_empty_success_does_not_store_error_payload() -> None:
    assert errors_text([], []) is None
    assert read_errors(None) == ([], [])
