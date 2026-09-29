"""Разбор claim со списком групп в форматах разных провайдеров."""
from __future__ import annotations

from api.oidc.login import claim_list


def test_groups_as_strings() -> None:
    assert claim_list({"groups": ["a", "b"]}, "groups") == ["a", "b"]


def test_group_as_single_string() -> None:
    assert claim_list({"groups": "a"}, "groups") == ["a"]


def test_missing_claim() -> None:
    assert claim_list({}, "groups") == []


def test_groups_as_objects_give_name_and_id() -> None:
    # Avanpost FAM отдаёт группы объектами: сопоставлять можно и по имени,
    # и по неизменному идентификатору.
    claims = {"groups": [
        {"id": "c071b828-49c6-4db9-97e8-604443f6bec3", "is_service": False, "name": "Local. Users"},
        {"id": "6badd038-63a5-44bd-80b5-cd8307f7b4af", "name": "Other"},
    ]}
    assert claim_list(claims, "groups") == [
        "Local. Users", "c071b828-49c6-4db9-97e8-604443f6bec3",
        "Other", "6badd038-63a5-44bd-80b5-cd8307f7b4af",
    ]


def test_object_without_name_or_id_is_skipped() -> None:
    assert claim_list({"groups": [{"is_service": True}, "plain"]}, "groups") == ["plain"]
