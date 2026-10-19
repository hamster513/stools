"""Библиотека хантов: проверки при сохранении, мягкое удаление и оживление по коду."""
from __future__ import annotations

import json

import pytest

from api.modules.siem.hunting.library import (
    HuntIn,
    LibraryError,
    QueryIn,
    create_hunt,
    delete_hunt,
    hunt_by_code,
    hunt_queries,
    list_hunts,
    set_enabled,
    set_query_enabled,
    technique_from_name,
    update_hunt,
)

LOGIN = "tester"


def _q(query_id: str = "Q1", **kw) -> QueryIn:
    base = {"query": "event_src.host = 'x'", "fields": "time, event_src.host", "fields_label": "Время, Хост"}
    return QueryIn(query_id=query_id, **{**base, **kw})


def _hunt(code: str = "TH-WIN-001", **kw) -> HuntIn:
    base = {"name": "Закрепление через заставку (T1546.002)", "queries": [_q()]}
    return HuntIn(code=code, **{**base, **kw})


def test_create_extracts_technique(db_session):
    hunt = create_hunt(db_session, _hunt(), LOGIN)
    assert hunt.technique_id == "T1546.002"
    assert hunt.updated_by == LOGIN
    [query] = hunt_queries(db_session, hunt)
    assert json.loads(query.fields_json) == ["time", "event_src.host"]
    assert json.loads(query.labels_json) == ["Время", "Хост"]


def test_technique_from_name_variants():
    assert technique_from_name("Что-то (T1059)") == "T1059"
    assert technique_from_name("Без техники") is None


def test_explicit_technique_wins_over_name(db_session):
    hunt = create_hunt(db_session, _hunt(technique_id="T1059"), LOGIN)
    assert hunt.technique_id == "T1059"


def test_duplicate_code_rejected(db_session):
    create_hunt(db_session, _hunt(), LOGIN)
    with pytest.raises(LibraryError, match="код занят"):
        create_hunt(db_session, _hunt(name="Другое"), LOGIN)


def test_empty_fields_rejected(db_session):
    with pytest.raises(LibraryError, match="поля запроса пусты"):
        create_hunt(db_session, _hunt(queries=[_q(fields=" , ")]), LOGIN)
    with pytest.raises(LibraryError, match="поля запроса пусты"):
        create_hunt(db_session, _hunt(queries=[_q(query="  ")]), LOGIN)
    assert hunt_by_code(db_session, "TH-WIN-001") is None


def test_duplicate_query_id_rejected(db_session):
    with pytest.raises(LibraryError, match="query_id повторяется"):
        create_hunt(db_session, _hunt(queries=[_q("Q1"), _q("Q1")]), LOGIN)


def test_bad_technique_rejected(db_session):
    with pytest.raises(LibraryError, match="техника"):
        create_hunt(db_session, _hunt(technique_id="1546"), LOGIN)


def test_update_replaces_queries_by_query_id(db_session):
    hunt = create_hunt(db_session, _hunt(queries=[_q("Q1"), _q("Q2"), _q("Q3")]), LOGIN)
    before = {q.query_id: q.id for q in hunt_queries(db_session, hunt)}
    data = _hunt(
        name="Новое имя",
        enabled=False,
        queries=[_q("Q2", query="other = 1", enabled=False, limit=100), _q("Q4")],
    )
    update_hunt(db_session, hunt, data.model_copy(update={"code": "ignored"}), "editor")
    db_session.expire_all()
    hunt = hunt_by_code(db_session, "TH-WIN-001")
    assert hunt is not None
    assert (hunt.name, hunt.enabled, hunt.updated_by) == ("Новое имя", False, "editor")
    queries = {q.query_id: q for q in hunt_queries(db_session, hunt)}
    assert list(queries) == ["Q2", "Q4"]  # Q1 и Q3 убраны правкой из интерфейса
    assert queries["Q2"].id == before["Q2"]  # тот же запрос, а не новый
    assert (queries["Q2"].query, queries["Q2"].limit, queries["Q2"].enabled) == ("other = 1", 100, False)
    assert queries["Q4"].enabled is True


def test_delete_is_soft_and_code_revives(db_session):
    hunt = create_hunt(db_session, _hunt(queries=[_q("Q1"), _q("Q2")]), LOGIN)
    set_enabled(db_session, hunt, False, LOGIN)
    delete_hunt(db_session, hunt, LOGIN)
    assert hunt.deleted_at is not None
    assert list_hunts(db_session) == []
    assert [h.code for h in list_hunts(db_session, include_deleted=True)] == ["TH-WIN-001"]
    assert hunt_by_code(db_session, "TH-WIN-001") is not None

    revived = create_hunt(db_session, _hunt(name="Вернулся", queries=[_q("Q1")]), LOGIN)
    assert revived.id == hunt.id
    assert revived.deleted_at is None
    assert revived.name == "Вернулся"
    assert revived.enabled is False  # включённость как была до удаления
    assert [q.query_id for q in hunt_queries(db_session, revived)] == ["Q1"]
    assert [h.code for h in list_hunts(db_session)] == ["TH-WIN-001"]


def test_set_query_enabled(db_session):
    hunt = create_hunt(db_session, _hunt(), LOGIN)
    [query] = hunt_queries(db_session, hunt)
    set_query_enabled(db_session, query, False, "editor")
    db_session.expire_all()
    [query] = hunt_queries(db_session, hunt)
    assert query.enabled is False
    assert hunt.updated_by == "editor"
