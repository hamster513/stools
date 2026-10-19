"""YAML владельца: разбор, предпросмотр без удалений, применение с «интерфейс главнее», выгрузка."""
from __future__ import annotations

import json

import pytest

from api.modules.siem.hunting.library import (
    HuntIn,
    LibraryError,
    QueryIn,
    delete_hunt,
    hunt_by_code,
    hunt_queries,
    set_enabled,
    set_query_enabled,
    update_hunt,
)
from api.modules.siem.hunting.yaml_io import (
    apply_import,
    export_library_yaml,
    parse_library_yaml,
    preview_import,
)

LOGIN = "tester"

SAMPLE = """\
TH-WIN-001:
    name: Закрепление через заставку (T1546.002)
    description: Ищем подмену параметров заставки.
    query_list:
        - query_id: Q1
          query: "object.name = 'ScreenSaveTimeOut'"
          fields: time, event_src.host, subject.account.name
          fields_label: Время, Хост, УЗ
        - query_id: Q2
          query: "object.process.name endswith '.scr'"
          fields: time, object.process.cmdline
          fields_label: Время
          limit: 200
TH-WIN-002:
    name: Запуск через планировщик
    description: ""
    query_list:
        - query_id: Q1
          query: "object.name = 'schtasks'"
          fields: time, event_src.host
          fields_label: Время, Хост
        - query_id: Q2
          query: "object.name = 'at'"
          fields: time
          fields_label: Время, Лишняя, Ещё
"""


def _load(text: str = SAMPLE):
    return parse_library_yaml(text.encode())


def test_parse_owner_format():
    hunts = _load()
    assert [h.code for h in hunts] == ["TH-WIN-001", "TH-WIN-002"]
    first, second = hunts
    assert first.name == "Закрепление через заставку (T1546.002)"
    assert first.technique_id is None  # техника берётся из названия при сохранении
    assert [q.query_id for q in first.queries] == ["Q1", "Q2"]
    assert first.queries[0].fields == "time, event_src.host, subject.account.name"
    assert first.queries[1].limit == 200
    assert first.queries[0].limit is None
    assert len(second.queries) == 2


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "- a\n- b\n",
        "TH-X: 5\n",
        "TH-X:\n  name: n\n",
        "TH-X:\n  name: n\n  query_list: []\n",
        "TH-X:\n  name: n\n  query_list:\n    - query_id: Q1\n      query: ''\n      fields: time\n",
        "TH-X:\n  name: n\n  query_list:\n    - query_id: Q1\n      query: a\n      fields: ''\n",
        "TH-X:\n  name: n\n  query_list:\n    - query_id: Q1\n      query: a\n      fields: time\n      limit: много\n",
        "a: [unclosed\n",
    ],
)
def test_parse_rejects_broken_file(raw):
    with pytest.raises(LibraryError):
        parse_library_yaml(raw.encode())


def test_preview_classifies_new_changed_same(db_session):
    hunts = _load()
    apply_import(db_session, hunts[:1], set(), LOGIN)
    changed = _load(SAMPLE.replace("Ищем подмену", "Ищем изменение").replace("'.scr'", "'.exe'"))
    rows = {r.code: r for r in preview_import(db_session, changed)}
    assert rows["TH-WIN-002"].action == "new"
    assert rows["TH-WIN-001"].action == "changed"
    assert rows["TH-WIN-001"].changes == ["описание", "Q2 изменён"]

    rows = {r.code: r for r in preview_import(db_session, hunts)}
    assert rows["TH-WIN-001"].action == "same"
    assert rows["TH-WIN-002"].action == "new"


def test_preview_lists_new_and_missing_queries_and_revive(db_session):
    apply_import(db_session, _load(), set(), LOGIN)
    reduced = _load(SAMPLE.replace("        - query_id: Q2\n          query: \"object.process.name endswith '.scr'\"\n"
                                   "          fields: time, object.process.cmdline\n"
                                   "          fields_label: Время\n          limit: 200\n", ""))
    [row] = [r for r in preview_import(db_session, reduced) if r.code == "TH-WIN-001"]
    assert (row.action, row.changes) == ("same", ["Q2 нет в файле"])
    # запрос вне файла не требует замены: применение ничего не пропускает и ничего не удаляет
    assert apply_import(db_session, reduced, set(), LOGIN) == {"created": 0, "replaced": 0, "skipped": 0}
    queries = hunt_queries(db_session, hunt_by_code(db_session, "TH-WIN-001"))
    assert [q.query_id for q in queries] == ["Q1", "Q2"]

    extended = _load(SAMPLE + "        - query_id: Q3\n          query: z = 1\n          fields: time\n")
    [row] = [r for r in preview_import(db_session, extended) if r.code == "TH-WIN-002"]
    assert (row.action, row.changes) == ("changed", ["Q3 новый"])

    delete_hunt(db_session, hunt_by_code(db_session, "TH-WIN-001"), LOGIN)
    [row] = [r for r in preview_import(db_session, _load()) if r.code == "TH-WIN-001"]
    assert row.action == "revive"


def test_apply_creates_new_enabled_with_technique(db_session):
    result = apply_import(db_session, _load(), set(), LOGIN)
    assert result == {"created": 2, "replaced": 0, "skipped": 0}
    hunt = hunt_by_code(db_session, "TH-WIN-001")
    assert (hunt.enabled, hunt.technique_id) == (True, "T1546.002")
    queries = hunt_queries(db_session, hunt)
    assert [q.enabled for q in queries] == [True, True]
    assert json.loads(queries[1].labels_json) == ["Время", "object.process.cmdline"]  # подписи выровнены
    assert queries[1].limit == 200


def _edit_in_ui(db_session):
    """Хант правлен в интерфейсе: другой текст Q1, Q2 выключен, добавлен Q9."""
    apply_import(db_session, _load(), set(), LOGIN)
    hunt = hunt_by_code(db_session, "TH-WIN-001")
    _, q2 = hunt_queries(db_session, hunt)
    update_hunt(
        db_session,
        hunt,
        HuntIn(
            code=hunt.code,
            name=hunt.name,
            description=hunt.description,
            queries=[
                QueryIn(query_id="Q1", query="ui = 'edited'", fields="time", fields_label="Время"),
                QueryIn(query_id="Q2", query=q2.query, fields="time, object.process.cmdline",
                        fields_label="Время", limit=200, enabled=False),
                QueryIn(query_id="Q9", query="ui = 'added'", fields="time"),
            ],
        ),
        "editor",
    )
    set_query_enabled(db_session, hunt_queries(db_session, hunt)[1], False, "editor")


def test_apply_without_replace_keeps_ui_edits(db_session):
    _edit_in_ui(db_session)
    hunt = hunt_by_code(db_session, "TH-WIN-001")
    snapshot = [(q.query_id, q.query, q.fields_json, q.enabled) for q in hunt_queries(db_session, hunt)]
    assert snapshot[0][1] == "ui = 'edited'"

    result = apply_import(db_session, _load(), set(), LOGIN)

    assert result == {"created": 0, "replaced": 0, "skipped": 1}
    db_session.expire_all()
    hunt = hunt_by_code(db_session, "TH-WIN-001")
    assert [(q.query_id, q.query, q.fields_json, q.enabled) for q in hunt_queries(db_session, hunt)] == snapshot
    assert hunt.updated_by == "editor"


def test_apply_with_replace_updates_text_but_not_enabled(db_session):
    _edit_in_ui(db_session)

    result = apply_import(db_session, _load(), {"TH-WIN-001"}, LOGIN)

    assert result == {"created": 0, "replaced": 1, "skipped": 0}
    db_session.expire_all()
    hunt = hunt_by_code(db_session, "TH-WIN-001")
    queries = {q.query_id: q for q in hunt_queries(db_session, hunt)}
    assert queries["Q1"].query == "object.name = 'ScreenSaveTimeOut'"  # текст из файла
    assert queries["Q2"].enabled is False  # включённость из интерфейса не тронута
    assert queries["Q9"].query == "ui = 'added'"  # запрос, которого нет в файле, не удалён
    assert hunt.updated_by == LOGIN


def test_apply_revive_keeps_old_enabled_and_never_deletes(db_session):
    _edit_in_ui(db_session)
    hunt = hunt_by_code(db_session, "TH-WIN-001")
    set_enabled(db_session, hunt, False, LOGIN)
    delete_hunt(db_session, hunt, LOGIN)

    result = apply_import(db_session, _load(), set(), LOGIN)

    assert result == {"created": 1, "replaced": 0, "skipped": 0}
    db_session.expire_all()
    hunt = hunt_by_code(db_session, "TH-WIN-001")
    assert hunt.deleted_at is None
    assert hunt.enabled is False
    assert {q.query_id for q in hunt_queries(db_session, hunt)} == {"Q1", "Q2", "Q9"}


def test_export_roundtrip(db_session):
    apply_import(db_session, _load(), set(), LOGIN)
    raw = export_library_yaml(db_session)
    again = parse_library_yaml(raw)
    assert [h.code for h in again] == ["TH-WIN-001", "TH-WIN-002"]
    assert {r.action for r in preview_import(db_session, again)} == {"same"}
    assert "Закрепление через заставку" in raw.decode()  # кириллица читаема, без \u-escape


def test_export_includes_disabled_and_skips_deleted(db_session):
    apply_import(db_session, _load(), set(), LOGIN)
    set_enabled(db_session, hunt_by_code(db_session, "TH-WIN-001"), False, LOGIN)
    delete_hunt(db_session, hunt_by_code(db_session, "TH-WIN-002"), LOGIN)
    assert [h.code for h in parse_library_yaml(export_library_yaml(db_session))] == ["TH-WIN-001"]


def test_parse_rejects_absurd_limit():
    raw = SAMPLE.replace("limit: 200", "limit: 99999999999")
    with pytest.raises(LibraryError, match="предел событий"):
        parse_library_yaml(raw.encode())


def test_import_revive_keeps_manual_technique(db_session):
    apply_import(db_session, _load(), set(), LOGIN)
    hunt = hunt_by_code(db_session, "TH-WIN-001")
    hunt.technique_id = "T1000"
    db_session.commit()
    delete_hunt(db_session, hunt, LOGIN)

    apply_import(db_session, _load(), set(), LOGIN)

    db_session.expire_all()
    hunt = hunt_by_code(db_session, "TH-WIN-001")
    assert hunt.deleted_at is None
    assert hunt.technique_id == "T1000"  # в названии T1546.002, но вручную заданная техника главнее
