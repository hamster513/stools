"""Обновление матрицы ATT&CK.

Проверяется то, что дорого потерять: подтверждённая человеком разметка
и уже принятый перевод. Обновление матрицы не должно молча отменять
ни то ни другое.
"""
from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.db.models import AttackTranslation
from api.jobs import start_job
from api.modules.attack.models import AttackJob
from tests.api.conftest import upload_and_wait
from tests.api.test_attack_markup import _grouped_zip


@pytest.fixture
def snapshot_id(auth_client: TestClient) -> int:
    """Снапшот с опознаваемой схемой именования: без неё групп нет,
    а разметка ведётся по группам."""
    return int(upload_and_wait(auth_client, _grouped_zip())["snapshot_id"])


def bundle_file(techniques: list[dict[str, Any]], version: str = "20.0") -> bytes:
    """Минимальный STIX-бандл в форме, которую разбирает load_bundle."""
    objects: list[dict[str, Any]] = [
        {"type": "x-mitre-collection", "x_mitre_version": version},
        {
            "type": "x-mitre-tactic",
            "id": "tactic--exec",
            "name": "Execution",
            "x_mitre_shortname": "execution",
        },
        {
            "type": "x-mitre-matrix",
            "name": "Enterprise ATT&CK",
            "tactic_refs": ["tactic--exec"],
        },
    ]
    for t in techniques:
        objects.append(
            {
                "type": "attack-pattern",
                "name": t["name"],
                "description": t.get("description", ""),
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": t["id"]}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
            }
        )
    return json.dumps({"spec_version": "2.1", "objects": objects}).encode()


def upload(client: TestClient, data: bytes, preview: bool = False) -> dict[str, Any]:
    path = "/api/settings/attack/preview" if preview else "/api/settings/attack"
    response = client.post(path, files={"file": ("attack.json", data, "application/json")})
    assert response.status_code == 200, response.text
    return response.json()


def test_builtin_bundle_is_available_without_uploading_anything(
    auth_client: TestClient,
) -> None:
    body = auth_client.get("/api/settings/attack").json()
    assert body["source"] == "builtin"
    assert body["version"] == "19.2"
    assert body["technique_count"] == 697
    assert body["missing"] == 0, "поставка приходит переведённой"
    assert body["stale"] == 0


def test_preview_changes_nothing(auth_client: TestClient) -> None:
    """Посмотреть, что приедет, можно не принимая обновление."""
    data = bundle_file([{"id": "T1047", "name": "WMI", "description": "новое описание"}])
    diff = upload(auth_client, data, preview=True)
    assert diff["version"] == "20.0"
    assert diff["current_version"] == "19.2"
    assert auth_client.get("/api/settings/attack").json()["version"] == "19.2"


def test_diff_names_what_appeared_changed_and_disappeared(auth_client: TestClient) -> None:
    data = bundle_file(
        [
            {"id": "T1047", "name": "Windows Management Instrumentation", "description": "иное"},
            {"id": "T9001", "name": "Совсем новая техника"},
        ]
    )
    diff = upload(auth_client, data, preview=True)
    assert "T9001" in diff["added"]
    assert "T1047" in diff["changed"], "описание изменилось — перевод устарел"
    assert "T1003" in diff["removed"]
    assert diff["tactics_removed"], "в подложном бандле одна тактика вместо пятнадцати"


def test_uploaded_bundle_becomes_the_working_matrix(auth_client: TestClient) -> None:
    data = bundle_file([{"id": "T9001", "name": "Новая техника", "description": "описание"}])
    upload(auth_client, data)
    state = auth_client.get("/api/settings/attack").json()
    assert state["source"] == "uploaded"
    assert state["version"] == "20.0"
    assert state["technique_count"] == 1

    # Матрица и справочник идут по принятой версии, а не по вложенной.
    matrix = auth_client.get("/api/attack/matrix")
    assert matrix.status_code == 200, matrix.text
    reference = auth_client.get("/api/attack/techniques?q=T9001").json()
    assert reference["items"][0]["technique_id"] == "T9001"


def test_upload_survives_a_restart(auth_client: TestClient) -> None:
    """Загруженная матрица живёт в базе: обычный перезапуск её не трогает."""
    import api.modules.attack.services.attack_bundle as service

    upload(auth_client, bundle_file([{"id": "T9001", "name": "Новая"}]))
    service.invalidate_cache()
    assert auth_client.get("/api/settings/attack").json()["version"] == "20.0"


def test_confirmed_markup_survives_a_bundle_update(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Обновление матрицы не стирает подтверждённую человеком разметку:
    она привязана к идентификатору техники, а не к версии бандла."""
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]
    auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "group": group, "techniques": ["T1047"]},
    )

    upload(auth_client, bundle_file([{"id": "T9001", "name": "Новая"}]))
    again = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    row = next(g for g in again["items"] if g["group"] == group)

    assert row["status"] == "confirmed"
    assert [t["technique_id"] for t in row["techniques"]] == ["T1047"]
    # Техники в новой матрице нет — это видно, а не угадывается по пустому
    # названию: иначе в интерфейсе остался бы голый идентификатор.
    assert row["techniques"][0]["missing"] is True
    assert row["version_outdated"] is True


def test_coverage_counts_what_needs_review_after_an_update(
    auth_client: TestClient, snapshot_id: int
) -> None:
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    auth_client.post(
        "/api/siem/attack/confirm",
        json={
            "snapshot_id": snapshot_id,
            "group": groups["items"][0]["group"],
            "techniques": ["T1047"],
        },
    )
    upload(auth_client, bundle_file([{"id": "T9001", "name": "Новая"}]))
    body = auth_client.get(f"/api/siem/attack/coverage?snapshot_id={snapshot_id}").json()
    # Считается по правилам: подтверждение группой записалось каждому её
    # правилу, и устареть при смене матрицы должно каждое.
    assert body["outdated_groups"] == 4
    assert body["missing_techniques"] == ["T1047"]


def test_manual_translation_is_not_overwritten_by_the_shipped_one(
    auth_client: TestClient, db_session: Any
) -> None:
    """Обновление софта не отменяет правку человека: у переводов разное
    происхождение, и правка человека выигрывает."""
    import api.modules.attack.services.attack_bundle as service

    auth_client.get("/api/settings/attack")
    row = db_session.get(AttackTranslation, "T1047")
    row.name_ru = "Моё название"
    row.origin = service.ORIGIN_MANUAL
    db_session.commit()

    bundle = service.current(db_session)
    service.seed_builtin_translations(db_session, bundle)
    db_session.expire_all()
    assert db_session.get(AttackTranslation, "T1047").name_ru == "Моё название"


def test_stale_translation_is_visible(auth_client: TestClient) -> None:
    """Устаревший перевод опаснее отсутствующего: отсутствие видно сразу,
    а устаревший выглядит нормальным русским текстом, просто описывает
    не ту технику."""
    data = bundle_file(
        [{"id": "T1047", "name": "Windows Management Instrumentation", "description": "иное"}]
    )
    upload(auth_client, data)
    state = auth_client.get("/api/settings/attack").json()
    assert state["stale"] == 1
    assert state["missing"] == 0

    pending = auth_client.get("/api/settings/attack/translation/gaps").json()
    assert pending["items"][0] == {
        "technique_id": "T1047",
        "name": "Windows Management Instrumentation",
        "reason": "stale",
    }


def test_translation_is_refused_while_the_model_is_not_configured(
    auth_client: TestClient,
) -> None:
    upload(auth_client, bundle_file([{"id": "T9001", "name": "Новая"}]))
    response = auth_client.post("/api/settings/attack/translate")
    assert response.status_code == 409
    assert "настройках" in response.json()["detail"]


def test_nothing_to_translate_is_refused_explicitly(auth_client: TestClient) -> None:
    """«Переводить нечего» — не то же самое, что «перевод не удался»."""
    auth_client.put(
        "/api/settings/llm", json={"base_url": "http://x.invalid:11434", "enabled": True}
    )
    response = auth_client.post("/api/settings/attack/translate")
    assert response.status_code == 409
    assert "нечего" in response.json()["detail"]


def test_second_translation_is_refused_while_the_first_runs(
    auth_client: TestClient, db_session: Any
) -> None:
    """Перевод идёт один: две задачи писали бы в одни и те же строки."""
    upload(auth_client, bundle_file([{"id": "T9001", "name": "Новая"}]))
    auth_client.put(
        "/api/settings/llm", json={"base_url": "http://x.invalid:11434", "enabled": True}
    )
    start_job(db_session, AttackJob, "translate", "tester")

    response = auth_client.post("/api/settings/attack/translate")
    assert response.status_code == 409
    assert response.json()["detail"] == "перевод уже идёт"


def test_model_translates_the_gaps(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch, db_session: Any
) -> None:
    import api.modules.attack.services.translate_job as service

    upload(auth_client, bundle_file([{"id": "T9001", "name": "Brand New", "description": "d"}]))
    auth_client.put(
        "/api/settings/llm", json={"base_url": "http://x.invalid:11434", "enabled": True}
    )

    def fake(self: Any, prompt: str, schema: Any) -> str:
        ids = schema["properties"]["techniques"]["items"]["properties"]["technique_id"]["enum"]
        return json.dumps(
            {
                "techniques": [
                    {"technique_id": i, "name_ru": "Совсем новая", "description_ru": "перевод"}
                    for i in ids
                ]
            },
            ensure_ascii=False,
        )

    monkeypatch.setattr(service.OllamaCompletion, "complete", fake)
    response = auth_client.post("/api/settings/attack/translate")
    assert response.status_code == 202
    job = auth_client.get(f"/api/attack/jobs/{response.json()['job_id']}").json()
    assert job["status"] == "done", job

    import api.modules.attack.services.attack_bundle as bundle_service

    bundle_service.invalidate_cache()
    state = auth_client.get("/api/settings/attack").json()
    assert state["missing"] == 0 and state["stale"] == 0

    row = db_session.get(AttackTranslation, "T9001")
    assert row.name_ru == "Совсем новая"
    # Происхождение записано: перевод модели и перевод человека — разные
    # вещи, и на непроверенный перевод нужно смотреть иначе.
    assert row.origin == "llm"


def test_unreachable_model_does_not_erase_existing_translation(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch, db_session: Any
) -> None:
    """То же правило, что и в разметке: молчание модели не является
    утверждением, что перевода нет."""
    import api.modules.attack.services.translate_job as service

    upload(auth_client, bundle_file([{"id": "T1047", "name": "WMI", "description": "иное"}]))
    before = db_session.get(AttackTranslation, "T1047").name_ru
    assert before

    auth_client.put(
        "/api/settings/llm", json={"base_url": "http://x.invalid:11434", "enabled": True}
    )

    def dead(self: Any, *args: Any, **kwargs: Any) -> Any:
        raise service.ModelError("модель недоступна: URLError")

    monkeypatch.setattr(service.OllamaCompletion, "complete", dead)
    job_id = auth_client.post("/api/settings/attack/translate").json()["job_id"]
    job = auth_client.get(f"/api/attack/jobs/{job_id}").json()
    assert job["status"] == "failed"
    assert "ни одной техники" in job["error"]

    db_session.expire_all()
    assert db_session.get(AttackTranslation, "T1047").name_ru == before


def _replace_by_shipped(db_session: Any) -> None:
    """Смоделировать обновление софта: отпечаток вложенного бандла сменился."""
    import api.modules.attack.services.attack_bundle as service
    from api.db.models import AttackBundleRow

    row = db_session.get(AttackBundleRow, 1)
    row.builtin_fingerprint = "отпечаток прошлой поставки"
    db_session.commit()
    service.invalidate_cache()


def test_shipped_bundle_replaces_the_uploaded_one_and_says_so(
    auth_client: TestClient, db_session: Any
) -> None:
    """Заказчик загружал матрицу руками. Подмена молча — худший вариант:
    он увидел бы у себя другую версию без объяснения, откуда та взялась."""
    upload(auth_client, bundle_file([{"id": "T9001", "name": "Новая"}], version="20.0"))
    assert auth_client.get("/api/settings/attack").json()["version"] == "20.0"

    _replace_by_shipped(db_session)

    state = auth_client.get("/api/settings/attack").json()
    assert state["version"] == "19.2", "поставка перекрывает загруженное"
    assert state["source"] == "builtin"
    notice = state["replacement"]
    assert notice is not None
    assert notice["replaced_version"] == "20.0"
    assert notice["current_version"] == "19.2"
    # Откат назад выделяется отдельно: это не просто смена версии.
    assert notice["downgraded"] is True


def test_replacement_notice_is_not_shown_when_version_went_forward(
    auth_client: TestClient, db_session: Any
) -> None:
    upload(auth_client, bundle_file([{"id": "T9001", "name": "Старая"}], version="18.0"))
    _replace_by_shipped(db_session)
    notice = auth_client.get("/api/settings/attack").json()["replacement"]
    assert notice is not None, "о замене сообщаем в любом случае"
    assert notice["downgraded"] is False, "версия выросла — это не откат"


def test_notice_stays_until_dismissed(auth_client: TestClient, db_session: Any) -> None:
    upload(auth_client, bundle_file([{"id": "T9001", "name": "Новая"}], version="20.0"))
    _replace_by_shipped(db_session)

    assert auth_client.get("/api/settings/attack").json()["replacement"] is not None
    assert auth_client.get("/api/settings/attack").json()["replacement"] is not None

    assert auth_client.post("/api/settings/attack/notice/dismiss").status_code == 204
    assert auth_client.get("/api/settings/attack").json()["replacement"] is None


def test_uploading_again_clears_the_notice(auth_client: TestClient, db_session: Any) -> None:
    """Человек сам выбрал версию — напоминать о прошлой подмене незачем."""
    upload(auth_client, bundle_file([{"id": "T9001", "name": "Новая"}], version="20.0"))
    _replace_by_shipped(db_session)
    assert auth_client.get("/api/settings/attack").json()["replacement"] is not None

    upload(auth_client, bundle_file([{"id": "T9002", "name": "Ещё новее"}], version="21.0"))
    state = auth_client.get("/api/settings/attack").json()
    assert state["version"] == "21.0"
    assert state["replacement"] is None


def test_ordinary_restart_replaces_nothing(auth_client: TestClient) -> None:
    """Отпечаток вложенного бандла не менялся — значит софт не обновляли,
    и загруженную матрицу трогать не за что."""
    import api.modules.attack.services.attack_bundle as service

    upload(auth_client, bundle_file([{"id": "T9001", "name": "Новая"}], version="20.0"))
    for _ in range(3):
        service.invalidate_cache()
        state = auth_client.get("/api/settings/attack").json()
    assert state["version"] == "20.0"
    assert state["source"] == "uploaded"
    assert state["replacement"] is None


def test_subtechnique_counts_as_coverage_of_its_parent(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Человек, уточнивший разметку до подтехники, закрыл технику точнее,
    а не перестал её закрывать. Без этого правка разметки в сторону
    точности выглядела бы в матрице как её отсутствие."""
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]
    response = auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "group": group, "techniques": ["T1021.001"]},
    )
    assert response.status_code == 204

    matrix = auth_client.get("/api/attack/matrix").json()
    cells = {c["technique_id"]: c for t in matrix["tactics"] for c in t["techniques"]}
    assert cells["T1021"]["layers"]["siem"]["status"] == "confirmed"
    assert cells["T1021"]["layers"]["siem"]["count"] == 1

    layer = auth_client.get(f"/api/siem/attack/layer/{snapshot_id}").json()
    assert [t["techniqueID"] for t in layer["techniques"]] == ["T1021"]

    coverage = auth_client.get(f"/api/siem/attack/coverage?snapshot_id={snapshot_id}").json()
    assert coverage["missing_techniques"] == [], "подтехника не «исчезнувшая техника»"
    assert coverage["by_tactic"].get("lateral-movement") == 1


def test_human_can_name_a_technique_the_model_never_offered(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Правка разметки — это не только вычёркивание предложенного.
    Модель могла не увидеть нужную технику вовсе."""
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]
    auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "group": group, "techniques": ["T1486"]},
    )
    again = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    row = next(g for g in again["items"] if g["group"] == group)
    assert [t["technique_id"] for t in row["techniques"]] == ["T1486"]
    # Происхождение записано: техника названа человеком, а не моделью.
    assert row["techniques"][0]["source"] == "manual"
