from __future__ import annotations

import io
import json
import zipfile
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from api.db.models import AttackMarkup
from tests.api.conftest import META, upload_and_wait

#: Схема именования определяется по данным, а не задаётся шаблоном, поэтому
#: двух правил ей мало: разбиение на одну группу считается вырожденным
#: и отбрасывается. Двенадцать правил в трёх группах — минимум, на котором
#: схема `author/category/group/rule_id` уверенно опознаётся.
_GROUPS = (("HC", "002", 5), ("AC", "026", 4), ("HC", "006", 3))


def _grouped_zip(extra: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "taxonomy.json",
            json.dumps(
                {
                    "msgid": {},
                    "subject.account.name": {},
                    "dst.ip": {},
                    "_build_info": {"version": "t"},
                }
            ),
        )
        index = 0
        for category, group, count in _GROUPS:
            for i in range(count):
                index += 1
                uuid = f"{index:08d}-bb9e-4ee4-9262-6754b7ee28d2"
                base = f"correlation-rules/rules/correlation/{uuid}"
                zf.writestr(f"{base}/metainfo.yaml", META)
                # Первое правило каждой группы несёт захардкоженный адрес:
                # без единой находки нечем проверить маркировку в инвентаре.
                body = (
                    'event Start:\n    filter { msgid == "4688" and dst.ip == "10.20.30.40" }\n'
                    if i == 0
                    else 'event Start:\n    filter { msgid == "4688" }\n'
                )
                zf.writestr(f"{base}/DEMO_{category}_{group}_{i:03d}_Rule.co", body)
        if extra:
            uuid = "99999999-bb9e-4ee4-9262-6754b7ee28d2"
            base = f"correlation-rules/rules/correlation/{uuid}"
            zf.writestr(f"{base}/metainfo.yaml", META)
            zf.writestr(
                f"{base}/DEMO_HC_002_099_Extra.co",
                'event Start:\n    filter { msgid == "4625" }\n',
            )
    return buf.getvalue()


@pytest.fixture
def snapshot_id(auth_client: TestClient) -> int:
    """Снапшот с опознаваемой схемой именования: двенадцать правил, три группы."""
    return int(upload_and_wait(auth_client, _grouped_zip())["snapshot_id"])


@pytest.fixture
def grouped_zip_v2() -> bytes:
    return _grouped_zip(extra=True)



# --------------------------------------------------------------------------
# Настройки
# --------------------------------------------------------------------------


def test_settings_default_to_unconfigured_model(auth_client: TestClient) -> None:
    """Пустой адрес — законное состояние, а не ошибка: без модели работает
    всё, кроме предложений по разметке."""
    assert auth_client.get("/api/settings/llm").json()["base_url"] == ""
    body = auth_client.get("/api/siem/settings").json()
    assert body["attack"]["attack_version"] == "19.2"


def test_settings_round_trip(auth_client: TestClient) -> None:
    llm_payload = {
        "base_url": "http://модель.invalid:11434",
        "model": "qwen3:8b-q4_K_M",
        "embed_model": "bge-m3",
        "think": False,
        "timeout": 60,
        "enabled": True,
    }
    assert auth_client.put("/api/settings/llm", json=llm_payload).status_code == 204
    assert auth_client.get("/api/settings/llm").json()["base_url"] == "http://модель.invalid:11434"

    assert auth_client.put("/api/siem/settings", json={"attack": {"top_k": 20}}).status_code == 204
    assert auth_client.get("/api/siem/settings").json()["attack"]["top_k"] == 20


def test_test_llm_without_address_does_not_reach_the_network(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Проверка пустого адреса обязана отвечать сразу, а не идти наружу."""
    import urllib.request

    def explode(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("обращение наружу при незаданном адресе")

    monkeypatch.setattr(urllib.request, "urlopen", explode)
    body = auth_client.post("/api/settings/llm/test", json={"base_url": "  "}).json()
    assert body["ok"] is False
    assert "не задан" in body["error"]


def test_test_llm_reports_failure_without_leaking_exception_text(
    auth_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Наружу уходит вид поломки, а не текст исключения: он несёт адрес
    и тело запроса, то есть выжимку по правилам."""
    import urllib.request

    def explode(*args: Any, **kwargs: Any) -> Any:
        raise OSError("Connection refused to 10.20.30.40:11434 while sending srv99")

    monkeypatch.setattr(urllib.request, "urlopen", explode)
    body = auth_client.post(
        "/api/settings/llm/test", json={"base_url": "http://x.invalid:11434"}
    ).json()
    assert body["ok"] is False
    assert "srv99" not in body["error"]
    assert "10.20.30.40" not in body["error"]


# --------------------------------------------------------------------------
# Запуск разметки
# --------------------------------------------------------------------------


def test_run_is_refused_while_the_model_is_not_configured(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Отказ явный, до создания задания: иначе о неработоспособности узнают
    через минуту по упавшему заданию."""
    response = auth_client.post("/api/siem/attack/run", json={"snapshot_id": snapshot_id})
    assert response.status_code == 409
    assert "настройках" in response.json()["detail"]


def test_leak_guard_keeps_the_payload_off_the_wire(
    auth_client: TestClient, snapshot_id: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Выжимка, не прошедшая проверку, наружу не уходит вовсе.

    Проверка стоит до первого обращения с текстом выжимки не по стилю,
    а по существу: выгрузка — инвентарь внутренней инфраструктуры, и цена
    ошибки в том, что он уедет к модели.

    Отправка описаний техник при этом утечкой не является: это публичные
    данные MITRE, вложенные в образ. Разделять эти два обращения и надо.
    """
    import api.modules.siem.services.attack as service

    embedded: list[str] = []
    completed: list[str] = []

    def fake_embed(self: Any, texts: list[str]) -> list[list[float]]:
        embedded.extend(texts)
        return [[1.0, 0.0] for _ in texts]

    def fake_complete(self: Any, prompt: str, schema: Any) -> str:
        completed.append(prompt)
        return "{}"

    monkeypatch.setattr(service.OllamaEmbedder, "embed", fake_embed)
    monkeypatch.setattr(service.OllamaCompletion, "complete", fake_complete)

    def blocked(payload: Any, blocklist: Any) -> None:
        raise service.LeakGuardError("тест")

    monkeypatch.setattr(service, "assert_no_leak", blocked)

    auth_client.put(
        "/api/settings/llm", json={"base_url": "http://x.invalid:11434", "enabled": True}
    )
    auth_client.put("/api/siem/settings", json={"attack": {"top_k": 15}})
    response = auth_client.post("/api/siem/attack/run", json={"snapshot_id": snapshot_id})
    assert response.status_code == 202
    job = auth_client.get(f"/api/siem/jobs/{response.json()['job_id']}").json()
    assert job["status"] == "done", job

    # Наружу ушли только описания техник; ни одной строки из выгрузки
    # и ни одного обращения к генеративной модели.
    assert completed == []
    assert not any("4688" in text or "DEMO" in text for text in embedded)

    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    assert {g["status"] for g in groups["items"]} == {"unmapped"}


@pytest.mark.parametrize('task_routing', [False, True])
def test_markup_reaches_the_model_when_the_guard_passes(
    auth_client: TestClient, snapshot_id: int, monkeypatch: pytest.MonkeyPatch, task_routing: bool
) -> None:
    """Обратная сторона предыдущего теста: без него «ничего не ушло»
    неотличимо от «разметка вообще не работает»."""
    import api.modules.siem.services.attack as service

    def fake_embed(self: Any, texts: list[str]) -> list[list[float]]:
        if task_routing:
            assert self._settings.provider == 'ollama'
            assert self._settings.embed_model == 'separate-vectors'
        return [[1.0, 0.0] for _ in texts]

    def fake_complete(self: Any, prompt: str, schema: Any) -> str:
        if task_routing:
            assert self._settings.provider == 'deepseek'
            assert self._settings.model == 'separate-reasoner'
            assert self._settings.api_key.get_secret_value() == 'task-test-key'
        first = schema["properties"]["techniques"]["items"]["properties"]["technique_id"]["enum"][0]
        return json.dumps(
            {"techniques": [{"technique_id": first, "confidence": "низкая", "evidence": "тест"}]}
        )

    monkeypatch.setattr(service.OllamaEmbedder, "embed", fake_embed)
    monkeypatch.setattr(service.OllamaCompletion, "complete", fake_complete)

    auth_client.put(
        "/api/settings/llm", json={"base_url": "http://x.invalid:11434", "enabled": True}
    )
    if task_routing:
        response = auth_client.put('/api/settings/llm', json={
            'tasks': {'attack_embeddings': {'provider': 'ollama', 'model': 'separate-vectors'},
                      'attack_markup': {'provider': 'deepseek', 'model': 'separate-reasoner'}},
            'key_updates': {'deepseek': 'task-test-key'},
        })
        assert response.status_code == 204
    auth_client.put("/api/siem/settings", json={"attack": {"top_k": 5}})
    job_id = auth_client.post(
        "/api/siem/attack/run", json={"snapshot_id": snapshot_id}
    ).json()["job_id"]
    assert auth_client.get(f"/api/siem/jobs/{job_id}").json()["status"] == "done"

    body = auth_client.get(f"/api/siem/attack/coverage?snapshot_id={snapshot_id}").json()
    # Модель спрашивают по каждому правилу: выжимка по группе сливала
    # заголовки и описания всех её правил в одну, и сигнал размывался.
    assert body["suggested"] == 12
    assert body["techniques_covered"] >= 1
    # Разметка получена по самому правилу, наследованием она не является.
    assert body["inherited"] == 0

    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    first = groups["items"][0]
    assert first["techniques"][0]["source"] == "llm"
    # Кандидаты сохраняются: без них спорную разметку через полгода
    # не разобрать — они меняются вместе с бандлом, моделью и выжимкой.
    assert len(first["candidates"]) == 5


# --------------------------------------------------------------------------
# Покрытие, подтверждение, слой
# --------------------------------------------------------------------------


def test_coverage_says_the_model_is_not_configured(
    auth_client: TestClient, snapshot_id: int
) -> None:
    body = auth_client.get(f"/api/siem/attack/coverage?snapshot_id={snapshot_id}").json()
    assert body["llm_configured"] is False
    assert body["group_count"] == 3
    # Считается по правилам: единица разметки — правило, и «не размечено»
    # означает двенадцать нерешённых правил, а не три нетронутые группы.
    assert body["rule_count"] == 12
    assert body["unmapped"] == 12
    assert body["attack_version"] == "19.2"


def test_confirmation_records_who_and_when(
    auth_client: TestClient, snapshot_id: int, db_session: Any
) -> None:
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]

    response = auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "group": group, "techniques": ["T1047"]},
    )
    assert response.status_code == 204

    # Подтверждение группой записывается по правилам: единица разметки —
    # правило, а группа осталась лишь способом решить пачку одним движением.
    rows = db_session.query(AttackMarkup).filter_by(group_name=group).all()
    assert len(rows) > 1
    for row in rows:
        assert row.status == "confirmed"
        assert row.reviewed_by == "tester"
        assert row.reviewed_at is not None
        # Для каждого правила в отдельности решение не проверено.
        assert row.inherited is True


def test_unknown_technique_is_refused(auth_client: TestClient, snapshot_id: int) -> None:
    """Идентификатор не из бандла — это опечатка или устаревшая техника;
    записать её значит завести разметку, которую потом никто не найдёт."""
    response = auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "group": "DEMO/HC/002", "techniques": ["T9999"]},
    )
    assert response.status_code == 422
    assert "T9999" in response.json()["detail"]


def test_confirmed_markup_survives_a_new_snapshot(
    auth_client: TestClient, snapshot_id: int, grouped_zip_v2: bytes
) -> None:
    """Разметка привязана к группе, а не к загрузке: подтверждённая
    человеком работа обязана пережить следующую выгрузку."""
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]
    auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "group": group, "techniques": ["T1047"]},
    )

    second = upload_and_wait(auth_client, grouped_zip_v2, "kb2.zip")["snapshot_id"]
    again = auth_client.get(f"/api/siem/attack/groups?snapshot_id={second}").json()
    by_group = {g["group"]: g for g in again["items"]}
    assert by_group[group]["status"] == "confirmed"
    assert [t["technique_id"] for t in by_group[group]["techniques"]] == ["T1047"]


def test_rule_inherits_the_markup_of_its_group(
    auth_client: TestClient, snapshot_id: int
) -> None:
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]
    auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "group": group, "techniques": ["T1047"]},
    )

    rules = auth_client.get(f"/api/siem/rules?snapshot_id={snapshot_id}").json()
    item = rules["items"][0]
    assert item["attack"]["status"] == "confirmed"
    assert item["attack"]["techniques"][0]["technique_id"] == "T1047"
    assert item["attack"]["techniques"][0]["tactics"] == ["execution"]

    detail = auth_client.get(
        f"/api/siem/rules/{item['uuid']}?snapshot_id={snapshot_id}"
    ).json()
    assert detail["attack"]["techniques"][0]["name_ru"]


def test_layer_carries_legend_and_categorical_colour(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Слой открывают в чужом инструменте, где нет ни этого интерфейса,
    ни объяснения, чем предложение модели отличается от подтверждения."""
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    auth_client.post(
        "/api/siem/attack/confirm",
        json={
            "snapshot_id": snapshot_id,
            "group": groups["items"][0]["group"],
            "techniques": ["T1047"],
        },
    )
    layer = auth_client.get(f"/api/siem/attack/layer/{snapshot_id}").json()
    assert layer["versions"]["navigator"] == "4.5"
    assert layer["versions"]["attack"] == "19.2"
    assert [t["techniqueID"] for t in layer["techniques"]] == ["T1047"]
    assert len(layer["legendItems"]) >= 2
    assert all(item["label"] for item in layer["legendItems"])


def test_technique_reference_is_in_russian(auth_client: TestClient) -> None:
    body = auth_client.get("/api/attack/techniques?q=T1003.001").json()
    assert body["items"][0]["name_ru"] == "Память LSASS"
    assert body["items"][0]["is_subtechnique"] is True


def test_matrix_shows_the_uncovered_part_too(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Смысл матрицы — видеть незакрытое. Матрица из одних лишь закрытых
    техник превращается в список достижений."""
    body = auth_client.get("/api/attack/matrix").json()
    tactics = body["tactics"]
    assert [t["shortname"] for t in tactics[:3]] == [
        "reconnaissance",
        "resource-development",
        "initial-access",
    ], "порядок колонок задан MITRE и несёт смысл — это последовательность шагов атаки"
    assert sum(len(t["techniques"]) for t in tactics) > 200
    assert all(t["covered"] == 0 for t in tactics), "разметки ещё нет"


def test_matrix_marks_confirmed_technique(auth_client: TestClient, snapshot_id: int) -> None:
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]
    auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "group": group, "techniques": ["T1047"]},
    )
    body = auth_client.get("/api/attack/matrix").json()
    execution = next(t for t in body["tactics"] if t["shortname"] == "execution")
    cell = next(c for c in execution["techniques"] if c["technique_id"] == "T1047")
    assert cell["layers"]["siem"]["status"] == "confirmed"
    assert cell["layers"]["siem"]["count"] == 1
    assert execution["covered"] == 1


def test_matrix_does_not_expand_subtechniques(auth_client: TestClient, snapshot_id: int) -> None:
    """475 подтехник против 222 техник: развёрнутые, они дают колонки
    высотой в экран. Число подтехник у ячейки при этом сообщается."""
    body = auth_client.get("/api/attack/matrix").json()
    ids = [c["technique_id"] for t in body["tactics"] for c in t["techniques"]]
    assert not any("." in i for i in ids)
    execution = next(t for t in body["tactics"] if t["shortname"] == "execution")
    cell = next(c for c in execution["techniques"] if c["technique_id"] == "T1059")
    assert cell["subtechnique_count"] > 5


def test_findings_can_be_narrowed_to_one_rule(auth_client: TestClient, snapshot_id: int) -> None:
    """Инвентарь правил открывает разбор находок по выбранному правилу —
    по идентификатору, а не по имени: на имена полагаться нельзя."""
    rules = auth_client.get(f"/api/siem/rules?snapshot_id={snapshot_id}").json()
    target = next(r for r in rules["items"] if r["open_finding_count"] > 0)
    body = auth_client.get(
        f"/api/siem/findings?snapshot_id={snapshot_id}&object_uuid={target['uuid']}"
    ).json()
    assert body["total"] == target["open_finding_count"]
    assert {f["object_uuid"] for f in body["items"]} == {target["uuid"]}


def test_accepted_finding_stops_demanding_attention(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Принятая находка — это уже принятое решение, а не долг. Иначе
    маркировка в инвентаре никогда не гаснет, и её перестают замечать."""
    rules = auth_client.get(f"/api/siem/rules?snapshot_id={snapshot_id}").json()
    target = next(r for r in rules["items"] if r["open_finding_count"] > 0)
    before = target["open_finding_count"]

    finding = auth_client.get(
        f"/api/siem/findings?snapshot_id={snapshot_id}&object_uuid={target['uuid']}"
    ).json()["items"][0]
    accepted = auth_client.put(
        "/api/findings/state",
        json={"module": "siem", "scope_id": 0, "key": finding["key"], "status": "risk_accepted", "comment": "проверено"},
    )
    assert accepted.status_code == 200, accepted.text

    again = auth_client.get(f"/api/siem/rules?snapshot_id={snapshot_id}").json()
    after = next(r for r in again["items"] if r["uuid"] == target["uuid"])
    assert after["open_finding_count"] == before - 1


def _configure_model(auth_client: TestClient) -> None:
    auth_client.put(
        "/api/settings/llm", json={"base_url": "http://x.invalid:11434", "enabled": True}
    )
    auth_client.put("/api/siem/settings", json={"attack": {"top_k": 5}})


def _mark_everything(
    auth_client: TestClient, snapshot_id: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Первый прогон: модель отвечает по всем группам."""
    import api.modules.siem.services.attack as service

    monkeypatch.setattr(
        service.OllamaEmbedder, "embed", lambda self, texts: [[1.0, 0.0] for _ in texts]
    )
    monkeypatch.setattr(
        service.OllamaCompletion,
        "complete",
        lambda self, prompt, schema: json.dumps(
            {
                "techniques": [
                    {
                        "technique_id": schema["properties"]["techniques"]["items"][
                            "properties"
                        ]["technique_id"]["enum"][0],
                        "confidence": "высокая",
                        "evidence": "тест",
                    }
                ]
            }
        ),
    )
    _configure_model(auth_client)
    job_id = auth_client.post(
        "/api/siem/attack/run", json={"snapshot_id": snapshot_id}
    ).json()["job_id"]
    assert auth_client.get(f"/api/siem/jobs/{job_id}").json()["status"] == "done"


def test_unreachable_model_does_not_erase_existing_markup(
    auth_client: TestClient, snapshot_id: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """«Модель недоступна» и «модель ничего не нашла» — разные вещи.

    На живом прогоне модель отвалилась на двадцать восьмой группе из сорока
    четырёх, и шестнадцать оставшихся были записаны как «не размечено»
    за сто сорок миллисекунд. Пробел в матрице читался как «техник нет»,
    а не как «спросить не удалось».
    """
    import api.modules.siem.services.attack as service

    _mark_everything(auth_client, snapshot_id, monkeypatch)
    before = auth_client.get(f"/api/siem/attack/coverage?snapshot_id={snapshot_id}").json()
    assert before["suggested"] == 12

    def dead(self: Any, *args: Any, **kwargs: Any) -> Any:
        raise service.ModelError("модель недоступна: URLError")

    monkeypatch.setattr(service.OllamaCompletion, "complete", dead)
    job_id = auth_client.post(
        "/api/siem/attack/run", json={"snapshot_id": snapshot_id}
    ).json()["job_id"]
    job = auth_client.get(f"/api/siem/jobs/{job_id}").json()

    assert job["status"] == "failed", "отвал модели обязан провалить задание, а не завершить его"
    assert "перестала отвечать" in job["error"]

    after = auth_client.get(f"/api/siem/attack/coverage?snapshot_id={snapshot_id}").json()
    assert after["suggested"] == before["suggested"], "прежняя разметка обязана остаться"
    assert after["unmapped"] == 0


def test_a_single_model_failure_is_reported_but_does_not_stop_the_run(
    auth_client: TestClient, snapshot_id: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Одиночный сбой бывает — таймаут, выгрузка весов. Останавливаться
    на нём значило бы не размечать ничего; молчать о нём — выдавать
    пробел за ответ модели."""
    import api.modules.siem.services.attack as service

    _configure_model(auth_client)
    monkeypatch.setattr(
        service.OllamaEmbedder, "embed", lambda self, texts: [[1.0, 0.0] for _ in texts]
    )

    calls = {"n": 0}

    def flaky(self: Any, prompt: str, schema: Any) -> str:
        calls["n"] += 1
        if calls["n"] == 1:
            raise service.ModelError("модель недоступна: TimeoutError")
        first = schema["properties"]["techniques"]["items"]["properties"]["technique_id"]["enum"][0]
        return json.dumps(
            {"techniques": [{"technique_id": first, "confidence": "низкая", "evidence": "тест"}]}
        )

    monkeypatch.setattr(service.OllamaCompletion, "complete", flaky)
    job_id = auth_client.post(
        "/api/siem/attack/run", json={"snapshot_id": snapshot_id}
    ).json()["job_id"]
    job = auth_client.get(f"/api/siem/jobs/{job_id}").json()

    assert job["status"] == "done"
    assert "не ответила по 1 правилам" in job["error"]

    coverage = auth_client.get(f"/api/siem/attack/coverage?snapshot_id={snapshot_id}").json()
    assert coverage["suggested"] == 11, "остальные правила размечены"


def test_empty_answer_does_not_erase_previous_markup(
    auth_client: TestClient, snapshot_id: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """«В этот раз модель ничего не выбрала» — не основание стереть то,
    что она выбрала в прошлый раз."""
    import api.modules.siem.services.attack as service

    _mark_everything(auth_client, snapshot_id, monkeypatch)
    monkeypatch.setattr(
        service.OllamaCompletion,
        "complete",
        lambda self, prompt, schema: json.dumps({"techniques": []}),
    )
    job_id = auth_client.post(
        "/api/siem/attack/run", json={"snapshot_id": snapshot_id}
    ).json()["job_id"]
    assert auth_client.get(f"/api/siem/jobs/{job_id}").json()["status"] == "done"

    coverage = auth_client.get(f"/api/siem/attack/coverage?snapshot_id={snapshot_id}").json()
    assert coverage["suggested"] == 12
    assert coverage["unmapped"] == 0


def test_technique_detail_tells_what_covers_it(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Одного названия в ячейке матрицы мало: нужно понять, что это за
    техника, есть ли внутри незакрытое и что её закрывает."""
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]
    auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "group": group, "techniques": ["T1059.001"]},
    )

    body = auth_client.get(
        "/api/attack/technique/T1059"
    ).json()
    assert body["name_ru"] == "Интерпретаторы команд и сценариев"
    assert body["description_ru"]
    assert body["covered"] is True, "подтехника закрывает родителя"
    assert body["layers"]["siem"]["status"] == "confirmed"

    # Подтехники видно все, и видно, какая из них закрыта.
    by_id = {s["technique_id"]: s for s in body["subtechniques"]}
    assert by_id["T1059.001"]["covered"] is True
    assert by_id["T1059.003"]["covered"] is False

    # Слой называет, чем именно техника закрыта, и даёт ссылку туда.
    items = body["layers"]["siem"]["items"]
    assert [i["title"] for i in items] == [group]
    # Ключ группы в ссылке закодирован: в нём есть слэши.
    assert parse_qs(urlparse(items[0]["href"]).query)["group"] == [group]


def test_technique_nobody_covers_says_so_plainly(
    auth_client: TestClient, snapshot_id: int
) -> None:
    body = auth_client.get("/api/attack/technique/T1486").json()
    assert body["covered"] is False
    assert body["layers"]["siem"] is None
    assert body["description_ru"], "описание есть даже у незакрытой техники"


def test_unknown_technique_detail_is_a_404(auth_client: TestClient, snapshot_id: int) -> None:
    assert (
        auth_client.get("/api/attack/technique/T9999").status_code
        == 404
    )


def test_group_detail_lists_its_rules_with_their_problems(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Решение о группе принимают, глядя на её правила. Список из одних
    имён для этого не годится: важно, что разобрано и где замечания."""
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]

    body = auth_client.get(
        f"/api/siem/attack/group?snapshot_id={snapshot_id}&group={group}"
    ).json()
    assert body["group"] == group
    assert len(body["rules"]) == body["rule_count"]
    assert body["with_findings"] >= 1
    assert body["unparsed"] == 0
    assert all("name" in r and "open_finding_count" in r for r in body["rules"])


def test_group_detail_of_a_missing_group_is_a_404(
    auth_client: TestClient, snapshot_id: int
) -> None:
    response = auth_client.get(
        f"/api/siem/attack/group?snapshot_id={snapshot_id}&group=НЕТ/ТАКОЙ/ГРУППЫ"
    )
    assert response.status_code == 404


def test_revoked_technique_is_carried_over_not_lost(
    auth_client: TestClient, snapshot_id: int, db_session: Any
) -> None:
    """Разметка отозванной техникой показывается перенесённой, а не пропавшей.

    В ATT&CK 19 семейство T1562 «Impair Defenses» отозвано целиком, и
    вся разметка по обходу защиты, подтверждённая на прошлой версии,
    иначе превратилась бы в «техники больше нет». MITRE оставляет
    указатель на замену, и пользоваться им дешевле, чем звать человека.

    Перенос именно показывается: в базе остаётся то, что подтвердил
    человек. Молча подменять чужое решение нельзя даже на правильное.
    """
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]
    rule_uuid = auth_client.get(
        f"/api/siem/attack/group?snapshot_id={snapshot_id}&group={group}"
    ).json()["rules"][0]["uuid"]
    row = AttackMarkup(
        rule_uuid=rule_uuid,
        group_name=group,
        status="confirmed",
        techniques_json=json.dumps([{"technique_id": "T1562.001", "confidence": "высокая"}]),
        attack_version="17.1",
    )
    db_session.add(row)
    db_session.commit()

    items = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()["items"]
    described = next(i for i in items if i["group"] == group)["techniques"][0]

    assert described["missing"] is False
    assert described["technique_id"] == "T1685"
    assert described["moved_from"] == "T1562.001"
    assert described["name"]

    stored = db_session.query(AttackMarkup).filter_by(rule_uuid=rule_uuid).one()
    assert "T1562.001" in stored.techniques_json


def test_empty_tactic_is_not_called_blind(auth_client: TestClient, snapshot_id: int) -> None:
    """Тактика без единой техники не помечается «ни одного правила».

    Пустая колонка — не слепая зона: покрывать в ней нечего, и красный
    заголовок над ней требует работы, которой не существует. Проверка
    отдельная, потому что `not any([])` истинно, и ошибка тихая.
    """
    matrix = auth_client.get("/api/attack/matrix").json()
    for tactic in matrix["tactics"]:
        if not tactic["techniques"]:
            assert tactic["blind"] is False, tactic["shortname"]
        elif tactic["blind"]:
            assert tactic["covered"] == 0


def test_parent_markup_is_shown_as_unrefined(
    auth_client: TestClient, snapshot_id: int, db_session: Any
) -> None:
    """Разметка родительской техникой не выдаётся за покрытие способа.

    Клетка матрицы от неё зелёная, но установлено лишь семейство приёма.
    На живой выгрузке все 95 указаний разметки — родительские, и ни одна
    подтехника внутри «закрытой» техники при этом не закрыта.
    """
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]
    rule_uuid = auth_client.get(
        f"/api/siem/attack/group?snapshot_id={snapshot_id}&group={group}"
    ).json()["rules"][0]["uuid"]
    db_session.add(
        AttackMarkup(
            rule_uuid=rule_uuid,
            group_name=group,
            status="confirmed",
            techniques_json=json.dumps([{"technique_id": "T1003", "confidence": "высокая"}]),
        )
    )
    db_session.commit()

    detail = auth_client.get("/api/attack/technique/T1003").json()
    assert detail["covered"] is True
    assert [i["title"] for i in detail["layers"]["siem"]["items"]] == [group]
    assert not any(s["covered"] for s in detail["subtechniques"])

    # Уточнение снимает признак: назван конкретный способ.
    auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "group": group, "techniques": ["T1003.001"]},
    )
    refined = auth_client.get("/api/attack/technique/T1003").json()
    assert [s["technique_id"] for s in refined["subtechniques"] if s["covered"]] == ["T1003.001"]


def test_subtechniques_are_ordered_by_prevalence(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Подтехники идут по распространённости, а не по номеру.

    У T1003 их восемь. Человеку, пришедшему уточнять разметку, важно
    с чего начать; нумерация MITRE об этом ничего не говорит.
    """
    detail = auth_client.get(
        "/api/attack/technique/T1003"
    ).json()
    subs = detail["subtechniques"]
    assert len(subs) > 3
    levels = [s["level"] for s in subs]
    assert levels == sorted(levels, reverse=True)

    # Числа именно подтехники, а не унаследованные от родителя: свёрнутые
    # они были бы у всех одинаковыми и ничего бы не подсказывали.
    assert len({s["actor_groups"] for s in subs}) > 1
    lsass = next(s for s in subs if s["technique_id"] == "T1003.001")
    assert lsass["actor_groups"] > 0


def test_rules_of_one_group_carry_different_techniques(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Правила одной группы могут быть размечены по-разному.

    Ради этого разметка и переехала с групп на правила. На выгрузке
    заказчика группа `DEMO/HC/002` содержит двадцать одно правило и
    девятнадцать разных техник по его собственной ручной разметке;
    одна запись на группу такого не выражает.
    """
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]
    rules = auth_client.get(
        f"/api/siem/attack/group?snapshot_id={snapshot_id}&group={group}"
    ).json()["rules"]
    assert len(rules) >= 2

    for rule, technique in zip(rules[:2], ["T1047", "T1059.001"], strict=True):
        assert (
            auth_client.post(
                "/api/siem/attack/confirm",
                json={
                    "snapshot_id": snapshot_id,
                    "rule_uuid": rule["uuid"],
                    "techniques": [technique],
                },
            ).status_code
            == 204
        )

    again = auth_client.get(
        f"/api/siem/attack/group?snapshot_id={snapshot_id}&group={group}"
    ).json()
    by_uuid = {r["uuid"]: r for r in again["rules"]}
    assert by_uuid[rules[0]["uuid"]]["techniques"] == ["T1047"]
    assert by_uuid[rules[1]["uuid"]]["techniques"] == ["T1059.001"]
    # Обе техники видны в своде группы, но группа не выдаёт себя
    # за размеченную целиком: остальные её правила не тронуты.
    assert {t["technique_id"] for t in again["techniques"]} == {"T1047", "T1059.001"}
    assert again["status"] == "unmapped"
    assert again["unmapped_rules"] == len(rules) - 2


def test_group_confirmation_is_marked_as_not_checked_per_rule(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Подтверждение группой помечается унаследованным, правилом — нет.

    Решение, принятое глядя на группу, ничего не утверждает о каждом
    её правиле в отдельности. Выдавать одно за другое — та же ложь,
    что родительская техника вместо подтехники.
    """
    groups = auth_client.get(f"/api/siem/attack/groups?snapshot_id={snapshot_id}").json()
    group = groups["items"][0]["group"]
    auth_client.post(
        "/api/siem/attack/confirm",
        json={"snapshot_id": snapshot_id, "group": group, "techniques": ["T1047"]},
    )
    rules = auth_client.get(
        f"/api/siem/attack/group?snapshot_id={snapshot_id}&group={group}"
    ).json()["rules"]
    assert all(r["inherited"] for r in rules)

    auth_client.post(
        "/api/siem/attack/confirm",
        json={
            "snapshot_id": snapshot_id,
            "rule_uuid": rules[0]["uuid"],
            "techniques": ["T1047"],
        },
    )
    refreshed = auth_client.get(
        f"/api/siem/attack/group?snapshot_id={snapshot_id}&group={group}"
    ).json()["rules"]
    by_uuid = {r["uuid"]: r for r in refreshed}
    assert by_uuid[rules[0]["uuid"]]["inherited"] is False
    assert all(by_uuid[r["uuid"]]["inherited"] for r in rules[1:])


def test_confirm_demands_exactly_one_target(
    auth_client: TestClient, snapshot_id: int
) -> None:
    """Ни правила, ни группы — записывать некуда; и то и другое — неясно куда."""
    for body in (
        {"snapshot_id": snapshot_id, "techniques": ["T1047"]},
        {
            "snapshot_id": snapshot_id,
            "group": "DEMO/HC/002",
            "rule_uuid": "нет-такого",
            "techniques": ["T1047"],
        },
    ):
        response = auth_client.post("/api/siem/attack/confirm", json=body)
        assert response.status_code == 422
