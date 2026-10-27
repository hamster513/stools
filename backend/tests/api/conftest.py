"""Инфраструктура тестов HTTP-слоя: тот же Postgres, что и в проде (см.
`tests/conftest.py`), свой временный каталог для архивов на каждый тест.

Переопределение — через переменные окружения (`STOOLS_DATABASE_URL`,
`STOOLS_DATA_DIR`), которые читает `api.settings.Settings`, плюс сброс
модульных синглтонов engine/sessionmaker в `api.db.base`: и обработчики
запросов (через `Depends(get_db)`), и фоновая обработка задания
(`api.modules.siem.services.ingest.process_upload`, которая вызывает `get_sessionmaker()`
напрямую, в обход DI — `BackgroundTasks` выполняется уже после того, как
FastAPI закрыл сессию запроса) в итоге смотрят в одну и ту же тестовую базу.

База одна на весь прогон, схема в ней разложена миграциями; изоляция
между тестами — TRUNCATE всех таблиц после каждого теста.
"""
from __future__ import annotations

import io
import json
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select

import api.db.base as db_base
import api.modules.ad.models
import api.modules.attack.models
import api.modules.ksc.models
import api.modules.siem.hunting.models
import api.modules.vm.models  # noqa: F401 — модели модулей должны быть в реестре
from api.db.models import AccessGroup, AccessMembership, AccessRole, AccessRoleLevel, AppUser
from api.platform.services.access import ensure_builtin
from api.security import hash_password
from tests.api.fake_oidc import FakeProvider
from tests.conftest import truncate_all

U1 = "000ffb49-bb9e-4ee4-9262-6754b7ee28d2"
U2 = "111ffb49-bb9e-4ee4-9262-6754b7ee28d3"

META = "ObjectId: LOC-CR-1\nOrigin: Local\n"

CO_WITH_LIST_DUP = """
event Start:
    filter { msgid == "4688" and subject.account.name == "srv99" }
query Q = select("h") from DEMO_Critical_Hosts_by_Rule
"""

CO_PLAIN = """
event Start:
    filter { msgid == "4624" and dst.ip == "10.20.30.40" }
"""

TEST_LOGIN = "tester"
TEST_PASSWORD = "correct horse battery staple"
#: Ключ шифрования секретов в тестах — фиксированная строка, не настоящий ключ.
TEST_SESSION_SECRET = "test-only-session-secret"


def _build_kb_zip(extra_rule: bool = False) -> bytes:
    """extra_rule=True добавляет третье правило, ничего не меняя в U1 —
    сумма прежних находок остаётся байт-в-байт той же, а sha256 архива
    другой. Нужно для проверки, что вердикт переживает новый снапшот
    (спека §4.2): ключ вердикта — (object_uuid, kind, field, value_hash),
    и правило U1 с его находкой между двумя загрузками не меняется."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "taxonomy.json",
            json.dumps(
                {
                    "msgid": {},
                    "subject.account.name": {},
                    "dst.ip": {},
                    "_build_info": {"version": "test-1.0"},
                }
            ),
        )
        zf.writestr(
            f"correlation-rules/rules/correlation/{U1}/metainfo.yaml", META
        )
        zf.writestr(
            f"correlation-rules/rules/correlation/{U1}/DEMO_HC_002_029_Impacket.co",
            CO_WITH_LIST_DUP,
        )
        zf.writestr(
            f"correlation-rules/rules/correlation/{U2}/metainfo.yaml", META
        )
        zf.writestr(
            f"correlation-rules/rules/correlation/{U2}/DEMO_HC_002_030_Other.co",
            CO_PLAIN,
        )
        zf.writestr(
            "correlation_defaults.json",
            json.dumps(
                {
                    "DEMO_Critical_Hosts_by_Rule": [{"host": "srv99"}],
                    # Колонка описания — самая частая в настоящей выгрузке:
                    # она есть в 86 списках из 170.
                    "DEMO_Hosts_with_notes": [
                        {"host": "srv01", "description": "согласовано, тикет 4242"}
                    ],
                }
            ),
        )
        if extra_rule:
            u3 = "222ffb49-bb9e-4ee4-9262-6754b7ee28d4"
            zf.writestr(f"correlation-rules/rules/correlation/{u3}/metainfo.yaml", META)
            zf.writestr(
                f"correlation-rules/rules/correlation/{u3}/DEMO_HC_002_031_Extra.co",
                'event Start:\n    filter { msgid == "4625" }\n',
            )
    return buf.getvalue()


@pytest.fixture
def kb_zip_bytes() -> bytes:
    """Синтетическая выгрузка: два правила, одна находка класса 1 (дублирует
    список) и одна находка класса 2 (внутренний IP)."""
    return _build_kb_zip()


@pytest.fixture
def kb_zip_bytes_v2() -> bytes:
    """Тот же U1 с той же находкой, плюс лишнее правило — другой sha256,
    та же находка по (object_uuid, kind, field, value)."""
    return _build_kb_zip(extra_rule=True)


@pytest.fixture(autouse=True)
def _reset_db_singletons() -> Iterator[None]:
    db_base._engine = None
    db_base._SessionLocal = None
    yield
    if db_base._engine is not None:
        db_base._engine.dispose()
    db_base._engine = None
    db_base._SessionLocal = None


@pytest.fixture
def app_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    postgres_url: str,
    migrated_database: Engine,
) -> Iterator[Any]:
    data_dir = tmp_path / "data"
    monkeypatch.setenv("STOOLS_DATABASE_URL", postgres_url)
    monkeypatch.setenv("STOOLS_DATA_DIR", str(data_dir))
    monkeypatch.setenv("STOOLS_SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv("STOOLS_SESSION_SECRET", TEST_SESSION_SECRET)
    # Синхронизацию Assets после импорта модуля API ведёт отдельным потоком; в тестах — на месте:
    # поток пережил бы тест и писал в базу, которую уже чистит TRUNCATE.
    monkeypatch.setattr("api.modules.assets.services.sync.spawn", lambda fn: fn())
    # Расписание истечения рисков, которое заводит старт API, в тестах не заводится: тесты
    # расписаний модулей считают строки platform_schedule. Его проверяет test_mine_and_expiry.py.
    monkeypatch.setattr("api.main.ensure_platform_schedules", lambda: None)
    # Так же расписания Threat Hunting: их проверяет tests/siem_hunting/test_dispatcher.py.
    monkeypatch.setattr("api.main.ensure_hunting_schedules", lambda: None)
    from api.settings import get_settings

    yield get_settings()
    # Соединения приложения возвращаем в сервер до TRUNCATE: незакрытая
    # сессия фоновой задачи держала бы блокировку на таблице.
    if db_base._engine is not None:
        db_base._engine.dispose()
    truncate_all(migrated_database)


@pytest.fixture
def db_session(app_settings: Any) -> Iterator[Any]:
    session = db_base.get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


#: Права пользователя теста: область → уровень (отсутствующая — `deny`).
Levels = dict[str, str]
#: Старые имена ролей — встроенные группы (их роли «Администратор», «Аналитик», «Аудитор»).
BUILTIN_GROUP_OF = {"admin": "Администраторы", "analyst": "Аналитики", "auditor": "Аудиторы"}


def _join(db: Any, user: AppUser, group: AccessGroup) -> None:
    db.add(AccessMembership(user_id=user.id, group_id=group.id))
    db.commit()


def _builtin_group(db: Any, role: str) -> AccessGroup:
    return db.scalars(select(AccessGroup).where(AccessGroup.name == BUILTIN_GROUP_OF[role])).one()


@pytest.fixture
def test_user(db_session: Any) -> AppUser:
    """Администратор: член встроенной группы «Администраторы». Сиды групп сносит TRUNCATE
    между тестами, поэтому они восстанавливаются здесь, до старта клиента."""
    ensure_builtin(db_session)
    user = AppUser(login=TEST_LOGIN, password_hash=hash_password(TEST_PASSWORD))
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    _join(db_session, user, _builtin_group(db_session, "admin"))
    return user


@pytest.fixture
def client(app_settings: Any) -> Iterator[TestClient]:
    from api.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth_client(client: TestClient, test_user: AppUser) -> TestClient:
    """Клиент с уже установленной сессионной cookie."""
    response = client.post(
        "/api/auth/login", json={"login": TEST_LOGIN, "password": TEST_PASSWORD}
    )
    assert response.status_code == 204, response.text
    return client


@pytest.fixture
def make_user(db_session: Any) -> Callable[[str, Levels | str], AppUser]:
    """Пользователь с паролем TEST_PASSWORD. `levels` — строка 'admin' | 'analyst' | 'auditor'
    (член встроенной группы) или словарь «область → уровень» (своя роль и группа с именем логина)."""

    def build(login: str, levels: Levels | str) -> AppUser:
        ensure_builtin(db_session)
        if isinstance(levels, str):
            group = _builtin_group(db_session, levels)
            role = levels
        else:
            access_role = AccessRole(
                name=login, description="", builtin=False,
                levels=[AccessRoleLevel(area=a, level=lv) for a, lv in levels.items()],
            )
            group = AccessGroup(name=login, source="local", role=access_role)
            db_session.add(group)
            # Старая колонка ещё читается находками; права по ней — самые узкие.
            role = "auditor"
        user = AppUser(login=login, password_hash=hash_password(TEST_PASSWORD), role=role)
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        _join(db_session, user, group)
        return user

    return build


def _login_for(levels: Levels | str) -> str:
    if isinstance(levels, str):
        return f"user-{levels}"
    return "user-" + ("-".join(f"{a}-{lv}" for a, lv in sorted(levels.items())) or "none")


@pytest.fixture
def client_as(
    app_settings: Any, make_user: Callable[[str, Levels | str], AppUser],
) -> Callable[[Levels | str], TestClient]:
    """Отдельный клиент, вошедший под новым пользователем с правами `levels` (как у make_user)."""
    from api.main import app

    def login(levels: Levels | str) -> TestClient:
        name = _login_for(levels)
        make_user(name, levels)
        client = TestClient(app)
        response = client.post("/api/auth/login", json={"login": name, "password": TEST_PASSWORD})
        assert response.status_code == 204, response.text
        return client

    return login


@pytest.fixture
def fam(monkeypatch: pytest.MonkeyPatch) -> FakeProvider:
    """Поддельный провайдер вместо сети: подменяет фабрику клиента в api.oidc.login."""
    from api.oidc import login as oidc_login
    from api.oidc import provider

    #: Кэш discovery и JWKS — модульный, между тестами он бы пережил смену ключа.
    provider.invalidate_cache()
    fake = FakeProvider()
    monkeypatch.setattr(oidc_login, "http_factory", fake.http_factory)
    return fake


@pytest.fixture
def oidc_enabled(auth_client: TestClient, fam: FakeProvider) -> FakeProvider:
    """Включённый вход через провайдера. Публичный адрес — https: по http
    настройки пускают только localhost, а TestClient зовётся testserver."""
    fam.redirect_uri = "https://testserver/api/auth/oidc/callback"
    body = {
        "enabled": True,
        "display_name": "FAM",
        "public_url": "https://testserver",
        "issuer_url": fam.issuer,
        "client_id": fam.client_id,
        "client_secret": fam.client_secret,
        "scopes": "openid profile groups",
        "groups_claim": "groups",
        "login_claim": "preferred_username",
        "name_claim": "name",
        "group_roles": [
            {"group": "stools-admins", "role": "admin"},
            {"group": "stools-analysts", "role": "analyst"},
            {"group": "stools-auditors", "role": "auditor"},
        ],
    }
    assert auth_client.put("/api/settings/oidc", json=body).status_code == 204
    return fam


def upload_and_wait(auth_client: TestClient, data: bytes, filename: str = "kb.zip") -> dict[str, Any]:
    """Загружает выгрузку и дожидается done — job(pending) -> ... -> job(done)
    выполняется синхронно в BackgroundTasks в пределах контекста
    `with TestClient(app)` (см. фикстуру client), так что на практике опрос
    ниже завершается с первой попытки; цикл — подстраховка, а не гонка."""
    response = auth_client.post(
        "/api/siem/snapshots",
        files={"file": (filename, data, "application/zip")},
    )
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()

    job = auth_client.get(f"/api/siem/jobs/{body['job_id']}").json()
    attempts = 0
    while job["status"] == "running" and attempts < 200:
        job = auth_client.get(f"/api/siem/jobs/{body['job_id']}").json()
        attempts += 1
    assert job["status"] == "done", job
    return body


def collect_and_wait(auth_client: TestClient) -> dict[str, Any]:
    """Запускает сбор из базы знаний и дожидается конца задачи: фон в TestClient
    выполняется синхронно, цикл — подстраховка."""
    response = auth_client.post("/api/siem/mp/collect")
    assert response.status_code == 202, response.text
    job_id = response.json()["job_id"]
    job = auth_client.get(f"/api/siem/jobs/{job_id}").json()
    attempts = 0
    while job["status"] == "running" and attempts < 200:
        job = auth_client.get(f"/api/siem/jobs/{job_id}").json()
        attempts += 1
    return dict(job)


@pytest.fixture
def snapshot_id(auth_client: TestClient, kb_zip_bytes: bytes) -> int:
    body = upload_and_wait(auth_client, kb_zip_bytes)
    return int(body["snapshot_id"])
