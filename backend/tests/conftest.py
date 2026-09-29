"""Общие фикстуры всех наборов тестов, в том числе тестовая база.

Тесты HTTP-слоя ходят в тот же Postgres, что и прод: SQLite слишком многое
прощает (переиспользование id, наивные datetime, отсутствие длин у varchar),
и зелёный прогон на нём ничего не говорил о работе на стенде. База —
одна на весь прогон pytest: контейнер поднимается лениво, при первом
запросе фикстуры, так что наборы без базы (`tests/analyzers`,
`tests/parsers`, `tests/attack`) остаются такими же быстрыми, как были.
"""
import atexit
import json
import os
import subprocess
import time
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path

# У настроек нет умолчания адреса базы (api/settings.py), а часть модулей
# собирает приложение уже при импорте — раньше, чем фикстура поднимет
# тестовый Postgres. Заглушка нужна только для сборки; фикстура базы ниже
# перезаписывает переменную настоящим адресом.
os.environ.setdefault("STOOLS_DATABASE_URL", "postgresql+psycopg://stools@localhost:5432/stools_tests_unset")

import pytest
from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy import text as sql_text

BACKEND_DIR = Path(__file__).resolve().parent.parent

#: Тот же образ, что и в ops/docker-compose.yml: тесты проверяют схему и
#: поведение ровно той версии сервера, которая стоит на стенде.
POSTGRES_IMAGE = "postgres:16-alpine"
POSTGRES_USER = "stools"
POSTGRES_PASSWORD = "stools"
POSTGRES_DB = "stools_test"

#: Сколько ждать готовности сервера в контейнере, секунд.
READY_TIMEOUT = 30.0


def _docker(*args: str) -> str:
    """Вызов docker; при ошибке падаем с stderr в тексте исключения."""
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker {' '.join(args)} завершился с кодом {result.returncode}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout.strip()


def _wait_ready(url: str) -> None:
    """Ждём, пока сервер начнёт принимать соединения."""
    import psycopg

    deadline = time.monotonic() + READY_TIMEOUT
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            # psycopg не понимает префикс диалекта SQLAlchemy.
            with psycopg.connect(url.replace("postgresql+psycopg://", "postgresql://"), connect_timeout=2):
                return
        except psycopg.OperationalError as exc:  # сервер ещё поднимается
            last = exc
            time.sleep(0.3)
    raise RuntimeError(f"Postgres не поднялся за {READY_TIMEOUT:.0f} с: {last}")


@pytest.fixture(scope="session")
def postgres_url() -> Iterator[str]:
    """URL тестовой базы: свой контейнер на весь прогон или чужой сервер.

    `STOOLS_TEST_DATABASE_URL` берётся как есть — это путь для CI и для
    уже поднятого сервера. Схема в такой базе всё равно пересоздаётся
    миграциями, а таблицы чистятся между тестами, поэтому указывать нужно
    одноразовую базу, а не рабочую.
    """
    external = os.environ.get("STOOLS_TEST_DATABASE_URL")
    if external:
        yield external
        return

    try:
        container = _docker(
            "run", "-d", "--rm",
            "-e", f"POSTGRES_USER={POSTGRES_USER}",
            "-e", f"POSTGRES_PASSWORD={POSTGRES_PASSWORD}",
            "-e", f"POSTGRES_DB={POSTGRES_DB}",
            "-p", "127.0.0.1:0:5432",
            POSTGRES_IMAGE,
            # Тестовой базе незачем переживать выключение питания.
            "-c", "fsync=off", "-c", "full_page_writes=off",
            "-c", "synchronous_commit=off",
        )
    except (OSError, RuntimeError) as exc:
        raise RuntimeError(
            "не удалось поднять Postgres для тестов: "
            f"{exc}\nЛибо запустите docker, либо укажите готовую одноразовую "
            "базу в STOOLS_TEST_DATABASE_URL."
        ) from None

    # Контейнер не должен пережить прерванный прогон: --rm снимает его при
    # штатной остановке, atexit — при падении pytest между фикстурами.
    def cleanup() -> None:
        subprocess.run(
            ["docker", "rm", "-f", "-v", container],
            capture_output=True, text=True, check=False,
        )

    atexit.register(cleanup)
    try:
        # `docker port` отдаёт «127.0.0.1:54321» (и вторую строку для ::1).
        mapping = _docker("port", container, "5432").splitlines()[0]
        port = mapping.rsplit(":", 1)[1]
        url = (
            f"postgresql+psycopg://{POSTGRES_USER}:{POSTGRES_PASSWORD}"
            f"@127.0.0.1:{port}/{POSTGRES_DB}"
        )
        _wait_ready(url)
        yield url
    finally:
        cleanup()
        atexit.unregister(cleanup)


@pytest.fixture(scope="session")
def migrated_database(postgres_url: str) -> Iterator[Engine]:
    """Схема тестовой базы — из миграций, один раз на прогон.

    `create_all` по metadata был бы быстрее, но тогда цепочка миграций
    проверялась бы только на стенде. Здесь `alembic upgrade head`
    прогоняется на Postgres при каждом запуске тестов.
    """
    from alembic import command
    from alembic.config import Config

    # env.py читает URL из настроек приложения, поэтому подставляем его в
    # окружение процесса до вызова alembic (и оставляем: `app_settings`
    # выставляет то же значение).
    os.environ["STOOLS_DATABASE_URL"] = postgres_url
    command.upgrade(Config(str(BACKEND_DIR / "alembic.ini")), "head")

    engine = create_engine(postgres_url, future=True)
    try:
        yield engine
    finally:
        engine.dispose()


def truncate_all(engine: Engine) -> None:
    """Очистка базы между тестами: TRUNCATE всех таблиц, кроме alembic_version.

    Список таблиц берётся у сервера, а не из `Base.metadata`: так он полон
    независимо от того, чьи модели успел импортировать конкретный тест.
    """
    with engine.connect() as conn:
        tables = [t for t in inspect(conn).get_table_names() if t != "alembic_version"]
        if not tables:
            return
        names = ", ".join(f'"{t}"' for t in tables)
        conn.execute(sql_text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))
        conn.commit()


@pytest.fixture(scope="module")
def reference_zip() -> Path:
    """Настоящая выгрузка. Путь — в STOOLS_FIXTURE_ZIP, иначе тест пропускается."""
    raw = os.environ.get("STOOLS_FIXTURE_ZIP")
    if not raw:
        pytest.skip("STOOLS_FIXTURE_ZIP не задана — регрессионные тесты пропущены")
    path = Path(raw)
    if not path.is_file():
        pytest.skip(f"выгрузка не найдена: {path}")
    return path


#: Суффикс файла с эталонными числами: он лежит рядом с самим архивом.
NUMBERS_SUFFIX = ".numbers.json"


@pytest.fixture(scope="module")
def reference_numbers(reference_zip: Path) -> dict[str, int]:
    """Эталонные числа выгрузки — из файла рядом с архивом.

    Числа выведены из конкретной инсталляции и в репозиторий не попадают,
    как и сама выгрузка: рядом с архивом должен лежать файл с тем же
    именем и суффиксом `.numbers.json`.
    """
    path = reference_zip.with_name(reference_zip.name + NUMBERS_SUFFIX)
    if not path.is_file():
        pytest.skip(
            f"эталонных чисел нет: положите рядом с выгрузкой файл {path.name}"
        )
    numbers: dict[str, int] = json.loads(path.read_text(encoding="utf-8"))
    return numbers


@pytest.fixture
def synthetic_zip(tmp_path: Path) -> Callable[[dict[str, str]], Path]:
    """Фабрика: словарь «путь в архиве → содержимое» превращается в zip."""

    def build(members: dict[str, str], name: str = "kb.zip") -> Path:
        path = tmp_path / name
        with zipfile.ZipFile(path, "w") as zf:
            for member, text in members.items():
                zf.writestr(member, text)
        return path

    return build
