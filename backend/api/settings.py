"""Конфигурация HTTP-сервиса. Читается из переменных окружения (префикс
STOOLS_), значения по умолчанию годятся для локальной разработки и тестов.
"""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="STOOLS_", env_file=".env", extra="ignore")

    #: SQLAlchemy URL. Сервис рассчитан на Postgres — и в проде, и в
    #: тестах: SQLite прощает то, чего сервер не прощает (переиспользование
    #: id, наивные datetime, отсутствие длин у varchar), поэтому умолчание
    #: указывает на локальный Postgres, а не на файл рядом с каталогом.
    database_url: str = "postgresql+psycopg://kbaudit@localhost:5432/kbaudit"

    #: Каталог, куда сохраняются загруженные архивы (и кэш разбора).
    data_dir: Path = Path("./data")

    #: Срок жизни сессионной cookie — контракт фиксирует 12 часов.
    session_ttl_hours: int = 12

    session_cookie_name: str = "stools_session"
    #: Secure-флаг cookie. По умолчанию включён (инструмент хранит инвентарь
    #: инфраструктуры — модель доступа не слабее, чем к самому SIEM); для
    #: локальной разработки без TLS можно выключить через
    #: STOOLS_SESSION_COOKIE_SECURE=false.
    session_cookie_secure: bool = True

    #: Ключ шифрования секретов подключений (api/crypto.py). Пустой — секреты
    #: хранятся открытым текстом; с session_cookie_secure=true сервис при
    #: этом не стартует. Смена ключа делает сохранённые секреты нечитаемыми.
    session_secret: str = ""

    #: Откуда скачивается бандл ATT&CK по кнопке. Стенды без выхода наружу
    #: указывают свой зеркальный адрес через STOOLS_ATTACK_BUNDLE_URL.
    attack_bundle_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    )

    #: /docs, /redoc, /openapi.json закрыты по умолчанию (инструмент хранит
    #: инвентарь инфраструктуры, схема API наружу не нужна). Включать только
    #: для локальной отладки: STOOLS_EXPOSE_DOCS=true.
    expose_docs: bool = False

    @property
    def archive_dir(self) -> Path:
        return self.data_dir / "archives"


def get_settings() -> Settings:
    return Settings()
