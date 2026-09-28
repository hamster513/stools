"""Онлайн-загрузка бандла ATT&CK.

Скачанное не применяется само: сначала человек видит разницу с
действующей матрицей и подтверждает. До подтверждения выжимка лежит в
app_setting['attack.pending'] — один ожидающий бандл на систему, новая
загрузка замещает старый.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import tempfile
import zlib
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from api.db.models import AppSetting
from api.jobs import JobHandle
from api.modules.attack.services.attack_bundle import BundleDiff, accept, diff
from api.settings import get_settings
from kbaudit.attack.bundle import AttackBundle, load_bundle

PENDING_KEY = "attack.pending"
SOURCE_ONLINE = "online"

#: Предел размера бандла — общий для загрузки файлом и скачивания с сайта.
#: Полный enterprise-attack.json — около пятидесяти мегабайт; запас нужен
#: на рост, но не безграничный: разбор идёт в памяти процесса, который
#: обслуживает и всё остальное.
MAX_BUNDLE_BYTES = 120 * 1024 * 1024


class PendingMeta(BaseModel):
    """Шапка скачанного бандла: всё, что показывает карточка ожидания.

    Сам бандл сюда не входит — он мегабайтный, а на каждый заход
    в настройки нужна только эта шапка.
    """

    version: str | None  # NOSONAR(S8396) разбор сохранённых данных: поле обязательно
    downloaded_at: dt.datetime
    url: str
    diff: BundleDiff


def download(
    url: str,
    to_path: Path,
    handle: JobHandle,
    http: httpx.Client | None = None,
    max_bytes: int | None = None,
) -> int:
    """Скачать файл, отмечая прогресс в строке задачи.

    Свой клиент закрывается здесь же; переданный принадлежит вызывающему
    и не закрывается — он мог завести его на несколько загрузок.

    Считаем скачанное сами: content-length сервер присылает не всегда,
    а сбитый адрес может отдавать поток без конца.
    """
    size = 0
    with ExitStack() as stack:
        client = http or stack.enter_context(
            httpx.Client(timeout=600.0, follow_redirects=True)
        )
        with client.stream("GET", url) as r:
            if r.status_code != 200:
                raise ValueError(f"{url}: HTTP {r.status_code}")
            total = int(r.headers.get("content-length") or 0) or None
            with to_path.open("wb") as out:
                for chunk in r.iter_bytes():
                    out.write(chunk)
                    size += len(chunk)
                    if max_bytes is not None and size > max_bytes:
                        raise ValueError(
                            f"бандл больше {max_bytes // (1024 * 1024)} МБ"
                            " — проверьте адрес STOOLS_ATTACK_BUNDLE_URL"
                        )
                    handle.tick(size, total=total, message=f"скачано {size // 1_000_000} МБ")
    return size


def run_download(
    db: Session, handle: JobHandle, http_factory: Callable[[], httpx.Client] | None = None
) -> None:
    """Скачать бандл и отложить его до подтверждения.

    Действующая матрица не трогается: подмена молча — худший вариант,
    человек должен сперва увидеть, что именно приедет.
    """
    url = get_settings().attack_bundle_url
    handle.stage("download", message=url)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "enterprise-attack.json"
        download(
            url,
            path,
            handle,
            http_factory() if http_factory else None,
            max_bytes=MAX_BUNDLE_BYTES,
        )
        handle.stage("parse", message="разбор бандла")
        bundle = load_bundle(path)
    if not bundle.techniques:
        raise ValueError("в скачанном файле нет ни одной техники")
    handle.stage("diff", message="сравнение с действующей матрицей")
    meta = PendingMeta(
        version=bundle.version,
        downloaded_at=dt.datetime.now(dt.UTC),
        url=url,
        diff=diff(db, bundle),
    )
    row = db.get(AppSetting, PENDING_KEY) or AppSetting(key=PENDING_KEY)
    row.value_json = json.dumps(
        {
            "meta": json.loads(meta.model_dump_json()),
            "bundle_z": base64.b64encode(
                zlib.compress(bundle.model_dump_json().encode("utf-8"))
            ).decode("ascii"),
        }
    )
    db.add(row)
    db.commit()


def _stored(db: Session) -> dict[str, Any] | None:
    """Разобранная строка ожидания, если она есть и читается.

    Строку пишет только этот код, поэтому нечитаемая означает, что она от
    прежней версии выжимки или испорчена. Такая считается отсутствующей:
    показать «ничего не ждёт» честнее, чем пятисотку на каждый заход
    в настройки, из которой человеку не выбраться. `DELETE /pending`
    её уберёт.
    """
    row = db.get(AppSetting, PENDING_KEY)
    if row is None or row.value_json in ("", "{}"):
        return None
    try:
        raw = json.loads(row.value_json)
    except ValueError:
        return None
    return raw if isinstance(raw, dict) else None


def pending(db: Session) -> PendingMeta | None:
    """Шапка ожидающего подтверждения бандла, если он есть.

    Строки прежней версии хранили шапку вперемешку с бандлом — читаем
    и такие: обновление продукта не должно терять уже скачанное.
    """
    raw = _stored(db)
    if raw is None:
        return None
    try:
        return PendingMeta.model_validate(raw.get("meta", raw))
    except ValidationError:
        return None


def pending_bundle(db: Session) -> AttackBundle | None:
    """Сам ожидающий бандл. Разворачивается только ради применения."""
    raw = _stored(db)
    if raw is None:
        return None
    packed = raw.get("bundle_z")
    try:
        if isinstance(packed, str):
            return AttackBundle.model_validate_json(
                zlib.decompress(base64.b64decode(packed))
            )
        if "bundle" in raw:  # прежняя форма: бандл лежал рядом с шапкой
            return AttackBundle.model_validate(raw["bundle"])
    except (ValidationError, ValueError, zlib.error):
        return None
    return None


def discard_pending(db: Session) -> None:
    """Отказаться от скачанного."""
    row = db.get(AppSetting, PENDING_KEY)
    if row is not None:
        db.delete(row)
        db.commit()


def apply_pending(db: Session, login: str | None) -> BundleDiff:
    """Принять скачанное. Разница считается заново: матрица могла смениться
    файлом, пока бандл ждал."""
    waiting = pending_bundle(db)
    if waiting is None:
        raise ValueError("ожидающего бандла нет")
    summary = diff(db, waiting)
    accept(db, waiting, login, source=SOURCE_ONLINE)
    discard_pending(db)
    return summary
