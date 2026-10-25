"""Реестр свежести данных: каждый модуль регистрирует провайдера строк «что и когда обновлялось».

Платформа ничего не знает о справочниках модулей: модуль сам отдаёт `DataItem` по своей
базе, а `collect` склеивает ответы в одну сводку для экрана настроек. Упавший провайдер не
роняет сводку — вместо его строк появляется одна строка-ошибка, остальные модули целы.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from sqlalchemy.orm import Session

Kind = Literal["reference", "snapshot", "source"]
State = Literal["fresh", "stale", "missing", "running"]


@dataclass(frozen=True)
class DataItem:
    module: str
    key: str
    title: str
    kind: Kind
    updated_at: dt.datetime | None
    state: State
    source: str | None
    detail: str
    #: Куда вести ссылку «Обновить» на экране настроек.
    anchor: str


Provider = Callable[[Session], list[DataItem]]

_PROVIDERS: dict[str, Provider] = {}


def register_data_status(module: str, provider: Provider) -> None:
    """Повторная регистрация того же модуля заменяет провайдера."""
    _PROVIDERS[module] = provider


def registered_modules() -> frozenset[str]:
    return frozenset(_PROVIDERS)


def count_ru(n: int, forms: tuple[str, str, str]) -> str:
    """«1 запись», «2 записи», «248 312 записей»: число с разрядами и слово в нужной форме."""
    n10, n100 = n % 10, n % 100
    if n10 == 1 and n100 != 11:
        word = forms[0]
    elif 2 <= n10 <= 4 and not 12 <= n100 <= 14:
        word = forms[1]
    else:
        word = forms[2]
    return f"{n:,}".replace(",", " ") + " " + word


def stale_after(updated_at: dt.datetime | None, days: int, *, running: bool = False) -> State:
    """Состояние по возрасту: идущее обновление важнее возраста; naive-время считается UTC."""
    if running:
        return "running"
    if updated_at is None:
        return "missing"
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=dt.UTC)
    return "stale" if dt.datetime.now(dt.UTC) - updated_at > dt.timedelta(days=days) else "fresh"


def _module_order() -> dict[str, int]:
    # Лениво: api.modules тянет все модули, а модули регистрируются в этот реестр.
    from api.modules import MODULE_ROUTERS

    return {router.prefix.split("/")[2]: i for i, router in enumerate(MODULE_ROUTERS)}


def collect(db: Session) -> list[DataItem]:
    """Строки всех модулей: сначала в порядке MODULE_ROUTERS, незнакомые — после, по имени."""
    order = _module_order()
    items: list[DataItem] = []
    for module in sorted(_PROVIDERS, key=lambda m: (order.get(m, len(order)), m)):
        try:
            items.extend(_PROVIDERS[module](db))
        except Exception as exc:  # noqa: BLE001 — сводка не должна падать из-за одного модуля
            # Ошибка SQL оставляет транзакцию прерванной: без отката все следующие провайдеры
            # получили бы ту же ошибку на общей сессии.
            if db is not None:
                db.rollback()
            items.append(
                DataItem(module, "error", module, "source", None, "missing", None, f"ошибка: {type(exc).__name__}", "")
            )
    return items
