"""У ToolBox нет баз и выгрузок, которые устаревают: провайдер пуст, чтобы модуль был в реестре."""
from __future__ import annotations

from sqlalchemy.orm import Session

from api.platform.data_status import DataItem, register_data_status


def provide(db: Session) -> list[DataItem]:
    return []


register_data_status("toolbox", provide)
