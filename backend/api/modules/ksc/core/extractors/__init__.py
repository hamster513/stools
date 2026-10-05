"""Извлекатели записей политики по продукту. Импорт пакета регистрирует их в `policy_model.EXTRACTORS`; пакет
импортирует `api.modules.ksc` (`__init__`), поэтому реестр заполнен при любом использовании модуля, а `policy_model`
сам извлекатели не импортирует — циклов нет."""
from __future__ import annotations

from api.modules.ksc.core.extractors.kes_windows import extract_kes
from api.modules.ksc.core.policy_model import EXTRACTORS

EXTRACTORS["KES"] = extract_kes

__all__ = ["extract_kes"]
