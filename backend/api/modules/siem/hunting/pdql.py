"""Сборка PDQL-запроса ханта ровно так, как это делает скрипт владельца.

Запрос ханта хранит только условие и список полей; полный PDQL строится
здесь одним местом, чтобы то, что аналитик проверил в скрипте, уходило в
MaxPatrol без отличий. Подписи столбцов выравниваются по числу полей, как
в скрипте: недостающая подпись — имя поля, лишние отбрасываются.
"""
from __future__ import annotations


def split_fields(fields: str) -> list[str]:
    return [f.strip() for f in fields.split(",") if f.strip()]


def align_labels(fields: list[str], labels: str) -> list[str]:
    given = [label.strip() for label in labels.split(",")] if labels.strip() else []
    return (given + fields[len(given):])[: len(fields)]


def build_pdql(query: str, fields: list[str]) -> str:
    return f"filter({query}) | select({', '.join(fields)}) | sort(time desc)"
