"""Сборка ParsedArchive: zip → модели. Здесь и только здесь известно,
как части выгрузки складываются в целое."""
from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath

from kbaudit.models import KbObject, ObjectType, ParsedArchive, ParseStatus, Rule
from kbaudit.parsers.archive import BODY_EXT_BY_TYPE, group_by_uuid, read_text
from kbaudit.parsers.i18n import Localization, parse_localization
from kbaudit.parsers.metainfo import parse_metainfo
from kbaudit.parsers.rule_body import body_hash, parse_rule_body
from kbaudit.parsers.tables import (
    load_table_lists,
    load_table_rows,
    load_table_values,
    load_values_by_table,
)
from kbaudit.parsers.taxonomy import load_taxonomy

#: Синтаксис .cojs отличается от .co; разбирать его пока не умеем и врать
#: об этом не будем (спека §4.3).
UNSUPPORTED_EXT = {".cojs"}

_PREFIX_BY_TYPE: dict[ObjectType, str] = {
    ObjectType.CORRELATION: "correlation-rules/",
    ObjectType.FILTER: "filters/",
    ObjectType.ENRICHMENT: "enrichment-rules/",
    ObjectType.AGGREGATION: "aggregation-rules/",
}


def _body_member(members: list[str], allowed: set[str]) -> str | None:
    for member in members:
        if PurePosixPath(member).suffix.lower() in allowed:
            return member
    return None


def _collect_bodies(zf: zipfile.ZipFile) -> list[KbObject]:
    bodies: list[KbObject] = []
    for object_type, prefix in _PREFIX_BY_TYPE.items():
        allowed = BODY_EXT_BY_TYPE[object_type]
        for uuid, members in group_by_uuid(zf, prefix).items():
            member = _body_member(members, allowed)
            if not member:
                continue
            path = PurePosixPath(member)
            bodies.append(
                KbObject(
                    uuid=uuid,
                    object_type=object_type,
                    name=path.stem,
                    body_text=read_text(zf, member),
                    body_ext=path.suffix.lower(),
                )
            )
    return bodies


def parse_archive(path: Path) -> ParsedArchive:
    with zipfile.ZipFile(path) as zf:
        taxonomy = load_taxonomy(zf)
        rules: list[Rule] = []

        for uuid, members in group_by_uuid(zf, "correlation-rules/").items():
            meta_member = next(
                (m for m in members if PurePosixPath(m).name == "metainfo.yaml"), None
            )
            meta = parse_metainfo(zf.read(meta_member)) if meta_member else None

            body_member = _body_member(members, BODY_EXT_BY_TYPE[ObjectType.CORRELATION])
            if not body_member:
                continue
            body_path = PurePosixPath(body_member)
            text = read_text(zf, body_member)

            # Локализация разбирается по именам узлов: заголовок правила
            # и шаблоны его сообщений — разные вещи, и второе описывает
            # суть детекта словами, а первое часто содержит служебный код.
            localizations: dict[str, Localization] = {}
            for member in members:
                name = PurePosixPath(member).name
                if name.startswith("i18n") and name.endswith(".xml"):
                    localizations[name] = parse_localization(zf.read(member))
            ru = localizations.get("i18n_ru.xml", Localization())
            en = localizations.get("i18n_en.xml", Localization())

            unsupported = body_path.suffix.lower() in UNSUPPORTED_EXT
            parsed_body = (
                parse_rule_body(text, taxonomy.fields) if not unsupported else None
            )

            rules.append(
                Rule(
                    uuid=uuid,
                    name=body_path.stem,
                    object_id=meta.object_id if meta else None,
                    origin=meta.origin if meta else None,
                    body_type=body_path.suffix.lstrip("."),
                    parse_status=(
                        ParseStatus.UNSUPPORTED if unsupported else ParseStatus.OK
                    ),
                    body_hash=body_hash(text),
                    title_ru=ru.title,
                    title_en=en.title,
                    descriptions_ru=ru.descriptions,
                    descriptions_en=en.descriptions,
                    **(parsed_body.model_dump() if parsed_body else {}),
                )
            )

        return ParsedArchive(
            taxonomy=taxonomy,
            rules=sorted(rules, key=lambda r: r.name),
            bodies=_collect_bodies(zf),
            table_values=load_table_values(zf),
            values_by_table=load_values_by_table(zf),
            table_rows=load_table_rows(zf),
            table_lists=load_table_lists(zf),
        )
