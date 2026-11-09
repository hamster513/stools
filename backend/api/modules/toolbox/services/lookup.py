"""One entry point, independent permission check before reading each source."""

import datetime as dt

from sqlalchemy.orm import Session

from api.platform.services.access import Access, allows

from . import lookup_inventory as inventory
from . import lookup_vm
from .lookup_types import Group, LookupResult

SOURCES = (
    ("assets", [("assets", "Активы")], inventory.assets, False),
    ("ad", [("ad_domains", "Домены AD"), ("ad_hosts", "Компьютеры AD")], inventory.ad, False),
    ("ksc", [("antivirus", "Антивирус")], inventory.antivirus, False),
    (
        "vm",
        [("vm_hosts", "Хосты VM"), ("vulnerabilities", "Уязвимости хостов")],
        lookup_vm.vm,
        None,
    ),
    ("vm", [("cve", "Сведения о CVE")], lookup_vm.cve, True),
    ("vm", [("images", "Уязвимости образов")], lookup_vm.images, True),
    ("vm", [("publications", "Публикации об угрозе")], lookup_vm.publications, True),
)


def lookup(db: Session, query: str, kind: str, access: Access) -> LookupResult:
    groups: list[Group] = []
    for area, descriptors, handler, cve_only in SOURCES:
        if not allows(access, area, "read"):
            groups.extend(
                Group(id=id_, title=title, status="denied", note="Нет доступа к модулю-источнику.")
                for id_, title in descriptors
            )
        elif cve_only is not None and cve_only != (kind == "cve"):
            groups.extend(
                Group(
                    id=id_,
                    title=title,
                    status="not_applicable",
                    note="Источник не проверяется для этого типа запроса.",
                )
                for id_, title in descriptors
            )
        else:
            groups.extend(handler(db, query, kind))
    return LookupResult(query=query, kind=kind, searched_at=dt.datetime.now(dt.UTC), groups=groups)
