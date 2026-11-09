"""Imported VM findings and CVE publication evidence; no inference of compromise."""

from urllib.parse import urlencode

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.modules.vm.models import (
    VmCve,
    VmHost,
    VmHostCve,
    VmImage,
    VmImageCve,
    VmImport,
    VmRefNvd,
    VmRefState,
)
from api.modules.vm.trend_models import VmTrendEvidence, VmTrendIngestState, VmTrendPublication

from .lookup_types import LIMIT, Evidence, Group, facts, identity


def vm(db: Session, q: str, kind: str) -> list[Group]:
    imported = db.scalar(
        select(VmImport.finished_at)
        .order_by(VmImport.finished_at.desc(), VmImport.id.desc())
        .limit(1)
    )
    # VM stores FQDN in hostname. A short-name search can yield distinct hosts in different domains.
    match = identity(
        q,
        kind,
        name=func.split_part(VmHost.hostname, ".", 1),
        fqdn=VmHost.hostname,
        domain=func.substr(VmHost.hostname, func.strpos(VmHost.hostname, ".") + 1),
        ip=VmHost.ip,
    )
    if kind == "domain":
        match = match & (func.strpos(VmHost.hostname, ".") > 0)
    selected = select(VmHost)
    if kind == "cve":
        selected = selected.join(VmHostCve).where(VmHostCve.cve_id == q)
    else:
        selected = selected.where(match)
    rows = db.scalars(selected.order_by(VmHost.id).limit(LIMIT + 1))
    hosts = Group(
        id="vm_hosts",
        title="Хосты VM",
        note="VM хранит хосты с импортированными CVE; отсутствие хоста здесь не означает отсутствие уязвимостей.",
    ).fill(
        [
            Evidence(
                id=str(h.id),
                title=h.hostname or h.ip,
                reason="На хосте импортирована искомая CVE"
                if kind == "cve"
                else "Совпадение в инвентаре VM",
                source="VM",
                href="/vm/vulns?"
                + urlencode(
                    {"host_id": h.id, "status": "all", **({"cve": q} if kind == "cve" else {})}
                ),
                observed_at=imported,
                date_label="Последний импорт VM",
                facts=facts(IP=h.ip, ОС=h.os_name, Критичность=h.criticality, Зона=h.zone),
            )
            for h in rows
        ]
    )
    pairs = (
        select(VmHost, VmHostCve)
        .join(VmHostCve)
        .where(VmHostCve.cve_id == q if kind == "cve" else match)
    )
    pair_rows = db.execute(
        pairs.order_by(VmHostCve.risk.desc(), VmHost.id, VmHostCve.cve_id).limit(LIMIT + 1)
    )
    vulnerabilities = Group(
        id="vulnerabilities",
        title="Уязвимости хостов",
        note="Связи хост–CVE из импорта, включая находки с решениями аналитика. Текущий статус и подробности — в карточке VM.",
    ).fill(
        [
            Evidence(
                id=f"{h.id}:{p.cve_id}",
                title=f"{p.cve_id} · {h.hostname or h.ip}",
                reason="CVE присутствует в результатах импорта для этого хоста",
                source="VM",
                href="/vm/vulns?"
                + urlencode(
                    {
                        "host_id": h.id,
                        "cve": p.cve_id,
                        "status": "all",
                        "key": f"{h.hostname}|{h.ip}|{p.cve_id}",
                    }
                ),
                observed_at=imported,
                date_label="Последний импорт VM",
                facts=facts(**{"IP": h.ip, "Риск VM": p.risk}),
            )
            for h, p in pair_rows
        ]
    )
    return [hosts, vulnerabilities]


def cve(db: Session, q: str, kind: str) -> list[Group]:
    result = Group(
        id="cve",
        title="Сведения о CVE",
        note="Локальная база уязвимостей. Наличие записи не означает, что затронута наша инфраструктура.",
    )
    row = db.get(VmCve, q)
    ref = db.get(VmRefNvd, q)
    state = db.get(VmRefState, "nvd")
    if row or ref:
        values = {
            "CVSS": row.cvss
            if row
            else ((ref.cvss_v3 if ref.cvss_v3 is not None else ref.cvss_v2) if ref else None),
            "EPSS": row.epss if row else None,
            "CISA KEV": ("Да" if row.kev else "Нет в загруженных данных") if row else None,
            "Описание": (
                (row.description if row else None) or (ref.description if ref else "") or ""
            )[:1500],
        }
        result.fill(
            [
                Evidence(
                    id=q,
                    title=q,
                    reason="Точный идентификатор в локальной базе",
                    source="VM / NVD",
                    href="/vm/vulns?" + urlencode({"cve": q, "status": "all"}),
                    observed_at=state.loaded_at if state else None,
                    date_label="Загрузка NVD (обогащение обновляется отдельно)",
                    facts=facts(**values),
                )
            ]
        )
    return [result]


def images(db: Session, q: str, kind: str) -> list[Group]:
    rows = db.execute(
        select(VmImage, VmImageCve)
        .join(VmImageCve)
        .where(func.upper(VmImageCve.cve_id) == q)
        .order_by(VmImage.id, VmImageCve.package, VmImageCve.installed_version)
        .limit(LIMIT + 1)
    )
    return [
        Group(
            id="images",
            title="Уязвимости образов",
            note="Находки сканера образов; сами по себе не подтверждают запуск образа на хосте.",
        ).fill(
            [
                Evidence(
                    id=f"{i.id}:{v.package}:{v.installed_version}",
                    title=f"{i.project}/{i.repository}",
                    reason="CVE найдена в пакете образа",
                    source="Harbor / VM",
                    href=f"/vm/images/{i.id}?" + urlencode({"q": q}),
                    observed_at=i.scanned_at,
                    date_label="Сканирование образа",
                    facts=facts(
                        **{
                            "Пакет": v.package,
                            "Версия": v.installed_version,
                            "Исправлено в": v.fixed_version,
                            "Критичность": v.trivy_severity,
                            "Digest": i.digest,
                        }
                    ),
                )
                for i, v in rows
            ]
        )
    ]


def publications(db: Session, q: str, kind: str) -> list[Group]:
    result = Group(
        id="publications",
        title="Публикации об угрозе",
        note="Упоминание CVE в текущей загрузке публикаций. Это не подтверждение уязвимости наших систем. Ссылка открывает карточку угрозы.",
    )
    state = db.get(VmTrendIngestState, 1)
    if not state or not state.active_generation:
        result.note = "Действующая загрузка публикаций отсутствует."
        return [result]
    p = VmTrendPublication
    rows = db.execute(
        select(
            p.id, p.source_id, p.data["title"].astext, p.data["published_at"].astext, p.received_at
        )
        .join(VmTrendEvidence, VmTrendEvidence.publication_id == p.id)
        .where(
            VmTrendEvidence.card_id == q,
            p.generation == state.active_generation,
            p.retracted.is_(False),
        )
        .order_by(p.received_at.desc(), p.id.desc())
        .limit(LIMIT + 1)
    )
    result.fill(
        [
            Evidence(
                id=str(id_),
                title=title or q,
                reason="Публикация связана с точным идентификатором CVE",
                source=f"Публикации · {source}",
                href="/vm/trends?" + urlencode({"id": q}),
                observed_at=received,
                date_label="Получено коллектором",
                facts=facts(**{"Опубликовано (по источнику)": published}),
            )
            for id_, source, title, published, received in rows
        ]
    )
    return [result]
