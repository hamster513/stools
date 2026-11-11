"""Read-only assessment of Harbor's vulnerability gate, not pull authorization."""
from __future__ import annotations

import datetime as dt
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.modules.vm.models import VmHarborProjectPolicy, VmImage, VmImageCve

_RANK = {'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def evaluate(image: VmImage, snapshot: VmHarborProjectPolicy | None,
             findings: Iterable[tuple[str, str]], *, now: dt.datetime) -> dict[str, Any]:
    data = snapshot.data if snapshot and not snapshot.error else {}
    expiry = data.get('expires_at') or 0
    expired = bool(expiry and expiry <= now.timestamp())
    result = {'evaluated': False, 'state': 'unknown', 'reason': '', 'checked_at': snapshot.checked_at if snapshot else None,
                  'threshold': data.get('threshold'), 'enabled': data.get('enabled'),
                  'allowlist_source': data.get('allowlist_source'), 'allowlist_expires_at': expiry or None,
                  'allowlist_expired': expired, 'signature_required': data.get('signature_required', False),
                  'blocking_count': 0, 'excluded_count': 0, 'blocking_cves': [], 'excluded_cves': [],
                  'error': snapshot.error if snapshot else None}

    def done(state: str, reason: str) -> dict[str, Any]:
        return {**result, 'state': state, 'reason': reason}

    if image.artifact_kind in {'helm', 'other'}:
        return done('not_applicable', 'Артефакт не является контейнерным образом; оценка по отчёту образа не применяется.')
    if image.artifact_kind != 'image':
        return done('unknown', 'Тип артефакта ещё не определён. Выполните синхронизацию Harbor.')
    if not data or image.sync_error:
        return done('unknown', 'Не удалось обновить политику проекта или данные образа. Повторите синхронизацию Harbor.')
    if not data['enabled']:
        return done('allowed', 'В проекте отключена блокировка скачивания по уязвимостям.')
    if image.is_index:
        return done('unknown', 'Мультиархитектурный образ: Harbor проверяет манифест выбранной платформы. Общий отчёт не подтверждает скачивание каждой платформы.')
    if image.scan_status == 'none':
        return done('unknown', 'Нет скана: сканируемый образ Harbor заблокирует. Поддержка этого артефакта сканером не подтверждена.')
    if image.scan_status != 'success':
        return done('blocked', 'Блокировка по уязвимостям включена, но сканирование ещё не завершено успешно.')
    if not image.report_complete:
        return done('unknown', 'Данных отчёта недостаточно для надёжной оценки политики: отчёт неполный или содержит неоднозначные оценки. Повторите синхронизацию Harbor.')
    allowed = set() if expired else set(data['allowlist'])
    blockers, excluded = set(), set()
    uncertain = False
    for cve, severity in findings:
        if cve.upper() in allowed:
            excluded.add(cve)
        elif severity not in _RANK:
            uncertain = True
        elif severity != 'none' and _RANK[severity] >= _RANK[data['threshold']]:
            blockers.add(cve)
    result.update(evaluated=True, blocking_count=len(blockers), excluded_count=len(excluded),
                  blocking_cves=sorted(blockers)[:20], excluded_cves=sorted(excluded)[:20])
    if blockers:
        return done('blocked', 'Есть уязвимости на уровне порога проекта или выше, не покрытые действующими исключениями.')
    if uncertain:
        return done('unknown', 'В отчёте есть находки с неопределённой критичностью; разрешение на скачивание не подтверждено.')
    return done('allowed', 'Находок на уровне порога проекта или выше вне действующих исключений нет.')


def summaries(db: Session, images: list[VmImage]) -> dict[int, dict[str, Any]]:
    if not images:
        return {}
    policies = {p.project: p for p in db.scalars(select(VmHarborProjectPolicy).where(
        VmHarborProjectPolicy.project.in_({i.project for i in images}))) }
    findings: dict[int, list[tuple[str, str]]] = defaultdict(list)
    # One batch for the page; duplicates across packages do not change this gate.
    for image_id, cve, severity in db.execute(select(
        VmImageCve.image_id, VmImageCve.cve_id, VmImageCve.trivy_severity,
    ).where(VmImageCve.image_id.in_([i.id for i in images])).distinct()):
        findings[image_id].append((cve, severity))
    now = dt.datetime.now(dt.UTC)
    result = {}
    for image in images:
        policy = policies.get(image.project)
        if policy and policy.registry_url != image.registry_url:
            policy = None
        result[image.id] = evaluate(image, policy, findings[image.id], now=now)
    return result
