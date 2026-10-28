"""Бюджеты скорости движка сетевого экрана (спека §7): проверка пакета `check` ≤ 300 мс (медиана из 5), сводка секций
`net-rules/sections` ≤ 1 с.

Нормальный тест с лимитом по времени (маркера `slow` в проекте нет). Размеры:
- `evaluate_side` — объекты `HostFirewall` собираются напрямую, без БД: политика на 500 правил и 20 профилей по 500 правил
  (10 500 правил, пакет не совпадает ни с одним — худший обход), в режиме `auto` и в предельном ветвлении;
- маршруты — выгрузка 10 политик × (200 правил + 5 профилей по 200 правил) = 12 000 строк; загрузка выгрузки через API на
  50 × 20 × 500 слишком тяжёлая для теста, поэтому проверка маршрутов в 10 раз мельче по правилам на набор и в 5 раз по
  числу политик. Квадратичная часть (тень) растёт как n² на набор, то есть для набора в 500 правил — в ~6 раз.
"""
from __future__ import annotations

import statistics
import time
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.modules.ksc.core.firewall.evaluate import evaluate_side
from api.modules.ksc.core.firewall.model import (
    HostFirewall,
    Packet,
    Protocol,
    RuleView,
    SourceSet,
    ZoneView,
)
from api.modules.ksc.core.policy_model import Address, Scope, scope_to_json
from api.modules.ksc.models import KscNetRule
from api.modules.ksc.services.firewall import _shadow_cache as shadow_cache
from api.modules.ksc.services.firewall import shadow_lookup
from tests.ksc.firewall.test_api import RULES, _upload
from tests.ksc.kes11 import TCP, _address, kes11_export, kes11_sections, packet_rule
from tests.ksc.synthetic import P_NOTEBOOKS

#: Бюджеты спеки §7, секунды.
CHECK_BUDGET = 0.3
SECTIONS_BUDGET = 1.0
RUNS = 5

POLICIES, PROFILES, RULES_PER_SET = 10, 5, 200
EVAL_PROFILES, EVAL_RULES = 20, 500


def median_of(fn: Callable[[], Any], runs: int = RUNS) -> float:
    times = []
    for _ in range(runs):
        t = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t)
    return statistics.median(times)


# --- движок без БД ----------------------------------------------------------------------------------------------------


def _view(row_id: int, profile: str, i: int) -> RuleView:
    """Правило i набора: адрес из 198.51.100.0/24 и свой порт, каждое 10-е — по зоне; ни одно не совпадает с проверяемым пакетом."""
    zone = {"networks": i % 3} if i % 10 == 0 else {"remote": (Address(ip=f"198.51.100.{i % 254 + 1}", mask=32),)}
    return RuleView(
        row_id=row_id, policy_id=1, profile=profile, layer="packet", position=i, name=f"Тестовое правило {i}",
        action="запретить" if i % 2 else "разрешить", enabled=True,
        scope=Scope(direction=4, protocol=Protocol.TCP, remote_ports=((1000 + i, 1000 + i),), **zone),
        direction_text="", protocol_text="", local_ports_text="", remote_ports_text="", addresses_text="")


def _set(k: int, profile: str, priority: int | None) -> SourceSet:
    return SourceSet(policy_id=1, profile=profile, priority=priority, locked=True if profile else None,
                     rules=tuple(_view(k * EVAL_RULES + i, profile, i) for i in range(EVAL_RULES)))


def _host(undetermined: int = 0) -> HostFirewall:
    profiles = [_set(k + 1, f"Тестовый профиль {k}", k) for k in range(EVAL_PROFILES)]
    zones = (ZoneView("Тестовая локальная", 1, None), ZoneView("Тестовая публичная", 2, None))
    return HostFirewall(
        host_id="h-1", host_name="ws01.example.test", host_ip="192.0.2.10", policy_id=1, policy_name="Тестовая политика",
        packet=_set(0, "", None), packet_profiles=tuple(profiles[undetermined:]), packet_undetermined=tuple(profiles[:undetermined]),
        app=SourceSet(1, "", None, None, ()), app_profiles=(), app_undetermined=(), zones=zones, firewall_enabled=True,
        notify_only=False, hips_enabled=True, hips_notify_only=False, component_running=True, trust_groups=(), notes=())


def test_evaluate_side_budget() -> None:
    """500 правил в политике и в каждом из 20 профилей: вердикт стороны укладывается в бюджет `check`, в том числе при
    неопределённой активации профилей (ветвление до предела)."""
    packet = Packet(outbound=True, protocol=Protocol.TCP, local_port=None, remote_port=443, remote_ip="198.51.100.77", remote_host="")
    for undetermined in (0, 4):
        fw = _host(undetermined)
        res = evaluate_side(fw, packet)
        assert res.branches
        elapsed = median_of(lambda fw=fw: evaluate_side(fw, packet))
        print(f"evaluate_side: профилей неопределённо {undetermined}, ветвей {len(res.branches)}, медиана {elapsed * 1000:.0f} мс")
        assert elapsed <= CHECK_BUDGET, f"{elapsed:.3f} с при {undetermined} неопределённых профилях"
    # Режим replace — одна модель, не медленнее auto.
    assert median_of(lambda: evaluate_side(_host(), packet, profile_mode="replace")) <= CHECK_BUDGET


# --- маршруты ---------------------------------------------------------------------------------------------------------


def _rules(k: int) -> list[dict[str, Any]]:
    """200 различных исходящих правил набора k: адрес из 198.51.100.0/24 и свой порт (тени мало — худший случай для её расчёта)."""
    return [packet_rule(f"Тестовое правило {k}-{i}", action=i % 2, direction=4, protocol=TCP,
                        remote_ports=[{"begin": 1000 + i, "end": 1000 + i}], remote=[_address(f"198.51.100.{i % 254 + 1}", 32)])
            for i in range(RULES_PER_SET)]


def _big_export() -> dict[str, Any]:
    """Политика 1 — 200 правил и 5 профилей по 200 правил, активных у WS01 (тег VIP); ещё 9 таких же политик без хостов."""
    raw = kes11_export(**{RULES: _rules(0)})
    base = raw["policies"][0]
    extra_ids = range(10, 10 + POLICIES - 1)
    raw["policies"] += [{**base, "KLPOL_ID": pid, "KLPOL_DN": f"Тестовая политика {pid}"} for pid in extra_ids]
    for pid in (1, *extra_ids):
        raw["policy_contents"][str(pid)] = {**raw["policy_contents"]["1"], "sections": kes11_sections(**{RULES: _rules(pid)})}
        raw["policy_profiles"][str(pid)] = {"profiles": [
            {**P_NOTEBOOKS, "name": f"Тестовый профиль {j}", "sections": kes11_sections(**{RULES: _rules(100 * pid + j)})}
            for j in range(PROFILES)], "priorities": [f"Тестовый профиль {j}" for j in range(PROFILES)], "errors": []}
    return raw


@pytest.fixture(scope="module")
def big_snapshot() -> dict[str, Any]:
    return _big_export()


def test_routes_budget(auth_client: TestClient, big_snapshot: dict[str, Any]) -> None:
    """Выгрузка на 12 000 строк: проверка пакета (обе стороны и пакетом по хостам), сводка секций и страница списка с тенью."""
    t = time.perf_counter()
    sid = _upload(auth_client, big_snapshot)
    print(f"загрузка выгрузки: {time.perf_counter() - t:.1f} с")
    base = f"/api/ksc/snapshots/{sid}"
    hosts = auth_client.get(f"{base}/hosts", params={"limit": 200}).json()
    items = hosts["items"] if isinstance(hosts, dict) else hosts
    ids = [h["host_id"] for h in items]
    assert {"h-ws01", "h-ws02"} <= set(ids)
    # Первое чтение считает тень каждого набора и кладёт её в кэш между запросами: бюджет — для тёплого кэша (повторные
    # запросы), холодный расчёт печатается и ограничен щедро.
    shadow_cache.clear()
    t = time.perf_counter()
    first = auth_client.get(f"{base}/net-rules/sections")
    cold = time.perf_counter() - t
    print(f"sections, холодный кэш тени: {cold * 1000:.0f} мс")
    assert first.status_code == 200 and cold <= 3 * SECTIONS_BUDGET
    assert sum(s["layer"] == "packet" for s in first.json()) == POLICIES * (PROFILES + 1)

    def check(source: str, destination: dict[str, str]) -> None:
        r = auth_client.post(f"{base}/firewall/check",
                             json={"source_host_id": source, "destination": destination, "protocol": "tcp", "port": 443})
        assert r.status_code == 200, r.text

    def sections(**params: str) -> None:
        r = auth_client.get(f"{base}/net-rules/sections", params=params)
        assert r.status_code == 200, r.text

    def listing() -> None:
        r = auth_client.get(f"{base}/net-rules", params={"host_id": "h-ws01", "limit": 200})
        assert r.status_code == 200, r.text

    def batch() -> None:
        r = auth_client.post(f"{base}/firewall/check/batch", json={"sources": ids[:14], "destination": {"address": "198.51.100.77"},
                                                                    "protocol": "tcp", "port": 443})
        assert r.status_code == 200, r.text

    measured = {
        "check (адрес)": (median_of(lambda: check("h-ws01", {"address": "198.51.100.77"})), CHECK_BUDGET),
        "check (хост)": (median_of(lambda: check("h-ws01", {"host_id": "h-ws02"})), CHECK_BUDGET),
        "sections": (median_of(sections), SECTIONS_BUDGET),
        "sections (хост)": (median_of(lambda: sections(host_id="h-ws01")), SECTIONS_BUDGET),
        "net-rules (хост, 200 строк)": (median_of(listing), SECTIONS_BUDGET),
        "check/batch (14 хостов)": (median_of(batch), SECTIONS_BUDGET),
    }
    for name, (elapsed, budget) in measured.items():
        print(f"{name}: медиана {elapsed * 1000:.0f} мс (бюджет {budget * 1000:.0f})")
    over = {name: round(e, 3) for name, (e, budget) in measured.items() if e > budget}
    assert not over, over


def test_shadow_cache_follows_content() -> None:
    """Кэш тени между запросами: повторный вызов даёт тот же ответ из кэша; набор с теми же `id`, но другим содержимым
    (другая база, выключенное правило) не получает чужую тень."""
    def row(row_id: int, *, enabled: bool = True) -> KscNetRule:
        return KscNetRule(id=row_id, snapshot_id=1, policy_id=1, profile="", layer="packet", position=row_id, name=f"Тестовое правило {row_id}",
                          action="запретить", enabled=enabled, key=f"k{row_id}", scope_json=scope_to_json(Scope(direction=4)))

    shadow_cache.clear()
    first, second = row(1), row(2)
    assert shadow_lookup([first, second])(second) is not None
    assert len(shadow_cache) == 1
    assert shadow_lookup([first, second])(second) is not None and len(shadow_cache) == 1
    # Те же `id`, но первое правило выключено — тени нет, набор в кэше свой.
    assert shadow_lookup([row(1, enabled=False), second])(second) is None
    assert len(shadow_cache) == 2
