"""Ячейки сводки: состав каждого числа — те же учётки, что дали число, и с теми же параметрами."""
from __future__ import annotations

from typing import Any

import pytest

from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import ExportIndex
from api.modules.ad.core.summary import AGE_BOUNDS, SUMMARY_VERSION, build_summary
from api.modules.ad.core.summary_cells import (
    cell_count,
    params_config,
    summary_cells,
    summary_params,
)
from tests.ad.mini import DN, computer, dc, ft, group, mini_export, rid, user

ADMINISTRATOR = f"CN=Administrator,CN=Users,{DN}"
CFG_30 = AdConfig(user_inactivity_days=30)
CFG_90 = AdConfig()


def _idx() -> ExportIndex:
    alice = user("alice", 1101, uac=512 | 0x10000, pwdLastSet=ft(400))
    erin = user("erin", 1106, allowedToDelegateTo=["cifs/fs.corp.local"], lastLogonTimestamp=ft(2000))
    ws1 = computer("WS1", 1201, operatingSystem="Windows 11 Pro", operatingSystemVersion="10.0 (22631)", lapsExpiry=ft(-10))
    ops = group("Ops", rid(1300), [erin["dn"], ws1["dn"]])
    export = mini_export([
        alice,
        user("bob", 1102, lastLogonTimestamp=ft(200)),
        user("carol", 1103, uac=512 | 0x20 | 0x400000, sIDHistory=["S-1-5-21-9-9-9-1105"], pwdLastSet=None, lastLogonTimestamp=None),
        user("dave", 1104, uac=514),
        user("TRUST$", 1105, uac=2048),  # учётка доверия
        erin,
        group("Domain Admins", rid(512), [ADMINISTRATOR, alice["dn"], ops["dn"]]),
        ops,
        group("Protected Users", rid(525), [alice["dn"]]),
        ws1,
        computer("WS2", 1202, uac=4098, operatingSystem="Windows 11 Pro", operatingSystemVersion="10.0 (22631)"),
        computer("WS3", 1203, operatingSystem="Windows 10 Pro", operatingSystemVersion="10.0 (19045)",
                 lastLogonTimestamp=ft(200), allowedToDelegateTo=["cifs/fs.corp.local"]),
        computer("SRV1", 1204, lastLogonTimestamp=ft(400)),  # ОС не указана
        dc("DC1", 1000, operatingSystem="Windows Server 2022 Standard", operatingSystemVersion="10.0 (20348)"),
    ])
    return ExportIndex(export)


def _summary_ids(summary: dict[str, Any]) -> dict[str, int]:
    """Идентификатор ячейки → число в сводке, обходом JSON сводки."""
    out: dict[str, int] = {}
    for kind, counts in summary["accounts"].items():
        for key, n in counts.items():
            if kind == "users" and key == "laps":
                continue  # у пользователей LAPS не бывает: «—» на странице
            out[f"accounts:{kind}:{key}"] = n
    for block in ("password_age", "last_logon"):
        for scope, buckets in summary[block].items():
            for b in buckets:
                out[f"{block}:{scope}:{'over' if b['le'] is None else b['le']}"] = b["n"]
    for g in summary["groups"]:
        for field in ("members", "enabled", "inactive", "pwd_never_expires", "delegable", "protected_users"):
            out[f"groups:{field}:{g['sid']}"] = g[field]
    for row in summary["os"]:
        for field in ("total", "enabled", "active"):
            out[f"os:{field}:{row['build']}:{row['name']}"] = row[field]
    return out


def test_every_cell_matches_summary_number() -> None:
    idx = _idx()
    summary = build_summary(idx, CFG_90)
    cells = summary_cells(idx, CFG_90)
    assert cells
    for cell_id, cell in cells.items():
        assert len(cell.users) + len(cell.computers) == cell_count(summary, cell_id), cell_id


def test_every_nonzero_summary_number_has_cell() -> None:
    idx = _idx()
    summary = build_summary(idx, CFG_90)
    cells = summary_cells(idx, CFG_90)
    numbers = _summary_ids(summary)
    assert sum(n > 0 for n in numbers.values()) > 30  # выгрузка задевает все блоки
    missing = [cell_id for cell_id, n in numbers.items() if n > 0 and cell_id not in cells]
    assert missing == []
    assert set(cells) == set(numbers)  # и лишних ячеек нет


def test_account_cells_content() -> None:
    cells = summary_cells(_idx(), CFG_90)
    assert cells["accounts:users:disabled"].users == {rid(502), rid(1104)}  # krbtgt и dave
    assert cells["accounts:users:pwd_not_required"].users == {rid(1103)}
    assert rid(1105) in cells["accounts:users:enabled"].users  # учётка доверия — в составе, как и в числе
    assert cells["accounts:computers:laps"].computers == {rid(1201)}
    assert cells["accounts:computers:laps"].users == frozenset()
    assert cells["accounts:computers:delegation"].computers == {rid(1203)}  # штатная неограниченная у DC1 не в счёт
    assert "accounts:users:laps" not in cells
    assert cells["accounts:users:no_preauth"].label == "Пользователи: без предварительной аутентификации Kerberos"
    assert cells["accounts:users:sid_history"].label == "Пользователи: с SID History"
    assert cells["accounts:computers:laps"].label == "Компьютеры: с LAPS"
    assert cells["accounts:computers:total"].label == "Компьютеры: всего"


def test_bucket_membership() -> None:
    cells = summary_cells(_idx(), CFG_90)
    # у carol пароль не задан и входа не было — последняя корзина
    assert cells["password_age:all:over"].users == {rid(1103)}
    assert cells["password_age:admins:730"].users == {rid(1101)}
    assert cells["last_logon:admins:over"].users == {rid(1106)}  # erin через вложенную Ops, 2000 дней
    assert cells["last_logon:all:over"].users == {rid(1103), rid(1106)}
    assert [cell_id for cell_id in cells if cell_id.startswith("password_age:all:")] == [
        *(f"password_age:all:{le}" for le in AGE_BOUNDS), "password_age:all:over",
    ]


def test_bucket_labels_exact() -> None:
    cells = summary_cells(_idx(), CFG_90)
    assert cells["password_age:all:30"].label == "Возраст пароля 0–30 дн."
    assert cells["password_age:all:90"].label == "Возраст пароля 31–90 дн."
    assert cells["password_age:all:365"].label == "Возраст пароля 181–365 дн."
    assert cells["last_logon:all:1095"].label == "Давность входа 731–1095 дн."
    assert cells["last_logon:admins:over"].label == "Давность входа > 1095 дн. или неизвестно, админы"


def test_group_members_split_users_and_computers() -> None:
    cells = summary_cells(_idx(), CFG_90)
    members = cells[f"groups:members:{rid(512)}"]
    assert members.users == {rid(500), rid(1101), rid(1106)}
    assert members.computers == {rid(1201)}  # WS1 через вложенную Ops
    assert members.label == "Группа «Domain Admins»: участники"
    enabled = cells[f"groups:enabled:{rid(512)}"]
    assert enabled.computers == frozenset() and enabled.users == {rid(500), rid(1101), rid(1106)}
    assert enabled.label == "Группа «Domain Admins»: включённые пользователи"
    assert cells[f"groups:protected_users:{rid(512)}"].users == {rid(1101)}
    assert cells[f"groups:protected_users:{rid(512)}"].label == "Группа «Domain Admins»: в Protected Users"
    assert cells[f"groups:inactive:{rid(512)}"].label == "Группа «Domain Admins»: неактивные"
    assert cells[f"groups:delegable:{rid(512)}"].label == "Группа «Domain Admins»: делегируемые"
    assert cells[f"groups:pwd_never_expires:{rid(512)}"].label == "Группа «Domain Admins»: пароль не истекает"


def test_os_cells() -> None:
    cells = summary_cells(_idx(), CFG_90)
    win11 = cells["os:total:22631:Windows 11 Pro"]
    assert win11.computers == {rid(1201), rid(1202)} and win11.users == frozenset()
    assert win11.label == "ОС «Windows 11 Pro» 22631: всего"
    assert cells["os:enabled:22631:Windows 11 Pro"].computers == {rid(1201)}
    assert cells["os:active:22631:Windows 11 Pro"].label == "ОС «Windows 11 Pro» 22631: активно"
    unnamed = cells["os:total::"]
    assert unnamed.computers == {rid(1204)}
    assert unnamed.label == "ОС «не указана»: всего"


def test_key_falls_back_to_dn_without_sid() -> None:
    export = mini_export([computer("NOSID", 1250, sid=None)])
    cells = summary_cells(ExportIndex(export), CFG_90)
    assert cells["accounts:computers:total"].computers == {f"CN=NOSID,CN=Computers,{DN}"}


@pytest.mark.parametrize("cell_id", [
    "accounts:users:laps", "accounts:users:nope", "accounts:things:total", "accounts:users",
    "password_age:all:31", "password_age:some:30", "password_age:all:x", "last_logon:all",
    "groups:members:S-1-5-21-0-0-0-1", "groups:nope:" + rid(512), "os:total:1:Nope", "os:nope:22631:Windows 11 Pro",
    "nope", "",
])
def test_cell_count_unknown_is_none(cell_id: str) -> None:
    assert cell_count(build_summary(_idx(), CFG_90), cell_id) is None


def test_params_saved_and_restored() -> None:
    idx = _idx()
    summary = build_summary(idx, CFG_30)
    assert SUMMARY_VERSION == 2
    assert summary["version"] == 2 and summary["params"]["user_inactivity_days"] == 30
    assert summary["params"] == summary_params(CFG_30)
    restored = params_config(summary, fallback=CFG_90)
    inactive = summary_cells(idx, restored)["accounts:users:inactive"].users
    assert inactive == summary_cells(idx, CFG_30)["accounts:users:inactive"].users
    assert inactive != summary_cells(idx, CFG_90)["accounts:users:inactive"].users  # параметр и правда влияет


def test_params_fallback_for_v1_summary() -> None:
    assert params_config({"version": 1}, fallback=CFG_90) is CFG_90
