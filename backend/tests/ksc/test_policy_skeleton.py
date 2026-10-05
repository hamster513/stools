"""Скелет выгрузки KSC (`tools/ksc_policy_skeleton.py`): имена секций и ключей, типы и вид
значений — и ни одного значения. Скрипт самостоятельный (только стандартная библиотека), его
запускают там, где лежит настоящая выгрузка, поэтому проверяется запуском отдельным процессом."""
from __future__ import annotations

import gzip
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

from tests.ksc import synthetic

SCRIPT = Path(__file__).resolve().parents[2] / "tools" / "ksc_policy_skeleton.py"

#: Значения, которые похожи на данные заказчика: в скелет не попадает ни одно.
PLANTED = (
    "C:\\Customer\\App\\agent.exe", "%ProgramFiles%\\Vendor\\*.dll", "\\\\fileserver\\share\\tool.exe",
    "d41d8cd98f00b204e9800998ecf8427e", "https://proxy.example.org:8080/", "10.20.30.40",
    "Бухгалтерия: исключение для 1С", "C:\\Users\\user1", "{0F8FAD5B-D9CB-469F-A165-70867728950E}", "Отдел продаж",
    "note-for-admins",
)


def _lock(value: Any, *, locked: bool) -> dict[str, Any]:
    return {"KLPRSS_Val": value, "KLPRSS_Mnd": locked}


def _export() -> dict[str, Any]:
    export = synthetic.build_export()
    sections = export["policy_contents"]["1"]["sections"]
    sections["TrustedZone"] = {
        "Rules": _lock(
            [
                {"type": "params", "value": {"Path": PLANTED[0], "Hash": PLANTED[3], "Enabled": True, "Comment": PLANTED[6]}},
                {"type": "params", "value": {"Path": PLANTED[1], "Enabled": False, "Components": [1, 2]}},
                {"type": "params", "value": {"Path": PLANTED[2], "Enabled": True}},
            ],
            locked=True,
        ),
        "Proxy": _lock({"Url": PLANTED[4], "Address": PLANTED[5], "Port": {"type": "long", "value": 8080}, "Note": PLANTED[10]}, locked=False),
        # Словари, ключи которых — данные, а не имена настроек: путь, GUID, кириллица, номер.
        "PerFolder": {PLANTED[7]: {"Scan": True}, PLANTED[8]: {"Scan": False}, PLANTED[9]: {"Scan": True}, "17": {"Scan": True}},
        "Empty": _lock([], locked=False),
        "Since": {"type": "datetime", "value": "2026-01-01T00:00:00Z"},
        "ServicePassword": _lock("<скрыто>", locked=True),
    }
    return export


def _run(path: Path, *extra: str) -> str:
    done = subprocess.run([sys.executable, str(SCRIPT), str(path), *extra], capture_output=True, text=True, encoding="utf-8", check=True)
    return done.stdout


def test_skeleton_names_keys_and_types_without_values(tmp_path: Path) -> None:
    path = tmp_path / "export.json"
    path.write_text(json.dumps(_export(), ensure_ascii=False), encoding="utf-8")
    out = _run(path)

    assert not [v for v in PLANTED if v in out]
    assert not [v for v in synthetic.SECRET_VALUES if v in out]
    for host in ("WS01", "ws01.corp.local", "corp.local", "Managed devices", "KES root"):
        assert host not in out

    assert "KES 12.0.0.0" in out
    assert "TrustedZone" in out and "KLPRSS_Basic" in out
    lines = {line.strip() for line in out.splitlines()}
    # Список правил: элементы сведены в одну форму, строки описаны видом, а не значением.
    assert "Rules[] : список, элементов 1–9, замок" in lines
    assert "Rules[].Path : str (маска, переменная, путь)" in lines
    assert "Rules[].Hash : str (хеш)" in lines
    assert "Rules[].Enabled : bool" in lines
    assert "Rules[].Comment : str (текст)" in lines
    assert "Rules[].Components[] : список, элементов 1–9" in lines
    assert "Rules[].Components[] : int" in lines
    assert "Proxy.Url : str (url), замок" in lines
    assert "Proxy.Address : str (ip), замок" in lines
    assert "Proxy.Port : long, замок" in lines
    assert "Empty[] : список, пустой, замок" in lines
    assert "Since : datetime" in lines
    # Ключи-данные заменены метками; ключи-имена настроек остались.
    assert "PerFolder.<ключ>.Scan : bool" in lines
    assert "PerFolder.<guid>.Scan : bool" in lines
    assert "PerFolder.<n>.Scan : bool" in lines
    # Скрытое сборщиком остаётся скрытым и помечено.
    assert "ServicePassword : str (скрыто), замок" in lines


def test_skeleton_lists_component_names_and_states(tmp_path: Path) -> None:
    path = tmp_path / "export.json"
    path.write_text(json.dumps(_export(), ensure_ascii=False), encoding="utf-8")
    out = _run(path)
    assert "КОМПОНЕНТЫ" in out
    assert "Firewall — состояния 1, 4" in out
    assert "поля записи: KLHST_PRCST_COMPONENT_DN, KLHST_PRCST_COMPONENT_ID, KLHST_PRCST_COMPONENT_STATUS" in out


def test_skeleton_reads_gzip_directory_and_writes_file(tmp_path: Path) -> None:
    data = tmp_path / "ksc"
    data.mkdir()
    (data / "1.json.gz").write_bytes(gzip.compress(json.dumps(_export(), ensure_ascii=False).encode()))
    # Файл PowerShell-сборщика: с BOM и без содержимого политик — в свод не мешает.
    bare = synthetic.build_export()
    bare["policy_contents"] = {}
    (data / "2.json").write_bytes(b"\xef\xbb\xbf" + json.dumps(bare, ensure_ascii=False).encode())
    target = tmp_path / "skeleton.txt"
    out = _run(data, "-o", str(target))
    text = target.read_text(encoding="utf-8")
    assert "Rules[].Path : str (маска, переменная, путь)" in text
    assert "файлов выгрузки: 2" in text
    assert not [v for v in PLANTED if v in text]
    assert str(target) in out


def test_skeleton_says_when_there_is_nothing(tmp_path: Path) -> None:
    bare = synthetic.build_export()
    bare["policy_contents"] = {}
    bare["host_components"] = {}
    path = tmp_path / "export.json"
    path.write_text(json.dumps(bare, ensure_ascii=False), encoding="utf-8")
    out = _run(path)
    assert "содержимого политик в выгрузке нет" in out
    assert "компонентов хостов в выгрузке нет" in out


def test_skeleton_numbers_flag_prints_distinct_values_of_numeric_keys(tmp_path: Path) -> None:
    """`--numbers`: у числовых ключей печатается набор встреченных значений — коды перечислений
    (действие, направление, уровень) иначе не расшифровать; строки по-прежнему не печатаются."""
    export = _export()
    sections = export["policy_contents"]["1"]["sections"]
    sections["TrustedZone"]["Rules"]["KLPRSS_Val"] += [
        {"type": "params", "value": {"Path": PLANTED[0], "Enabled": True, "Action": 2}},
        {"type": "params", "value": {"Path": PLANTED[1], "Enabled": True, "Action": 0}},
        {"type": "params", "value": {"Path": PLANTED[2], "Enabled": True, "Action": 2, "Size": {"type": "long", "value": 7}}},
    ]
    sections["TrustedZone"]["Many"] = _lock([{"type": "params", "value": {"Port": 1000 + n}} for n in range(12)], locked=False)
    path = tmp_path / "export.json"
    path.write_text(json.dumps(export, ensure_ascii=False), encoding="utf-8")
    plain = _run(path)
    assert "Rules[].Action : int" in {line.strip() for line in plain.splitlines()}
    assert "{0, 2}" not in plain
    out = _run(path, "--numbers")
    lines = {line.strip() for line in out.splitlines()}
    assert "Rules[].Action : int {0, 2}" in lines
    assert "Rules[].Size : long {7}" in lines
    assert "Many[].Port : int {различных: 12}" in lines
    assert not [v for v in PLANTED if v in out]


def test_skeleton_reads_zip_archive(tmp_path: Path) -> None:
    """Выгрузку передают архивом: читается каждая выгрузка внутри zip, чужие файлы пропускаются."""
    path = tmp_path / "export.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("ksc/export.json", json.dumps(_export(), ensure_ascii=False))
        archive.writestr("readme.txt", "не выгрузка")
    out = _run(path, "--numbers")
    assert "файлов выгрузки: 1" in out and "Rules[].Path : str (маска, переменная, путь)" in out
    assert not [v for v in PLANTED if v in out]
    broken = tmp_path / "broken.zip"
    broken.write_bytes(b"PK\x03\x04 not a zip")
    done = subprocess.run([sys.executable, str(SCRIPT), str(broken)], capture_output=True, text=True, encoding="utf-8")
    assert done.returncode == 1 and "ни одной выгрузки KSC не найдено" in done.stderr
