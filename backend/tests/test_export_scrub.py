"""Чистка выгрузок (`tools/export_scrub.py`): слова меняются по списку, адреса — по таблице
подсетей и автоматически. Скрипт самостоятельный (только стандартная библиотека), его запускают
там, где лежат настоящие данные, поэтому проверяется запуском отдельным процессом."""
from __future__ import annotations

import base64
import gzip
import io
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "export_scrub.py"

RULES = """
# слова
ключ = 0123456789abcdef
SRV01AB64 = ZZ01AB64
olddomain.example = newdomain.example
Иванов = Петров
# подсети
10.1.0.0/16 = 10.201.0.0/16
203.0.113.7 = 198.51.100.7
"""


def _b64(ip: str) -> str:
    return base64.b64encode(bytes(int(p) for p in ip.split("."))).decode()


def _ip(b64: str) -> str:
    return ".".join(str(b) for b in base64.b64decode(b64))


def _export() -> dict[str, Any]:
    return {
        "format": "stools-ksc/1",
        "server": {"name": "SRV01AB64.olddomain.example", "version": "10.1.2.3", "address": "10.1.2.3"},
        "hosts": [
            {"name": "srv01ab64", "fqdn": "srv01ab64.OLDDOMAIN.EXAMPLE", "ip": "10.1.44.15", "owner": "ИВАНОВ И.И."},
            {"hostname": "WS7", "ip": "10.9.8.7", "peer": "10.9.8.200", "far": "10.77.8.7", "home": "192.168.5.20", "dmz": "172.20.3.4",
             "resolver": "8.8.8.8", "ntp": "8.8.4.4"},
        ],
        "by_host": {"SRV01AB64": {"comment": "Сервер Иванова, шлюз 203.0.113.7, DNS 8.8.8.8, петля 127.0.0.1, маска 255.255.255.0"}},
        "rules": [{"octets": {"type": "binary", "value": _b64("10.1.2.3")}, "mask": 24}, {"octets": {"type": "binary", "value": "A" * 24}}],
        "products": {"11.4.0.233": True},
        "path": "C:\\Users\\Иванов\\app.exe",
    }


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, encoding="utf-8", check=check)


def _scrub(tmp_path: Path, source: Path, target: str, rules: str = RULES) -> tuple[Path, str]:
    rules_path = tmp_path / "rules.txt"
    rules_path.write_text(rules, encoding="utf-8")
    out = tmp_path / target
    done = _run(str(source), "-o", str(out), "-r", str(rules_path))
    return out, done.stdout


def test_json_words_subnets_auto_and_octets(tmp_path: Path) -> None:
    source = tmp_path / "export.json"
    # Как пишет PowerShell: BOM и не-ASCII символы в виде \uXXXX — замена всё равно находит слово.
    source.write_bytes(b"\xef\xbb\xbf" + json.dumps(_export(), ensure_ascii=True).encode())
    out, report = _scrub(tmp_path, source, "clean.json")
    raw = out.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    text = raw.decode("utf-8-sig")
    data = json.loads(text)
    for word in ("srv01ab64", "olddomain", "иванов"):
        assert word not in text.lower()
    # Регистр слова сохраняется: всё заглавными, всё строчными, иначе — как в правиле.
    assert data["server"]["name"] == "ZZ01AB64.newdomain.example"
    assert data["hosts"][0]["name"] == "zz01ab64" and data["hosts"][0]["fqdn"] == "zz01ab64.NEWDOMAIN.EXAMPLE"
    assert data["hosts"][0]["owner"] == "ПЕТРОВ И.И." and data["path"] == "C:\\Users\\Петров\\app.exe"
    assert "ZZ01AB64" in data["by_host"]
    # Таблица подсетей: номер хоста внутри подсети сохраняется; отдельный адрес — как /32.
    assert data["server"]["address"] == "10.201.2.3" and data["hosts"][0]["ip"] == "10.201.44.15"
    comment = data["by_host"]["ZZ01AB64"]["comment"]
    assert "198.51.100.7" in comment and "127.0.0.1" in comment and "255.255.255.0" in comment
    # Публичный адрес вне таблицы — случайный из 8.8.0.0/16, один и тот же при каждом вхождении.
    dns = re.search(r"DNS (8\.8\.\d+\.\d+),", comment)
    assert dns and dns.group(1) != "8.8.8.8" and data["hosts"][1]["resolver"] == dns.group(1)
    assert data["hosts"][1]["ntp"].startswith("8.8.") and data["hosts"][1]["ntp"] not in (dns.group(1), "8.8.4.4")
    # Имя ключа с номером версии не адрес.
    assert "11.4.0.233" in data["products"]
    # Номер версии не адрес, даже если похож.
    assert data["server"]["version"] == "10.1.2.3"
    # Автозамена: частная сеть остаётся частной, последний октет и общая подсеть сохраняются.
    ws = data["hosts"][1]
    assert ws["ip"] != "10.9.8.7" and ws["ip"].startswith("10.") and ws["ip"].endswith(".7")
    assert ws["peer"].rsplit(".", 1) == [ws["ip"].rsplit(".", 1)[0], "200"]
    assert ws["far"].rsplit(".", 1)[0] != ws["ip"].rsplit(".", 1)[0]
    assert ws["home"].startswith("192.168.") and ws["home"].endswith(".20") and ws["home"] != "192.168.5.20"
    assert ws["dmz"].startswith("172.") and 16 <= int(ws["dmz"].split(".")[1]) <= 31 and ws["dmz"] != "172.20.3.4"
    # Двоичный адрес KSC меняется тем же правилом; двоичное не-адрес не трогается.
    assert _ip(data["rules"][0]["octets"]["value"]) == "10.201.2.3"
    assert data["rules"][1]["octets"]["value"] == "A" * 24
    assert "8.8.8.8" in report and "остатков слов из правил: 0" in report
    lines = {line.strip() for line in report.splitlines()}
    # Что осталось как есть: подсеть публичного адреса, частные подсети вне таблицы, имя хоста без правила.
    assert {"8.8.8.0/24 — 2", "8.8.4.0/24 — 1"} <= lines
    assert {"10.9.8.0/24 — 2", "10.77.8.0/24 — 1", "192.168.5.0/24 — 1", "172.20.3.0/24 — 1"} <= lines
    assert "ws7 — 1" in lines
    assert not [line for line in lines if line.startswith(("zz01ab64 —", "srv01ab64 —", "10.201."))]


def test_auto_mapping_is_stable_with_key_and_differs_without(tmp_path: Path) -> None:
    source = tmp_path / "a.json"
    source.write_text(json.dumps({"ip": "10.9.8.7"}), encoding="utf-8")
    first = json.loads(_scrub(tmp_path, source, "1.json")[0].read_text(encoding="utf-8"))
    second = json.loads(_scrub(tmp_path, source, "2.json")[0].read_text(encoding="utf-8"))
    assert first == second
    other = json.loads(_scrub(tmp_path, source, "3.json", RULES.replace("0123456789abcdef", "fedcba9876543210"))[0].read_text(encoding="utf-8"))
    assert other != first
    _, report = _scrub(tmp_path, source, "4.json", "SRV01AB64 = ZZ01AB64\n")
    assert "ключ не задан" in report


def test_zip_gzip_directory_and_plain_text(tmp_path: Path) -> None:
    data = tmp_path / "data"
    (data / "SRV01AB64").mkdir(parents=True)
    (data / "SRV01AB64" / "export.json.gz").write_bytes(gzip.compress(json.dumps(_export(), ensure_ascii=False).encode()))
    (data / "hosts.csv").write_text("name;ip\nSRV01AB64.olddomain.example;10.1.2.3\n", encoding="utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("srv01ab64/notes.txt", "Иванов: 10.1.2.3")
        archive.writestr("inner.json", json.dumps(_export(), ensure_ascii=False))
    (data / "pack.zip").write_bytes(buf.getvalue())
    (data / "blob.bin").write_bytes(b"\xff\xfe\x00\xd8\x00")
    out, report = _scrub(tmp_path, data, "clean")
    assert (out / "hosts.csv").read_text(encoding="utf-8") == "name;ip\nZZ01AB64.newdomain.example;10.201.2.3\n"
    inner = json.loads(gzip.decompress((out / "ZZ01AB64" / "export.json.gz").read_bytes()))
    assert inner["server"]["name"] == "ZZ01AB64.newdomain.example"
    with zipfile.ZipFile(out / "pack.zip") as archive:
        assert sorted(archive.namelist()) == ["inner.json", "zz01ab64/notes.txt"]
        assert archive.read("zz01ab64/notes.txt").decode() == "Петров: 10.201.2.3"
    # Нечитаемый как текст файл в результат не попадает и назван в отчёте.
    assert not (out / "blob.bin").exists() and "blob.bin" in report
    everything = b"".join(p.read_bytes() for p in out.rglob("*") if p.is_file())
    assert b"SRV01AB64" not in everything and not [p for p in out.rglob("*") if "SRV01AB64" in p.name]


def test_report_counts_rules_and_hints_at_what_is_left(tmp_path: Path) -> None:
    source = tmp_path / "a.txt"
    source.write_text("SRV01AB64 srv01ab64 host5.forgotten.example user@mail.forgotten.example agent.exe 8.8.4.4", encoding="utf-8")
    _, report = _scrub(tmp_path, source, "b.txt")
    lines = {line.strip() for line in report.splitlines()}
    assert "SRV01AB64 — 2" in lines
    assert "Иванов — 0 (правило не сработало)" in lines
    assert "forgotten.example — 2" in lines
    assert "host5.forgotten.example — 1" in lines and "8.8.4.0/24 — 1" in lines
    assert "8.8.4.4 — 1" in lines
    assert "agent.exe" not in report


def test_bad_rules_and_same_path_are_refused(tmp_path: Path) -> None:
    source = tmp_path / "a.txt"
    source.write_text("x", encoding="utf-8")
    rules = tmp_path / "rules.txt"
    for bad in ("слово без знака равно\n", "10.1.0.0/16 = 10.2.0.0/24\n", "10.1.0.0/16 = слово\n", " = пусто\n", ""):
        rules.write_text(bad, encoding="utf-8")
        done = _run(str(source), "-o", str(tmp_path / "b.txt"), "-r", str(rules), check=False)
        assert done.returncode == 1 and done.stderr.strip()
    rules.write_text("a = b\n", encoding="utf-8")
    assert _run(str(source), "-o", str(source), "-r", str(rules), check=False).returncode == 1


def test_init_writes_template_with_fresh_key(tmp_path: Path) -> None:
    rules = tmp_path / "rules.txt"
    _run("--init", str(rules))
    text = rules.read_text(encoding="utf-8")
    assert "ключ = " in text
    assert _run("--init", str(rules), check=False).returncode == 1
    source = tmp_path / "a.txt"
    source.write_text("10.9.8.7", encoding="utf-8")
    # Шаблон без единого правила замены годится для запуска: адреса меняются по ключу.
    out = tmp_path / "b.txt"
    _run(str(source), "-o", str(out), "-r", str(rules))
    assert out.read_text(encoding="utf-8") != "10.9.8.7"
