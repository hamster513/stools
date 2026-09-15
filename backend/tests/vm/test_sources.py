from __future__ import annotations

from pathlib import Path

from api.modules.vm.core.sources import iter_path, split_cves, split_host

FIXTURES = Path(__file__).parent / "fixtures"


def test_split_host() -> None:
    assert split_host("srv01 (10.1.2.3)") == ("srv01", "10.1.2.3")
    assert split_host("srv01") == ("srv01", "")
    assert split_host("  srv01.corp (10.0.0.1)  ") == ("srv01.corp", "10.0.0.1")


def test_split_cves_dedupes_and_uppercases() -> None:
    assert split_cves("CVE-2021-44228, cve-2021-44228,junk,CVE-2019-0708") == ["CVE-2021-44228", "CVE-2019-0708"]
    assert split_cves("") == []


def test_iter_csv_fixture() -> None:
    rows = list(iter_path(FIXTURES / "hosts.csv"))
    assert [r.hostname for r in rows] == ["srv01.corp.local", "ws02.corp.local", "noip.corp.local", "srv03.corp.local"]
    assert rows[0].ip == "10.1.1.1" and rows[0].zone == "DMZ" and rows[0].groups == "Servers,Prod"
    assert rows[0].cves == ["CVE-2021-44228", "CVE-2019-0708"]
    assert rows[1].criticality == "Medium"  # регистр нормализован
    assert rows[2].cves == [] and rows[2].ip == ""
    assert rows[3].cves == ["CVE-2020-1472"]


def test_iter_json_fixture_streams_pairs() -> None:
    rows = list(iter_path(FIXTURES / "hosts.json"))
    assert len(rows) == 4  # одна запись — одна пара, группирует конвейер
    assert rows[0].hostname == "srv01.corp.local" and rows[0].cves == ["CVE-2019-1436"]
    assert rows[2].zone == "AppDMZ" and rows[2].criticality == "Low"
