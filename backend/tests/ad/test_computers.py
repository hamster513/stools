import base64
import datetime as dt

import pytest

from api.modules.ad.core import sd
from api.modules.ad.core.checks.computers import obsolete_os, step_up
from api.modules.ad.core.checks.coverage import coverage_gaps
from tests.ad.mini import computer, dc, ft, mini_export, rid, run, user

TODAY = dt.date(2026, 9, 9)
BUILDS = {"22000": dt.date(2024, 10, 8), "26100": dt.date(2027, 10, 12)}


@pytest.mark.parametrize(("name", "version", "expected"), [
    ("Windows Server 2003", "5.2 (3790)", "High"),
    ("Windows XP Professional", "5.1 (2600)", "High"),
    ("Windows 7 Professional", "6.1 (7601)", "Medium"),
    ("Windows Server 2012 R2 Standard", "6.3 (9600)", "Medium"),
    ("Windows 10 Enterprise", "10.0 (19045)", "Medium"),
    ("Windows 10 Enterprise LTSC", "10.0 (19044)", None),
    ("Windows 11 Enterprise", "10.0 (22000)", "Low"),
    ("Windows 11 Enterprise", "10.0 (26100)", None),
    ("Windows Server 2019 Standard", "10.0 (17763)", None),
    ("", "", None),
    ("Windows Server® 2008 Enterprise", "6.0 (6001)", "Medium"),
    ("Windows Vista™ Business", "6.0 (6002)", "Medium"),
])
def test_obsolete_os_table(name, version, expected):
    got = obsolete_os(name, version, BUILDS, TODAY)
    assert (got[0] if got else None) == expected


def test_step_up():
    assert [step_up(s) for s in ("Low", "Medium", "High", "Critical")] == ["Medium", "High", "Critical", "Critical"]


def test_obsolete_os_only_active_enabled_and_dc_step_up():
    exp = mini_export([
        computer("OLD1", 1101, operatingSystem="Windows 7 Professional", operatingSystemVersion="6.1 (7601)"),
        computer("GONE", 1102, operatingSystem="Windows 7 Professional", lastLogonTimestamp=ft(400)),
        computer("OFF", 1103, operatingSystem="Windows 7 Professional", uac=4098),
        dc("DC01", 1001, operatingSystem="Windows Server 2012 R2 Standard", operatingSystemVersion="6.3 (9600)"),
        computer("OK", 1104, operatingSystem="Windows Server 2022 Standard", operatingSystemVersion="10.0 (20348)"),
    ])
    assert {f.identity: f.severity for f in run("ObsoleteOs", exp)} == {"CORP\\OLD1$": "Medium", "CORP\\DC01$": "High"}


def test_inactive_computers_and_dc():
    exp = mini_export([computer("PC1", 1101, lastLogonTimestamp=ft(120)), computer("PC2", 1102), dc("DC02", 1002, lastLogonTimestamp=ft(120)),
                       computer("OFF", 1103, uac=4098, lastLogonTimestamp=ft(500))])
    assert {f.identity: f.severity for f in run("InactiveComputers", exp)} == {"CORP\\PC1$": "Low", "CORP\\DC02$": "High"}


def test_computer_password_age():
    exp = mini_export([computer("PC1", 1101, pwdLastSet=ft(200)), computer("PC2", 1102, pwdLastSet=ft(60)),
                       computer("ASLEEP", 1103, pwdLastSet=ft(200), lastLogonTimestamp=ft(100)), dc("DC01", 1001, pwdLastSet=ft(60))])
    assert {f.identity: f.severity for f in run("ComputerPasswordAge", exp)} == {"CORP\\PC1$": "Low", "CORP\\DC01$": "Medium"}


def test_dc_count():
    one = run("DcCount", mini_export([dc("DC01", 1001)]))
    assert [f.severity for f in one] == ["Low"] and one[0].details["controllers"] == ["DC01"]
    assert run("DcCount", mini_export([computer("PC1", 1101)])) == []
    assert "DcCount" in coverage_gaps(mini_export([computer("PC1", 1101)]))
    assert "DcCount" in coverage_gaps(mini_export([]))
    assert "DcCount" not in coverage_gaps(mini_export([dc("DC01", 1001)]))
    assert run("DcCount", mini_export([dc("DC01", 1001), dc("DC02", 1002)])) == []


def test_dc_delegation():
    exp = mini_export([dc("DC01", 1001, allowedToDelegateTo=["cifs/fs.corp.local"]), dc("DC02", 1002, uac=0x82000 | 0x1000000), dc("DC03", 1003),
                       computer("SRV", 1101, allowedToDelegateTo=["cifs/fs.corp.local"])])
    assert {f.identity for f in run("DcDelegation", exp)} == {"CORP\\DC01$", "CORP\\DC02$"}


def test_dc_owner():
    good = base64.b64encode(sd.build_sd([], owner=rid(512))).decode()
    bad = base64.b64encode(sd.build_sd([], owner=rid(1101))).decode()
    exp = mini_export([user("joiner", 1101), dc("DC01", 1001, sd=good), dc("DC02", 1002, sd=bad)])
    got = run("DcOwner", exp)
    assert [(f.target, f.identity, f.severity) for f in got] == [(next(o.dn for o in exp.objects if o.name == "DC02"), "CORP\\joiner", "Medium")]


def test_coverage_gaps_for_missing_os_and_acl():
    gaps = coverage_gaps(mini_export([dc("DC01", 1001), computer("PC1", 1101)]))
    assert "ObsoleteOs" in gaps and "DcOwner" in gaps
