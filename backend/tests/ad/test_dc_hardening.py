import datetime as dt

from api.modules.ad.core.ca_data import CaData, parse_ca_data
from tests.ad.mini import NOW, mini_export, run
from tests.ad.synthetic import build_ca_data


def ca(**dc: object) -> CaData:
    base = {"host": "dc01.corp.local", "strong_binding": 2, "mapping_methods": 0x18, "registry_read": True, "cim_read": True}
    return parse_ca_data(build_ca_data(sections=["dc"], cas=[], web=[], dcs=[{**base, **dc}]))


def kinds(dc_fields: dict[str, object]) -> dict[str, str]:
    return {f.key_extra: f.severity for f in run("DcHardening", mini_export(), ca=ca(**dc_fields))}


HARD = {"lm_compatibility": 5, "no_lm_hash": 1, "ldap_integrity": 2, "ldap_channel_binding": 2, "smb1": False, "smb_require_signing": True,
        "spooler": "disabled", "webclient": "absent", "last_boot": (NOW - dt.timedelta(days=20)).isoformat(),
        "tls": {"SSL 3.0": 0, "TLS 1.0": 0, "TLS 1.1": 0}}


def test_hardened_dc_is_clean() -> None:
    assert kinds(HARD) == {}


def test_defaults_when_registry_has_no_values() -> None:
    got = kinds({**HARD, "lm_compatibility": None, "ldap_integrity": None, "ldap_channel_binding": None})
    assert got == {"ntlmv1": "Medium", "ldap_signing": "Medium", "channel_binding": "Medium"}


def test_each_weakness() -> None:
    weak = {"lm_compatibility": 2, "no_lm_hash": 0, "ldap_integrity": 1, "ldap_channel_binding": 1, "smb1": True, "smb_require_signing": False,
            "spooler": "running", "webclient": "running", "last_boot": (NOW - dt.timedelta(days=400)).isoformat(),
            "tls": {"SSL 3.0": None, "TLS 1.0": 1, "TLS 1.1": 0}}
    assert kinds(weak) == {"ntlmv1": "High", "lm_hash": "Medium", "ldap_signing": "Medium", "channel_binding": "Low", "smb1": "High",
                           "smb_signing": "High", "spooler": "Medium", "webclient": "Low", "uptime": "Medium", "tls_old": "Low"}


def test_unread_channels_give_no_findings() -> None:
    assert kinds({"registry_read": False, "cim_read": False}) == {}
    assert run("DcHardening", mini_export()) == []          # данных контроллеров нет вовсе


def test_ntlm_level_4_still_accepts_ntlmv1() -> None:
    assert kinds({**HARD, "lm_compatibility": 4}) == {"ntlmv1": "Medium"}


def test_null_cim_fields_of_read_channel_give_no_findings() -> None:
    assert kinds({**HARD, "smb1": None, "smb_require_signing": None, "spooler": None, "webclient": None, "last_boot": None}) == {}


def test_tls_absent_values_are_not_findings() -> None:
    assert kinds({**HARD, "tls": None}) == {}
    assert kinds({**HARD, "tls": {"SSL 3.0": None, "TLS 1.0": None, "TLS 1.1": None}}) == {}


def test_uptime_threshold_from_settings() -> None:
    from api.modules.ad.core.config import AdConfig

    data = ca(**{**HARD, "last_boot": (NOW - dt.timedelta(days=40)).isoformat()})
    assert run("DcHardening", mini_export(), ca=data) == []
    got = run("DcHardening", mini_export(), cfg=AdConfig(dc_max_uptime_days=30), ca=data)
    assert [(f.key_extra, f.target) for f in got] == [("uptime", "dc01.corp.local")]
    assert got[0].details["value"] == 40


def test_details_name_default_and_collection_date() -> None:
    (f,) = run("DcHardening", mini_export(), ca=ca(**{**HARD, "ldap_integrity": None}))
    assert f.check == "DcHardening" and f.target == "dc01.corp.local" and not f.allowlisted
    assert f.details["value"] == 1 and f.details["default"] is True
    assert f.details["ca_data_collected_at"] == NOW.isoformat()
    (g,) = run("DcHardening", mini_export(), ca=ca(**{**HARD, "ldap_integrity": 0}))
    assert g.details["value"] == 0 and g.details["default"] is False
