"""Минимальная выгрузка для проверок гигиены: только то, что нужно тесту.

Базовые объекты домена (корень, Administrator, krbtgt, Domain Admins,
Administrators, Domain Users, Protected Users) кладутся всегда и ничего
не нарушают; тест добавляет свои объекты. Переданный объект с тем же dn,
что у базового, заменяет базовый.
"""
from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from api.modules.ad.core import sd
from api.modules.ad.core.ca_data import CaData
from api.modules.ad.core.checks import CHECK_BY_CODE
from api.modules.ad.core.config import AdConfig
from api.modules.ad.core.export import AdExport, ExportIndex
from api.modules.ad.core.findings import Finding
from tests.ad.synthetic import DN, DOMAIN_SID, NOW, b64sd, ft, rid

__all__ = ["DN", "DOMAIN_SID", "NOW", "b64sd", "computer", "dc", "ft", "group", "mini_export", "rid", "run", "user"]


def user(sam: str, r: int, **extra: Any) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "dn": f"CN={sam},CN=Users,{DN}", "class": "user", "sid": rid(r), "sam": sam, "name": sam,
        "uac": 512, "lastLogonTimestamp": ft(3), "pwdLastSet": ft(30),
    }
    return {**obj, **extra}


def computer(name: str, r: int, **extra: Any) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "dn": f"CN={name},CN=Computers,{DN}", "class": "computer", "sid": rid(r), "sam": f"{name}$", "name": name,
        "uac": 4096, "dNSHostName": f"{name.lower()}.corp.local", "lastLogonTimestamp": ft(3), "pwdLastSet": ft(30),
    }
    return {**obj, **extra}


def dc(name: str, r: int, **extra: Any) -> dict[str, Any]:
    # SERVER_TRUST_ACCOUNT | TRUSTED_FOR_DELEGATION — как у настоящего контроллера.
    return computer(name, r, **{"dn": f"CN={name},OU=Domain Controllers,{DN}", "uac": 0x82000, **extra})


def group(sam: str, sid: str, members: Sequence[str] = (), **extra: Any) -> dict[str, Any]:
    obj: dict[str, Any] = {"dn": f"CN={sam},CN=Users,{DN}", "class": "group", "sid": sid, "sam": sam, "name": sam, "member": list(members)}
    return {**obj, **extra}


def mini_export(objects: Sequence[dict[str, Any]] = (), *, admins: Sequence[str] = (), domain: dict[str, Any] | None = None, **top: Any) -> AdExport:
    administrator = user("Administrator", 500, lastLogonTimestamp=ft(60))
    domain_admins = group("Domain Admins", rid(512), [administrator["dn"], *(f"CN={sam},CN=Users,{DN}" for sam in admins)])
    base = [
        {"dn": DN, "class": "domainDNS", "sid": DOMAIN_SID, "sd": b64sd([sd.build_ace(rid(512), sd.GENERIC_ALL)])},
        administrator,
        user("krbtgt", 502, uac=514),
        domain_admins,
        group("Administrators", "S-1-5-32-544", [domain_admins["dn"]]),
        group("Domain Users", rid(513)),
        group("Protected Users", rid(525)),
    ]
    own = {o["dn"].lower() for o in objects}
    raw: dict[str, Any] = {
        "format": "stools-ad/1",
        "collected_at": NOW.isoformat(),
        "domain": {"dn": DN, "sid": DOMAIN_SID, "dns_root": "corp.local", "netbios": "CORP", "machine_account_quota": 0, "functional_level": "7", **(domain or {})},
        "objects": [o for o in base if o["dn"].lower() not in own] + list(objects),
        **top,
    }
    return AdExport.model_validate(raw)


def run(code: str, export: AdExport, cfg: AdConfig | None = None, ca: CaData | None = None) -> list[Finding]:
    return CHECK_BY_CODE[code].func(ExportIndex(export, ca), cfg or AdConfig())
