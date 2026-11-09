"""Bounded local lookup: validated identifiers and evidence, never identity merging."""

from __future__ import annotations

import datetime as dt
import re
from ipaddress import ip_address
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import case, cast, func, or_
from sqlalchemy.dialects.postgresql import INET

LIMIT = 20
Kind = Literal["auto", "ip", "host", "domain", "cve"]


class LookupRequest(BaseModel):
    query: str = Field(min_length=1, max_length=255)
    kind: Kind = "auto"


class Fact(BaseModel):
    label: str
    value: str


class Evidence(BaseModel):
    id: str
    title: str
    reason: str
    source: str
    href: str
    observed_at: dt.datetime | dt.date | None = None
    date_label: str = "Дата данных"
    facts: list[Fact] = Field(default_factory=list)


class Group(BaseModel):
    id: str
    title: str
    status: Literal["searched", "denied", "not_applicable"] = "searched"
    note: str = ""
    items: list[Evidence] = Field(default_factory=list)
    has_more: bool = False

    def fill(self, items: list[Evidence]) -> Group:
        self.items = items[:LIMIT]
        self.has_more = len(items) > LIMIT
        return self


class LookupResult(BaseModel):
    query: str
    kind: str
    searched_at: dt.datetime
    groups: list[Group]


def parse_query(raw: str, kind: Kind) -> tuple[str, str]:
    q = raw.strip()
    if not q or len(q) > 253:
        raise ValueError("Введите IP, имя хоста, домен или CVE (до 253 символов).")
    if kind == "cve" or (kind == "auto" and q.upper().startswith("CVE-")):
        if not re.fullmatch(r"CVE-\d{4}-\d{4,19}", q, re.IGNORECASE):
            raise ValueError("CVE должен иметь вид CVE-2026-12345.")
        return q.upper(), "cve"
    try:
        ip = ip_address(q)
    except ValueError:
        ip = None
    if kind == "ip" or (
        kind == "auto" and (ip is not None or ":" in q or re.fullmatch(r"[\d.]+", q))
    ):
        if ip is None or "%" in q:
            raise ValueError("Введите корректный адрес IPv4 или IPv6 без маски и зоны интерфейса.")
        return str(ip), "ip"
    q = q.rstrip(".").lower()
    # Windows hostnames can contain underscores. Wildcards, URL and free text are not identifiers.
    if not re.fullmatch(r"[\w-]+(?:\.[\w-]+)*", q, re.ASCII) or any(
        len(s) > 63 for s in q.split(".")
    ):
        raise ValueError("Введите точное имя хоста или домена без URL, пробелов и масок поиска.")
    return q, "name" if kind == "auto" else kind


def identity(q: str, kind: str, *, name: Any, fqdn: Any, domain: Any, ip: Any) -> Any:
    if kind == "ip":
        # PostgreSQL 16 soft validation keeps malformed legacy values from aborting lookup.
        valid_ip = case((func.pg_input_is_valid(ip, "inet"), cast(ip, INET)), else_=None)
        return valid_ip == cast(q, INET)
    names = or_(func.lower(name) == q, func.lower(func.rtrim(fqdn, ".")) == q)
    domains = func.lower(func.rtrim(domain, ".")) == q
    return domains if kind == "domain" else names if kind == "host" else or_(names, domains)


def facts(**values: Any) -> list[Fact]:
    return [Fact(label=k, value=str(v)) for k, v in values.items() if v is not None and v != ""]
