"""Configuration joins only. No DNS, reachability or HTTP request routing inference."""
from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit


def ipv4(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        return None


def parse_listener(value: str) -> dict[str, Any] | None:
    parts = value.split()
    if not parts or 'quic' in parts or '$' in value:
        return None
    host, port = None, parts[0]
    if ':' in port:
        address, port = port.rsplit(':', 1)
        if address not in ('*', '0.0.0.0'):
            host = ipv4(address)
            if host is None:
                return None
    if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        return None
    return {'ip': host, 'port': int(port), 'raw': value}


def match_sites(catalog: list[dict[str, Any]], address: str, port: int | None = None, *, allow_name: bool = False, tls: bool | None = None) -> list[dict[str, Any]]:
    result = []
    address_ip = ipv4(address)
    name = address.lower().rstrip('.')
    for server in catalog:
        addresses: dict[str, str] = {}
        for item in server['addresses']:
            addresses.setdefault(item['ip'], item['source'])
        for site_index, site in enumerate(server['sites']):
            seen = set()
            for raw in site.get('listen', []):
                listener = parse_listener(raw)
                if not listener or (port is not None and listener['port'] != port):
                    continue
                if tls is not None and ('ssl' in raw.split()) != tls:
                    continue
                evidence = None
                if address_ip:
                    if listener['ip'] == address_ip:
                        evidence = 'listen'
                    elif listener['ip'] is None and address_ip in addresses:
                        evidence = addresses[address_ip]
                elif allow_name and name == server['hostname'].lower().rstrip('.') and not (listener['ip'] and ipaddress.IPv4Address(listener['ip']).is_loopback):
                    evidence = 'name'
                if evidence is None or listener['port'] in seen:
                    continue
                seen.add(listener['port'])
                result.append({'snapshot_id': server['snapshot_id'], 'server_id': server['server_id'],
                               'hostname': server['hostname'], 'site': site_index, 'port': listener['port'],
                               'listen': raw, 'domains': site.get('names', []), 'evidence': evidence,
                               'asset': server.get('asset'), 'imported_at': server['imported_at']})
    return result


def _ports(value: Any) -> list[tuple[int, int]] | None:
    if not isinstance(value, str):
        return None
    if value.lower() == 'any':
        return [(1, 65535)]
    ranges = []
    for part in value.split(','):
        match = re.fullmatch(r'\s*([0-9]{1,5})(?:-([0-9]{1,5}))?\s*', part)
        if not match:
            return None
        lo, hi = int(match[1]), int(match[2] or match[1])
        if not 1 <= lo <= hi <= 65535:
            return None
        ranges.append((lo, hi))
    return ranges or None


def nat_candidates(catalog: list[dict[str, Any]], publication: dict[str, Any], rule: dict[str, Any] | None) -> tuple[list[dict[str, Any]], list[str]]:
    warnings = []
    internal = ipv4(publication.get('internal'))
    if not internal or ipaddress.IPv4Address(internal).is_loopback or ipaddress.IPv4Address(internal).is_unspecified or ipaddress.IPv4Address(internal).is_multicast:
        return [], ['Внутренний адрес NAT не является одиночным IPv4; автоматическая связь не построена.']
    if publication.get('protocol') not in ('tcp', 'any'):
        return [], ['Протокол публикации не сопоставляется с HTTP/TCP nginx.']
    ports = _ports(publication.get('ports'))
    # Raw service strings are not a structured translation contract.
    preserved = publication.get('kind') in ('static', 'identity', 'destination_nat') and rule is not None and str(rule.get('service', '')).lower() in ('original', 'any')
    if not preserved:
        warnings.append('Порт после NAT не определён: показаны кандидаты по адресу, связь с портом nginx не подтверждена.')
    if ports is None:
        warnings.append('Порты публикации не распознаны; совпадение порта не подтверждено.')
    candidates = match_sites(catalog, internal)
    if preserved and ports is not None:
        candidates = [c for c in candidates if any(lo <= c['port'] <= hi for lo, hi in ports)]
    return [{**c, 'public_port': c['port'] if preserved and ports is not None else None} for c in candidates], warnings


def target_candidates(catalog: list[dict[str, Any]], target: dict[str, Any], origin: str, *, tls: bool | None = None) -> list[dict[str, Any]]:
    if target.get('port') is None or target.get('dynamic') or 'down' in target.get('parameters', '').split() or str(target.get('address', '')).startswith('unix:'):
        return []
    if not target.get('local'):
        return match_sites(catalog, target.get('host', ''), target.get('port'), allow_name=True, tls=tls)
    address = str(target.get('address', ''))
    try:
        host = urlsplit(address if '://' in address else 'tcp://' + address).hostname
    except ValueError:
        return []
    # localhost may resolve to IPv6 or an overridden address: do not invent that mapping.
    loopback = ipv4(host)
    if not loopback or not ipaddress.IPv4Address(loopback).is_loopback:
        return []
    local = [{**server, 'addresses': [{'ip': loopback, 'source': 'loopback'}]} for server in catalog if server['hostname'] == origin]
    return match_sites(local, loopback, target.get('port'), tls=tls)
