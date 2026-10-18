"""Поддельный JSON API RackTables на 127.0.0.1: HTTP Basic, POST с JSON, метод в `func`.

Отвечает как настоящий: 200 и JSON на успех, 400 и текст на ошибку, 401 без правильной учётки.
Сети — словарь id → ячейка (как `listCells`), адреса — список по диапазону.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Self

VERSION = "1.3.3"


def network_cell(rt_id: str, cidr: str, name: str = "", *, comment: str | None = None, vlan: str | None = None, tags: list[str] = (), kidc: int = 0) -> dict[str, Any]:
    net = ipaddress.ip_network(cidr)
    return {
        "realm": "ipv4net", "id": rt_id, "ip": str(net.network_address), "mask": str(net.prefixlen), "name": name, "comment": comment,
        "8021q": [{"domain_id": "1", "vlan_id": vlan}] if vlan else [], "etags": [{"tag": t} for t in tags], "itags": [],
        "atags": [{"tag": "$any_net"}], "kidc": kidc, "spare_ranges": [], "ip_bin": "", "mask_bin": None, "vlanc": 1 if vlan else 0,
    }


def address_cell(ip: str, name: str = "", comment: str = "", reserved: bool = False) -> dict[str, Any]:
    return {"ip_address": ip, "name": name, "comment": comment, "is_reserved": "yes" if reserved else "no"}


class FakeRacktables:
    def __init__(self, username: str = "svc", password: str = "pw") -> None:
        self.username, self.password = username, password
        self.networks: dict[str, dict[str, Any]] = {}
        self.addresses: list[dict[str, Any]] = []
        self.calls: list[dict[str, Any]] = []
        self.fail_all = False
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                pass

            def do_POST(self) -> None:
                # Тело читается до проверки учётки: иначе соединение рвётся, а не отвечает 401.
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                expected = "Basic " + base64.b64encode(f"{fake.username}:{fake.password}".encode()).decode()
                if self.headers.get("Authorization") != expected:
                    self.send_response(401)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                fake.calls.append(body)
                status, payload = fake.dispatch(body)
                data = payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/plain" if isinstance(payload, str) else "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port: int = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}/json_api.php"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()

    def add_network(self, rt_id: str, cidr: str, name: str = "", **kw: Any) -> None:
        self.networks[rt_id] = network_cell(rt_id, cidr, name, **kw)

    def add_address(self, ip: str, name: str = "", **kw: Any) -> None:
        self.addresses = [a for a in self.addresses if a["ip_address"] != ip] + [address_cell(ip, name, **kw)]

    def dispatch(self, body: dict[str, Any]) -> tuple[int, Any]:
        func = body.get("func")
        if self.fail_all:
            return 400, "Database is unavailable"
        if func == "getAPIVersion":
            return 200, VERSION
        if func == "listCells":
            if body.get("realm") != "ipv4net":
                return 400, f"realm {body.get('realm')} is not supported by the fake"
            return 200, self.networks
        if func == "getIPAddressList":
            lo, hi = int(ipaddress.ip_address(body["ipStart"])), int(ipaddress.ip_address(body["ipEnd"]))
            return 200, [a for a in self.addresses if lo <= int(ipaddress.ip_address(a["ip_address"])) <= hi]
        return 400, f"Unknown function {func}"
