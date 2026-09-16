"""Поддельный KSC как HTTP-сервер — для прогона PowerShell-скрипта в контейнере.

Запуск: `python -m tests.ksc.fake_ksc_http <port>`; `STOOLS_FAKE_VARIANT=sparse`
переключает на выгрузку с пропущенными полями. Отвечает той же логикой,
что и `FakeKsc.handle` (см. fake_ksc.py), но по-настоящему слушает сокет —
скрипт внутри контейнера ходит на него как на боевой KSC Open API.
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests.ksc.fake_ksc import FakeKsc, parse_request

ksc = FakeKsc(variant=os.environ.get("STOOLS_FAKE_VARIANT", ""))


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # имя метода задаёт BaseHTTPRequestHandler
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length else b""
        method, body = parse_request(self.path, raw_body)
        headers = {k.lower(): v for k, v in self.headers.items()}
        status, payload = ksc.handle(method, body, headers)
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: object) -> None:  # тише вывод в тестах
        pass


def main() -> None:
    port = int(sys.argv[1])
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
