# ruff: noqa: SIM117
"""Real TLS and CONNECT transport: no mock transport or direct-route fallback."""
import base64
import json
import select
import socket
import socketserver
import ssl
import subprocess
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from api.modules.vm.services.trends.client import CollectorClient, CollectorError
from api.modules.vm.services.trends.settings import TrendConnectionIn


@pytest.fixture
def certificates(tmp_path):
    config = tmp_path / 'openssl.cnf'
    config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:TRUE\n')
    cert, key = tmp_path/'cert.pem', tmp_path/'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-config', str(config), '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    return context, cert.read_text()


@contextmanager
def serving(server, context=None):
    if context:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_direct_http_connect_https_proxy_and_failure_no_fallback(certificates):
    context, pem = certificates
    requests, tunnels = [], []
    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, self.headers.get('Authorization'), self.headers.get('Proxy-Authorization')))
            payload = json.dumps({'protocol_version': 1, 'collector_id': 'test', 'epoch': 'one', 'last_seq': 2}).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        def log_message(self, *args):
            pass
    class Proxy(socketserver.StreamRequestHandler):
        def handle(self):
            first = self.rfile.readline().decode().strip()
            headers = {}
            while line := self.rfile.readline().decode().strip():
                key, value = line.split(':', 1)
                headers[key.lower()] = value.strip()
            tunnels.append((first, headers))
            if headers.get('proxy-authorization') != 'Basic ' + base64.b64encode(b'proxy:secret').decode():
                self.wfile.write(b'HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n')
                self.wfile.flush()
                return
            target = first.split()[1]
            host, port = target.rsplit(':', 1)
            with socket.create_connection((host, int(port)), timeout=5) as upstream:
                self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                self.wfile.flush()
                while True:
                    ready, _, _ = select.select([self.connection, upstream], [], [], 3)
                    if not ready:
                        return
                    for src in ready:
                        data = src.recv(65536)
                        if not data:
                            return
                        (upstream if src is self.connection else self.connection).sendall(data)
    with serving(ThreadingHTTPServer(('127.0.0.1', 0), Origin), context) as origin:
        base = {'url': f'https://localhost:{origin}', 'token': 'private-token', 'ca_pem': pem}
        with CollectorClient(TrendConnectionIn(**base)) as client:
            expected = client.info()
        for scheme in ('http', 'https'):
            with serving(socketserver.ThreadingTCPServer(('127.0.0.1', 0), Proxy), context if scheme == 'https' else None) as port:
                config = {**base, 'proxy_enabled': True, 'proxy_scheme': scheme, 'proxy_host': 'localhost',
                          'proxy_port': port, 'proxy_username': 'proxy', 'proxy_password': 'secret', 'proxy_ca_pem': pem}
                with CollectorClient(TrendConnectionIn(**config)) as client:
                    assert client.info() == expected
                before = len(requests)
                with CollectorClient(TrendConnectionIn(**{**config, 'proxy_password': 'wrong'})) as client:
                    with pytest.raises(CollectorError, match='прокси'):
                        client.info()
                assert len(requests) == before
        assert len(requests) == 3
        assert all(auth == 'Bearer private-token' and proxy_auth is None for _, auth, proxy_auth in requests)
        assert all('authorization' not in headers for _, headers in tunnels)
        with CollectorClient(TrendConnectionIn(**{**base, 'ca_pem': ''})) as client:
            with pytest.raises(CollectorError, match='TLS'):
                client.info()
