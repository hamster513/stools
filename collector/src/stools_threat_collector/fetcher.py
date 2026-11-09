import ipaddress
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit

import httpx


class FetchError(ValueError):
    def __init__(self, message, retry_after=0):
        super().__init__(message)
        self.retry_after = retry_after


def resolve(host):
    return list({row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})


class Fetcher:
    def __init__(self, proxy=None, ca=None, transport=None, resolver=resolve, max_bytes=5 * 1024 * 1024):
        self.proxy = proxy or None
        self.context = ssl.create_default_context()
        if ca:
            self.context.load_verify_locations(cafile=ca)
        self.transport = transport
        self.resolver = resolver
        self.max_bytes = max_bytes
        self.deadline = time.monotonic() + 120

    def get(self, url, headers=None, allowed_hosts=None):
        original = urlsplit(url)
        allowed_hosts = allowed_hosts or {original.hostname}
        deadline = self.deadline
        with httpx.Client(proxy=self.proxy, verify=self.context, trust_env=False, transport=self.transport,
                          timeout=httpx.Timeout(30, connect=10), follow_redirects=False) as client:
            for _ in range(6):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise FetchError("source time budget exceeded")
                parts = urlsplit(url)
                if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
                    raise FetchError("invalid source URL")
                if parts.hostname not in allowed_hosts:
                    raise FetchError("redirect outside source domains")
                try:
                    addresses = self.resolver(parts.hostname)
                    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
                        raise FetchError("source resolved to non-public address")
                except (OSError, ValueError) as exc:
                    raise FetchError("source DNS or address rejected") from exc
                # Pin the checked address, preserving TLS SNI and the HTTP Host. A second
                # DNS lookup in the transport could otherwise bypass the address check.
                target = httpx.URL(url).copy_with(host=addresses[0])
                safe_headers = dict(headers or {})
                if (parts.scheme, parts.netloc) != (original.scheme, original.netloc):
                    safe_headers = {k:v for k,v in safe_headers.items() if k.lower() in ("user-agent", "accept")}
                request_headers = {"User-Agent": "STools-Threat-Collector/0.1", "Host": parts.netloc, **safe_headers}
                with client.stream("GET", target, headers=request_headers,
                                   timeout=httpx.Timeout(min(30, remaining), connect=min(10, remaining)),
                                   extensions={"sni_hostname": parts.hostname}) as response:
                    if response.has_redirect_location:
                        url = urljoin(url, response.headers.get("location", ""))
                        continue
                    if response.status_code == 429:
                        retry = response.headers.get("retry-after", "300")
                        raise FetchError("source rate limited", int(retry) if retry.isdigit() else 300)
                    if response.status_code != 304:
                        response.raise_for_status()
                    chunks, size = [], 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > self.max_bytes:
                            raise FetchError("response size limit exceeded")
                        if time.monotonic() > deadline:
                            raise FetchError("source time budget exceeded")
                        chunks.append(chunk)
                    clean_headers = {key: value for key, value in response.headers.items()
                                     if key.lower() not in ("content-encoding", "content-length")}
                    return httpx.Response(response.status_code, headers=clean_headers,
                                          content=b"".join(chunks), request=httpx.Request("GET", url))
        raise FetchError("too many source redirects")
