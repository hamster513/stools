"""Клиент Harbor (API v2.0): проекты, репозитории, артефакты с обзором скана и отчёт Trivy.

Без базы и без FastAPI: HTTP-клиент передаётся снаружи, чтобы тесты подменяли
транспорт, а не сеть. Аутентификация — учётная запись-робот (Basic).

Мультиархитектурный индекс — один артефакт: Harbor хранит обзор скана и отчёт
на самом индексе, поэтому детей индекса клиент не обходит, а только перечисляет
их платформы.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from api.hosts import LOGIN_REJECTED, NO_LINK, NO_RIGHTS, TLS_FAILED, is_tls_error, server_error
from api.limits import MAX_API_RESPONSE, ResponseTooLarge, read_limited

REPORT_MIME = "application/vnd.security.vulnerability.report; version=1.1"
REPORT_MIME_OLD = "application/vnd.security.vulnerability.report; version=1.0"

BAD_FORMAT = "BAD_FORMAT"
PAGE_SIZE = 100
#: Предохранитель от бесконечной пагинации при неисправном `X-Total-Count`
#: (200 страниц по 100 — 20 000 записей в одном списке).
MAX_PAGES = 200
DESCRIPTION_LIMIT = 2000
SEVERITIES = ("critical", "high", "medium", "low", "unknown")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE | re.ASCII)
_SCAN_STATUSES = frozenset({"success", "pending", "running", "error", "none"})
#: Harbor отдаёт обзор скана только тому, кто сказал, какие отчёты он понимает.
_ACCEPT = f"{REPORT_MIME}, {REPORT_MIME_OLD}"
#: Статусы скана Harbor, которых нет в словаре `success|pending|running|error|none`.
_STATUS_ALIASES = {"scheduled": "pending", "stopped": "error"}


class HarborConnectionLike(Protocol):
    url: str
    robot_name: str
    robot_secret: str
    verify_tls: bool


@dataclass(frozen=True)
class HarborInfo:
    version: str


@dataclass(frozen=True)
class HarborRepo:
    project: str
    name: str
    artifact_count: int
    update_time: datetime | None


@dataclass(frozen=True)
class HarborArtifact:
    digest: str
    tags: tuple[str, ...]
    size: int | None
    push_time: datetime | None
    media_type: str
    is_index: bool
    #: «os/arch» детей индекса из `references[]` без `os == "unknown"` (это аттестации);
    #: у обычного образа пусто.
    platforms: tuple[str, ...]
    scan_status: str  # success|pending|running|error|none
    scanned_at: datetime | None
    scanner: str | None
    #: Ключи: critical high medium low unknown total.
    trivy_counts: dict[str, int]
    artifact_kind: str = "unknown"
    reported_total: int | None = None


@dataclass(frozen=True)
class HarborVuln:
    vuln_id: str
    package: str
    installed_version: str
    fixed_version: str | None
    #: Строчными буквами, как ключи `trivy_counts`: critical high medium low unknown.
    severity: str
    cvss: float | None
    description: str | None
    link: str | None


class HarborError(Exception):
    """`kind` — класс отказа: `NO_LINK`, `TLS_FAILED`, `LOGIN_REJECTED`, `NO_RIGHTS`,
    `server_error(код)`, `BAD_FORMAT` или `HTTP <код>` для прочих ответов.
    `status` — код HTTP, если отказ пришёл с ним."""

    def __init__(self, kind: str, status: int | None = None) -> None:
        super().__init__(kind)
        self.kind = kind
        self.status = status


def is_cve(vuln_id: str) -> bool:
    return _CVE.fullmatch(vuln_id) is not None


def make_harbor_client(conn: HarborConnectionLike, timeout: float = 60.0) -> httpx.Client:
    return httpx.Client(
        auth=(conn.robot_name, conn.robot_secret),
        verify=conn.verify_tls,
        timeout=timeout,
        follow_redirects=False,
    )


def _time(value: object) -> datetime | None:
    """Время Harbor: ISO с `Z` и долями секунды до наносекунд. «Нулевое» время
    (`0001-01-01…`) — значит «не было»."""
    if not isinstance(value, str) or not value:
        return None
    text = re.sub(r"(\.\d{6})\d+", r"\1", value.strip())
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return None if parsed.year < 1900 else parsed


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _enc(name: str) -> str:
    """Имя репозитория в пути Harbor кодируется дважды: `a/b` → `a%252Fb`."""
    return quote(quote(name, safe=""), safe="")


def _tagged_digests(items: list[Any]) -> set[str]:
    """Разные digest артефактов с тегами в сыром списке Harbor."""
    found: set[str] = set()
    for raw in items:
        item = _dict(raw)
        digest, tags = item.get("digest"), item.get("tags")
        if isinstance(digest, str) and digest and isinstance(tags, list) and tags:
            found.add(digest)
    return found


def _project_path(project: str) -> str:
    return f"/projects/{quote(project, safe='')}"


class HarborClient:
    def __init__(self, conn: HarborConnectionLike, http: httpx.Client) -> None:
        self.conn = conn
        self.http = http
        self._registry_tokens: dict[str, str] = {}
        self._system_allowlist: dict | HarborError | None = None

    def runtime_image_ids(self, project: str, repository: str, digest: str) -> list[str]:
        from api.modules.vm.core.registry_manifests import image_ids

        return image_ids(self, project, repository, digest)

    @property
    def base(self) -> str:
        url = self.conn.url.strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return f"{url}/api/v2.0"

    def _get(self, path: str, params: dict[str, Any] | None = None, *, resource_name: bool = False) -> tuple[Any, httpx.Headers]:
        """GET → (JSON, заголовки). Любой сбой — `HarborError`."""
        headers = {"Accept": "application/json", "X-Accept-Vulnerabilities": _ACCEPT}
        if resource_name:
            headers["X-Is-Resource-Name"] = "true"
        try:
            with self.http.stream("GET", f"{self.base}{path}", params=params, headers=headers) as r:
                status = r.status_code
                if status == 401:
                    raise HarborError(LOGIN_REJECTED, status)
                if status == 403:
                    raise HarborError(NO_RIGHTS, status)
                if status >= 500:
                    raise HarborError(server_error(status), status)
                if status != 200:
                    raise HarborError(f"HTTP {status}", status)
                body = read_limited(r, MAX_API_RESPONSE)
                response_headers = r.headers
        except HarborError:
            raise
        except ResponseTooLarge as exc:
            raise HarborError(BAD_FORMAT) from exc
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            raise HarborError(TLS_FAILED if is_tls_error(exc) else NO_LINK) from exc
        try:
            return json.loads(body), response_headers
        except ValueError as exc:
            raise HarborError(BAD_FORMAT) from exc

    def _pages(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        page_size: int = PAGE_SIZE,
        enough: Callable[[list[Any]], bool] | None = None,
    ) -> list[Any]:
        """Все элементы списка: `page=1..`, пока `page * page_size < X-Total-Count`;
        без заголовка — пока страница полная. Сервер, игнорирующий `page`, отдаёт одну и ту же
        страницу: первый элемент страницы повторил первый элемент предыдущей — конец списка.
        `enough(items)` — собранного достаточно, дальше не листать. Больше `MAX_PAGES`
        страниц — `BAD_FORMAT`: усечённый список не выдаётся за полный."""
        items: list[Any] = []
        previous_first: Any = None
        for page in range(1, MAX_PAGES + 1):
            data, headers = self._get(path, {**(params or {}), "page": page, "page_size": page_size})
            if not isinstance(data, list):
                raise HarborError(BAD_FORMAT)
            if page > 1 and data and data[0] == previous_first:
                break
            items.extend(data)
            if enough is not None and enough(items):
                break
            total = headers.get("X-Total-Count", "")
            more = page * page_size < int(total) if total.isascii() and total.isdigit() else len(data) >= page_size
            if not more or not data:
                break
            previous_first = data[0]
        else:
            # Страницы кончились раньше списка: усечённый список не должен сойти за полный —
            # по нему синхронизация удаляет пропавшее.
            raise HarborError(BAD_FORMAT)
        return items

    def probe(self) -> HarborInfo:
        """Версия Harbor. `systeminfo` открыт всем, поэтому вход проверяет второй запрос — список проектов."""
        info, _ = self._get("/systeminfo")
        self._get("/projects", {"page": 1, "page_size": 1})
        version = _dict(info).get("harbor_version")
        if not isinstance(version, str) or not version:
            raise HarborError(BAD_FORMAT)
        return HarborInfo(version=version.split("-", 1)[0])

    def projects(self) -> list[str]:
        names = [_dict(p).get("name") for p in self._pages("/projects")]
        return [n for n in names if isinstance(n, str) and n]

    def system_allowlist(self) -> dict:
        if self._system_allowlist is None:
            try:
                value, _ = self._get("/system/CVEAllowlist")
                if not isinstance(value, dict):
                    raise HarborError(BAD_FORMAT)
                self._system_allowlist = value
            except HarborError as exc:
                self._system_allowlist = exc
        if isinstance(self._system_allowlist, HarborError):
            raise self._system_allowlist
        return self._system_allowlist

    def project_policy(self, project: str) -> dict[str, Any]:
        from api.modules.vm.core.harbor_policy import project_policy

        raw, _ = self._get(_project_path(project), resource_name=True)
        try:
            return project_policy(raw, self.system_allowlist)
        except (TypeError, ValueError) as exc:
            raise HarborError(BAD_FORMAT) from exc

    def repositories(self, project: str) -> list[HarborRepo]:
        prefix = f"{project}/"
        repos: list[HarborRepo] = []
        for raw in self._pages(f"{_project_path(project)}/repositories"):
            item = _dict(raw)
            full = item.get("name")
            if not isinstance(full, str) or not full:
                continue
            repos.append(
                HarborRepo(
                    project=project,
                    name=full.removeprefix(prefix),
                    artifact_count=_int(item.get("artifact_count")),
                    update_time=_time(item.get("update_time")),
                )
            )
        return repos

    def artifacts(self, project: str, repo: str, limit: int | None = None) -> list[HarborArtifact]:
        """Тегированные артефакты репозитория, свежие первыми (`sort=-push_time`, `q=tags=*`).
        `limit` — сколько разных тегированных digest нужно: дальше история не листается."""
        path = f"{_project_path(project)}/repositories/{_enc(repo)}/artifacts"
        params = {"with_scan_overview": "true", "with_tag": "true", "sort": "-push_time", "q": "tags=*"}

        def enough(items: list[Any]) -> bool:
            return limit is not None and len(_tagged_digests(items)) >= limit

        page_size = min(PAGE_SIZE, limit) if limit is not None and limit > 0 else PAGE_SIZE
        raws = self._pages(path, params, page_size, enough if limit is not None else None)
        found = [self._artifact(_dict(raw)) for raw in raws]
        return [a for a in found if a.digest]

    @staticmethod
    def _artifact(raw: dict[str, Any]) -> HarborArtifact:
        from api.modules.vm.core.harbor_policy import artifact_kind

        media_type = raw.get("manifest_media_type")
        media = media_type if isinstance(media_type, str) else ""
        tags = tuple(n for n in (_dict(t).get("name") for t in raw.get("tags") or []) if isinstance(n, str) and n)
        platforms: list[str] = []
        for ref in raw.get("references") or []:
            platform = _dict(_dict(ref).get("platform"))
            os_name, arch = platform.get("os"), platform.get("architecture")
            if not isinstance(os_name, str) or not isinstance(arch, str) or os_name == "unknown":
                continue
            label = f"{os_name}/{arch}"
            if label not in platforms:
                platforms.append(label)

        overview = _dict(raw.get("scan_overview"))
        report = _dict(overview.get(REPORT_MIME) or overview.get(REPORT_MIME_OLD))
        status = report.get("scan_status")
        scan_status = "none"
        if isinstance(status, str) and status:
            scan_status = _STATUS_ALIASES.get(status.lower(), status.lower())
            if scan_status not in _SCAN_STATUSES:
                scan_status = "none"
        scanner_info = _dict(report.get("scanner"))
        scanner = " ".join(str(scanner_info[k]) for k in ("name", "version") if scanner_info.get(k)) or None
        summary = _dict(report.get("summary"))
        by_severity = _dict(summary.get("summary"))
        counts = {sev: _int(by_severity.get(sev.capitalize())) for sev in SEVERITIES}
        counts["total"] = _int(summary.get("total"))
        total = summary.get("total")
        reported_total = total if isinstance(total, int) and not isinstance(total, bool) and total >= 0 else None

        size = raw.get("size")
        return HarborArtifact(
            digest=str(raw.get("digest") or ""),
            tags=tags,
            size=size if isinstance(size, int) and not isinstance(size, bool) else None,
            push_time=_time(raw.get("push_time")),
            media_type=media,
            is_index="manifest.list" in media or "image.index" in media,
            platforms=tuple(platforms),
            scan_status=scan_status,
            scanned_at=_time(report.get("end_time")),
            scanner=scanner,
            trivy_counts=counts,
            artifact_kind=artifact_kind(raw),
            reported_total=reported_total,
        )

    def vulnerabilities(self, project: str, repo: str, digest: str) -> list[HarborVuln]:
        path = (
            f"{_project_path(project)}/repositories/{_enc(repo)}"
            f"/artifacts/{quote(digest, safe=':')}/additions/vulnerabilities"
        )
        data, _ = self._get(path)
        report = _dict(data).get(REPORT_MIME)
        if report is None:
            report = _dict(data).get(REPORT_MIME_OLD)
        if not isinstance(report, dict):
            raise HarborError(BAD_FORMAT)
        vulns: list[HarborVuln] = []
        if "vulnerabilities" not in report:
            raise HarborError(BAD_FORMAT)
        raw_vulns = report.get("vulnerabilities")
        if raw_vulns is None:
            # Harbor represents a completed empty report with null as well as [].
            raw_vulns = []
        if not isinstance(raw_vulns, list):
            raise HarborError(BAD_FORMAT)
        for raw in raw_vulns:
            item = _dict(raw)
            vuln_id = item.get("id")
            if not isinstance(vuln_id, str) or not vuln_id:
                raise HarborError(BAD_FORMAT)
            links = [x for x in item.get("links") or [] if isinstance(x, str) and x]
            score = _dict(item.get("preferred_cvss")).get("score_v3")
            description = item.get("description")
            severity = item.get("severity")
            fixed = item.get("fix_version")
            vulns.append(
                HarborVuln(
                    vuln_id=vuln_id,
                    package=str(item.get("package") or ""),
                    installed_version=str(item.get("version") or ""),
                    fixed_version=fixed if isinstance(fixed, str) and fixed else None,
                    severity=severity.lower() if isinstance(severity, str) and severity.lower() in SEVERITIES else "unknown",
                    cvss=float(score) if isinstance(score, (int, float)) and not isinstance(score, bool) else None,
                    description=description[:DESCRIPTION_LIMIT] if isinstance(description, str) and description else None,
                    link=links[0] if links else None,
                )
            )
        return vulns
