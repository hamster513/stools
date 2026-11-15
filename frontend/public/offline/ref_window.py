"""Portable reference updates for (since, until], independent of STools state.

Only HTTP snapshot validators are cached. NVD and GHSA periods never require or
invent a full-import checkpoint, and source failures never trigger full feeds.
"""
from __future__ import annotations

import calendar
import hashlib
import json
import os
import re
import tempfile
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote, urlencode

try:  # Package import in backend; sibling import in the downloadable offline kit.
    from . import ref_updates as shared
except ImportError:
    import ref_updates as shared  # type: ignore[no-redef]

Http = Callable[[str, dict[str, str]], shared.HttpResponse]
RevisionResolver = Callable[[datetime, Http, str], str]


def period_bounds(period: str, now: datetime | None = None) -> tuple[datetime, datetime]:
    """Return UTC second-resolution (exclusive start, inclusive end) bounds.

    Three months means calendar months with the day clamped to the target month.
    Naive caller-supplied timestamps are interpreted as UTC, never machine time.
    """
    until = now or datetime.now(UTC)
    if until.tzinfo is None:
        until = until.replace(tzinfo=UTC)
    until = until.astimezone(UTC).replace(microsecond=0)
    if period in ("1d", "7d"):
        since = until - timedelta(days=1 if period == "1d" else 7)
    elif period == "3m":
        year, month = divmod(until.year * 12 + until.month - 4, 12)
        month += 1
        since = until.replace(year=year, month=month,
                              day=min(until.day, calendar.monthrange(year, month)[1]))
    else:
        raise ValueError("period must be 1d, 7d, or 3m")
    return since, until


@dataclass(frozen=True)
class GitWindowChanges:
    """Exact pinned-tree changes; moves are represented as delete plus add."""

    base_revision: str
    target_revision: str
    changed: list[str]
    deleted: list[str]


class GitWindowSource:
    """Resolve two public GitHub revisions and diff their blob-filtered trees.

    The end revision is resolved first. The cutoff lookup is anchored to that
    same immutable revision, so a concurrent branch move cannot mix histories.
    No GitHub compare/file-list truncation, full archive, or checkout is used.
    revision_resolver is an injectable local-fixture transport, not a checkpoint.
    """

    def __init__(
        self, cache_dir: Path | str, progress: shared.Progress | None = None, *,
        remote: str = shared.GHSA_REPOSITORY, ref: str = "main",
        prefixes: Iterable[str] = ("advisories",),
        path_filter: Callable[[str], bool] | None = None,
        proxies: dict[str, str] | None = None,
        revision_resolver: RevisionResolver | None = None,
    ) -> None:
        match = re.fullmatch(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?", remote)
        if match is None and not (remote.startswith("file://") and revision_resolver is not None):
            raise ValueError("window source requires a public GitHub repository")
        if not re.fullmatch(r"[A-Za-z0-9_./-]+", ref) or ref.startswith(("-", "/")) or ".." in ref:
            raise ValueError("invalid Git source ref")
        self.remote, self.ref = remote, ref
        self.prefixes = tuple(shared._path(prefix) for prefix in prefixes)
        if not self.prefixes:
            raise ValueError("Git window requires at least one path prefix")
        self.path_filter = path_filter or (lambda path: path.endswith(".json"))
        self.repository = "/".join(match.groups()) if match else "github/advisory-database"
        self.revision_resolver = revision_resolver or self._revision_at
        self.transport = shared.GitAdvisorySource(cache_dir, progress, remote=remote, proxies=proxies)
        identity = hashlib.sha256(remote.encode()).hexdigest()[:20]
        self.transport.path = Path(cache_dir) / (identity + ".git")

    def raw_url(self, revision: str, path: str) -> str:
        """Return a raw URL pinned to an exact revision and safe repository path."""
        if not shared.REVISION.fullmatch(revision):
            raise ValueError("invalid pinned revision")
        return f"https://raw.githubusercontent.com/{self.repository}/{revision}/{quote(shared._path(path), safe='/')}"

    def _revision_at(self, at: datetime, http: Http, ref: str) -> str:
        query = urlencode({"sha": ref, "until": shared._iso(at), "per_page": 1})
        response = http(f"https://api.github.com/repos/{self.repository}/commits?{query}",
                        {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        if response.status != 200 or len(response.body) > 1024 * 1024:
            raise ValueError("GitHub revision metadata unavailable; retry the selected period")
        try:
            records = json.loads(response.body)
            if not isinstance(records, list) or len(records) != 1:
                raise ValueError("GitHub cutoff revision unavailable")
            record = records[0]
            revision = record["sha"]
            committed = shared._date(record["commit"]["committer"]["date"])
            if not isinstance(revision, str) or not shared.REVISION.fullmatch(revision) or committed > at:
                raise ValueError("invalid GitHub pinned revision metadata")
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid GitHub revision metadata") from exc
        return revision

    def changes(self, since: datetime, until: datetime, http: Http) -> GitWindowChanges:
        """Return complete changed/deleted paths between the selected cutoffs."""
        if since >= until:
            raise ValueError("invalid Git time window")
        if since < period_bounds("3m", until)[0]:
            raise ValueError("Git time window cannot exceed three calendar months")
        target = self.revision_resolver(until, http, self.ref)
        base = self.revision_resolver(since, http, target)
        if any(not isinstance(value, str) or not shared.REVISION.fullmatch(value) for value in (base, target)):
            raise ValueError("invalid pinned Git revision")
        if base == target:
            return GitWindowChanges(base, target, [], [])
        transport = self.transport
        transport.path.mkdir(parents=True, exist_ok=True)
        if not (transport.path / "HEAD").exists():
            transport._git("init", "--bare")
            transport._git("config", "remote.origin.url", self.remote)
            transport._git("config", "remote.origin.promisor", "true")
            transport._git("config", "remote.origin.partialclonefilter", "blob:none")
        remote, _ = transport._git("config", "--get", "remote.origin.url")
        bare, _ = transport._git("rev-parse", "--is-bare-repository")
        if remote.decode().strip() != self.remote or bare.strip() != b"true":
            raise ValueError("Git window cache has incompatible source identity")
        if any(path.is_symlink() for path in (transport.path / "objects").rglob("*")):
            raise ValueError("Git window cache must not contain symbolic links")
        transport._check_size()
        _, trace = transport._git("ls-remote", "--exit-code", "origin", "refs/heads/" + self.ref, packet=True)
        if not re.search(rb"fetch=[^\r\n]*\bfilter\b", trace):
            raise ValueError("Git window source must support blob filtering")
        for revision in (base, target):
            transport._git("fetch", "--depth=1", "--filter=blob:none", "--no-tags", "--no-write-fetch-head", "origin", revision)
            transport._check_size()
            resolved, _ = transport._git("rev-parse", "--verify", revision + "^{commit}")
            if resolved.strip().decode() != revision:
                raise ValueError("Git pinned revision mismatch")
        raw, _ = transport._git("diff", "--name-status", "-z", "--no-renames", base, target, "--",
                                *(":(literal)" + prefix for prefix in self.prefixes))
        tokens = raw.split(b"\0")
        if tokens[-1] != b"" or (len(tokens) - 1) % 2:
            raise ValueError("invalid Git window tree diff")
        changed: list[str] = []
        deleted: list[str] = []
        for index in range(0, len(tokens) - 1, 2):
            status, path = tokens[index].decode(), shared._path(tokens[index + 1].decode())
            if not self.path_filter(path):
                continue
            if status in ("A", "M"):
                changed.append(path)
            elif status == "D":
                deleted.append(path)
            else:
                raise ValueError("unsupported Git window tree change " + status)
            if len(changed) + len(deleted) > shared.MAX_FILES:
                raise ValueError("Git window exceeds safe file count; select a shorter period")
        return GitWindowChanges(base, target, changed, deleted)


def _snapshot_base(cache: Path, name: str) -> shared.Json | None:
    path = cache / name / "window-validators.json"
    if not path.exists():
        return None
    if path.stat().st_size > 65536:
        raise ValueError("snapshot validator cache exceeds size limit")
    base = shared._json(path.read_bytes())
    shared.validate_checkpoint(name, base)
    return base


def build_window_bundle(
    out_path: Path | str, sources: Iterable[str], cache_dir: Path | str, *,
    period: str = "1d", now: datetime | None = None,
    progress: shared.Progress | None = None, http: Http | None = None,
    github: GitWindowSource | None = None, proxies: dict[str, str] | None = None,
    max_bytes: int = shared.MAX_BUNDLE_BYTES,
) -> shared.Json:
    """Publish an immutable v2 archive for exactly the requested UTC period.

    Only changed snapshots are included in full, since those upstream sources
    lack row deltas. Their local validators advance after archive publication.
    No state/export argument is accepted and no database baseline is implied.
    """
    selected = list(sources)
    if not selected or len(set(selected)) != len(selected) or any(name not in shared.SOURCES for name in selected):
        raise ValueError("unknown, repeated, or empty source selection")
    if type(max_bytes) is not int or not 1 <= max_bytes <= shared.MAX_BUNDLE_BYTES:
        raise ValueError("bundle limit cannot exceed 500 MiB")
    since, until = period_bounds(period, now)
    out_path, cache_dir = Path(out_path), Path(cache_dir)
    if out_path.exists():
        raise FileExistsError("update archive already exists; use a new output filename")
    progress = progress or (lambda message: None)
    http = http or shared.HttpClient(progress=progress, proxies=proxies)
    manifest: shared.Json = {"format": "stools-reference-update", "version": 2, "scope": "window",
        "created_at": shared._iso(until), "window": {"since": shared._iso(since), "until": shared._iso(until)}, "sources": []}
    snapshot_cache = cache_dir / "snapshots"
    next_validators = {}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".ref-window-", suffix=".zip", dir=out_path.parent)
    os.close(descriptor)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
            payloads = shared._Payloads(archive, progress)
            for name in selected:
                progress("Checking selected period: " + name)
                provenance: shared.Json = {"checked_at": shared._iso(until)}
                if name == "nvd":
                    files, deleted = shared._nvd_window(since, until, range(1999, until.year + 1), http, payloads, exclude_since=True)
                    provenance.update({"endpoint": shared.NVD_API, "selection": "lastModified", "bounds": "(since,until]"})
                elif name == "ghsa":
                    provider = github or GitWindowSource(cache_dir, progress, proxies=proxies)
                    changes = provider.changes(since, until, http)
                    files, deleted = shared._ghsa_payloads(changes.target_revision, changes.changed, changes.deleted, http, payloads)
                    provenance.update({"repository": provider.remote, "ref": provider.ref,
                        "base_revision": changes.base_revision, "target_revision": changes.target_revision, "bounds": "(since,until]"})
                else:
                    target, files, deleted = shared._snapshots(name, _snapshot_base(snapshot_cache, name), http, payloads, snapshot_cache / name)
                    shared.validate_checkpoint(name, target)
                    next_validators[name] = target
                    provenance.update(target)
                    provenance["selection"] = "conditional_snapshot"
                mode = ("delta" if name in ("nvd", "ghsa") else "snapshot") if files or deleted else "unchanged"
                manifest["sources"].append({"name": name, "mode": mode, "files": files,
                    "deleted_ids": deleted, "provenance": provenance})
            archive.writestr(shared.MANIFEST_NAME, json.dumps(manifest, ensure_ascii=False, separators=(",", ":")))
        if Path(temporary).stat().st_size > max_bytes:
            raise ValueError("update archive exceeds bundle limit; select fewer sources")
        progress("Publishing selected-period archive")
        with open(temporary, "rb") as stream:
            os.fsync(stream.fileno())
        os.link(temporary, out_path)
        shared._sync_directory(out_path.parent)
        for name, validators in next_validators.items():
            shared._atomic_write(snapshot_cache / name / "window-validators.json",
                                 json.dumps(validators, separators=(",", ":")).encode())
    finally:
        Path(temporary).unlink(missing_ok=True)
    return manifest
