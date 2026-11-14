"""Bounded ZIP codec and atomic filesystem storage for diagnostic packages."""

import datetime as dt
import io
import json
import re
import shutil
import stat
import tempfile
import uuid
import zipfile
import zlib
from pathlib import Path

from . import workspace

MAX_COMPRESSED = 20 * 1024 * 1024
MAX_UNCOMPRESSED = 50 * 1024 * 1024
EXPORT_TTL_SECONDS = 30 * 60
_ID = re.compile(r"[0-9a-f]{32}")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Некорректный диагностический пакет.")
        result[key] = value
    return result


def decode_archive(data: bytes) -> dict:
    from .exporter import validate_bundle

    if len(data) > MAX_COMPRESSED:
        raise ValueError("Диагностический пакет слишком большой.")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) != 1:
                raise ValueError
            info = members[0]
            mode = info.external_attr >> 16
            if (
                info.filename != "dataset.json"
                or info.is_dir()
                or info.flag_bits & 1
                or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                or (stat.S_IFMT(mode) and not stat.S_ISREG(mode))
                or info.file_size > MAX_UNCOMPRESSED
                or info.file_size > max(info.compress_size, 1) * 1000
            ):
                raise ValueError
            with archive.open(info) as source:
                raw = source.read(MAX_UNCOMPRESSED + 1)
            if len(raw) > MAX_UNCOMPRESSED:
                raise ValueError
        bundle = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
        return validate_bundle(bundle)
    except (
        ValueError,
        TypeError,
        KeyError,
        UnicodeError,
        OSError,
        EOFError,
        RuntimeError,
        RecursionError,
        zipfile.BadZipFile,
        NotImplementedError,
        zlib.error,
    ):
        raise ValueError("Некорректный или неподдерживаемый диагностический пакет.") from None


def encode_archive(bundle: dict) -> bytes:
    from .exporter import validate_bundle

    validate_bundle(bundle)
    raw = json.dumps(bundle, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(raw) > MAX_UNCOMPRESSED:
        raise ValueError("Диагностический пакет слишком большой.")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("dataset.json", raw)
    result = output.getvalue()
    if len(result) > MAX_COMPRESSED:
        raise ValueError("Диагностический пакет слишком большой.")
    return result


def _write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    path.chmod(0o600)


class PackageStore:
    def __init__(self, data_dir: Path):
        self.root = Path(data_dir) / "diagnostics"

    def _area(self, kind):
        path = self.root / kind
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        return path

    def _path(self, kind, package_id):
        if not isinstance(package_id, str) or not _ID.fullmatch(package_id):
            raise ValueError("Некорректный идентификатор пакета.")
        path = self._area(kind) / package_id
        if path.is_symlink():
            raise FileNotFoundError
        return path

    def import_path(self, package_id):
        path = self._path("imports", package_id)
        if not path.is_dir():
            raise FileNotFoundError
        return path

    def import_archive(self, data):
        bundle = decode_archive(data)
        package_id = uuid.uuid4().hex
        root = bundle["root"]
        name = "asset" if root["kind"] == "host" else "asset_user"
        row = next(item for item in bundle["tables"][name] if item["id"] == root["id"])
        title = (
            (row.get("fqdn") or row.get("name") or row.get("ip"))
            if name == "asset"
            else (row.get("display_name") or row.get("upn") or row.get("sam"))
        )
        metadata = {
            "id": package_id,
            "created_at": dt.datetime.now(dt.UTC).isoformat(),
            "summary": bundle["report"],
            "root": {**root, "title": title or str(root["id"])},
        }
        area = self._area("imports")
        temporary = Path(tempfile.mkdtemp(prefix=".pending-", dir=area))
        try:
            workspace.materialize(bundle, temporary)
            _write_json(temporary / "metadata.json", metadata)
            temporary.rename(area / package_id)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        return metadata

    def list_imports(self):
        result = []
        for path in self._area("imports").iterdir():
            if _ID.fullmatch(path.name) and path.is_dir() and not path.is_symlink():
                result.append(json.loads((path / "metadata.json").read_text(encoding="utf-8")))
        return sorted(result, key=lambda item: item["created_at"], reverse=True)

    def delete_import(self, package_id):
        shutil.rmtree(self.import_path(package_id))

    def _prune_exports(self):
        now = dt.datetime.now(dt.UTC)
        for path in self._area("exports").iterdir():
            if _ID.fullmatch(path.name) and path.is_dir() and not path.is_symlink():
                metadata = json.loads((path / "metadata.json").read_text(encoding="utf-8"))
                if dt.datetime.fromisoformat(metadata["expires_at"]) <= now:
                    shutil.rmtree(path)

    def create_export(self, bundle, owner_id):
        data = encode_archive(bundle)
        self._prune_exports()
        package_id = uuid.uuid4().hex
        expires = (dt.datetime.now(dt.UTC) + dt.timedelta(seconds=EXPORT_TTL_SECONDS)).isoformat()
        metadata = {"id": package_id, "summary": bundle["report"], "expires_at": expires}
        area = self._area("exports")
        temporary = Path(tempfile.mkdtemp(prefix=".pending-", dir=area))
        try:
            (temporary / "package.zip").write_bytes(data)
            (temporary / "package.zip").chmod(0o600)
            _write_json(temporary / "metadata.json", {**metadata, "owner_id": owner_id})
            temporary.rename(area / package_id)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
        return metadata

    def download_export(self, package_id, owner_id):
        self._prune_exports()
        path = self._path("exports", package_id)
        metadata = json.loads((path / "metadata.json").read_text(encoding="utf-8"))
        if metadata["owner_id"] != owner_id:
            raise FileNotFoundError
        return (path / "package.zip").read_bytes()
