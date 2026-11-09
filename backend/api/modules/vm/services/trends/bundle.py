import hashlib
import json
import zipfile
from typing import Any

from sqlalchemy.orm import Session

from .ingest import ChangePage, apply_page


def import_bundle(db: Session, stream: Any, reset: Any=False) -> None:
    with zipfile.ZipFile(stream) as archive:
        if sorted(archive.namelist()) != ["manifest.json", "pages.jsonl"]:
            raise ValueError("неверный состав пакета")
        if sum(item.file_size for item in archive.infolist()) > 500 * 1024 * 1024:
            raise ValueError("пакет превышает лимит распакованных данных")
        if archive.getinfo("manifest.json").file_size > 65536:
            raise ValueError("manifest превышает лимит")
        manifest = json.loads(archive.read("manifest.json"))
        if manifest.get("protocol_version") not in (1, 2) or (reset and manifest.get("after") != 0):
            raise ValueError("полное восстановление требует пакет от начала истории")
        digest = hashlib.sha256()
        with archive.open("pages.jsonl") as member:
            while chunk := member.read(1024 * 1024):
                digest.update(chunk)
        if digest.hexdigest() != manifest.get("sha256"):
            raise ValueError("контрольная сумма пакета не совпала")
        previous = manifest["after"]
        with archive.open("pages.jsonl") as member:
            for line in member:
                if len(line) > 8 * 1024 * 1024:
                    raise ValueError("страница пакета превышает лимит")
                page = ChangePage.model_validate_json(line)
                if page.protocol_version != manifest["protocol_version"]:
                    raise ValueError("версия страницы не соответствует пакету")
                if (page.collector_id, page.epoch, page.until_seq) != (manifest["collector_id"], manifest["epoch"], manifest["until_seq"]):
                    raise ValueError("несовместимые страницы пакета")
                if page.events and page.events[0].seq != previous + 1:
                    raise ValueError("разрыв последовательности пакета")
                previous = page.next_cursor
        if previous != manifest["until_seq"]:
            raise ValueError("неполный пакет")
        with archive.open("pages.jsonl") as member:
            for index, line in enumerate(member):
                apply_page(db, json.loads(line), reset=reset and index == 0)
