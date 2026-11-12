import hashlib
import json
import zipfile
from typing import Any

from sqlalchemy.orm import Session

from api.modules.vm.trend_models import VmTrendIngestState

from .ingest import ChangePage, apply_page, apply_snapshot_page


def import_bundle(db: Session, stream: Any, reset: Any=False) -> None:
    with zipfile.ZipFile(stream) as archive:
        if sorted(archive.namelist()) != ["manifest.json", "pages.jsonl"]:
            raise ValueError("неверный состав пакета")
        if sum(item.file_size for item in archive.infolist()) > 500 * 1024 * 1024:
            raise ValueError("пакет превышает лимит распакованных данных")
        if archive.getinfo("manifest.json").file_size > 65536:
            raise ValueError("manifest превышает лимит")
        manifest = json.loads(archive.read("manifest.json"))
        snapshot = manifest.get("format") == "snapshot-v1" and manifest.get("protocol_version") == 3
        protocol = manifest.get("event_protocol_version") if snapshot else manifest.get("protocol_version")
        if snapshot:
            baseline = manifest.get('baseline_seq')
            if not isinstance(baseline, int) or baseline < 0 or manifest.get('after') != 0 or not manifest.get('snapshot_id'):
                raise ValueError('неверный манифест снимка')
            state = db.get(VmTrendIngestState, 1)
            if state and not reset and ((state.collector_id, state.epoch) != (manifest.get('collector_id'), manifest.get('epoch')) or (state.snapshot_id is None and state.cursor > baseline)):
                raise ValueError('снимок требует явного полного восстановления')
        if protocol not in (1, 2) or (reset and manifest.get("after") != 0):
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
                raw = json.loads(line)
                if snapshot and (raw.get('snapshot_id'), raw.get('baseline_seq')) != (manifest['snapshot_id'], manifest['baseline_seq']):
                    raise ValueError('страница не соответствует снимку')
                page = ChangePage.model_validate(raw)
                if page.protocol_version != protocol:
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
                if snapshot:
                    apply_snapshot_page(db, json.loads(line), reset=index == 0)
                else:
                    apply_page(db, json.loads(line), reset=reset and index == 0)
