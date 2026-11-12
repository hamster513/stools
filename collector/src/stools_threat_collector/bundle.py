import hashlib
import json
import tempfile
import zipfile


def export_bundle(store, after, destination):
    snapshot = store.info()
    recovery = after < snapshot.get("cursor_floor", 0)
    if recovery:
        snapshot = {**snapshot, **store.create_snapshot()}
        after = 0
    until = snapshot["until_seq"] if recovery else snapshot["last_seq"]
    cursor = after
    digest = hashlib.sha256()
    size = 0
    with tempfile.TemporaryFile() as stream:
        while True:
            page = store.snapshot_page(snapshot["snapshot_id"], cursor) if recovery else store.changes(cursor, until)
            page["protocol_version"] = snapshot["protocol_version"]
            line = (json.dumps(page, ensure_ascii=False) + "\n").encode()
            size += len(line)
            if size > 500 * 1024 * 1024:
                raise ValueError("export exceeds bundle limit")
            stream.write(line)
            digest.update(line)
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break
        manifest = {**snapshot, "after": after, "until_seq": until, "sha256": digest.hexdigest()}
        if recovery:
            manifest.update(format="snapshot-v1", event_protocol_version=snapshot["protocol_version"], protocol_version=3)
        stream.seek(0)
        with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest))
            with archive.open("pages.jsonl", "w") as member:
                while chunk := stream.read(1024 * 1024):
                    member.write(chunk)
    destination.chmod(0o600)
