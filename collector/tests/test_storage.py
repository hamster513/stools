from concurrent.futures import ThreadPoolExecutor

import pytest
from stools_threat_collector.storage import Store


def document(text="First version"):
    return {"external_id": "article-1", "title": "CVE-2026-12345", "url": "https://example.org/a", "text": text}


def test_atomic_versions_pagination_restart(tmp_path):
    store = Store(tmp_path / "collector.db")
    source = store.save_source({"name": "Example", "publisher_id": "example", "url": "https://example.org/rss"})
    store.ingest(source["id"], [document()], {"etag": "one"})
    first = store.changes(0, limit=1)
    boundary = first["until_seq"]
    store.ingest(source["id"], [document()], {"etag": "two"})
    assert store.info()["last_seq"] == boundary
    store.ingest(source["id"], [document("Correction")], {"etag": "three"})
    page = store.changes(first["next_cursor"], until=boundary)
    assert all(e["seq"] <= boundary for e in page["events"])
    assert not page["has_more"]
    reopened = Store(tmp_path / "collector.db")
    assert reopened.info() == store.info()
    assert reopened.source(source["id"])["checkpoint"] == {"etag": "three"}
    assert reopened.changes(boundary)["events"][0]["revision"] == 2


def test_invalid_batch_rolls_back_checkpoint(tmp_path):
    store = Store(tmp_path / "collector.db")
    source = store.save_source({"name": "Example", "publisher_id": "example", "url": "https://example.org/rss"})
    before = store.info()["last_seq"]
    with pytest.raises((ValueError, KeyError)):
        store.ingest(source["id"], [document(), {"title": "missing ID"}], {"offset": 9})
    assert store.info()["last_seq"] == before
    assert store.source(source["id"])["checkpoint"] == {}


def test_concurrent_writes_have_unique_committed_sequence(tmp_path):
    store = Store(tmp_path / "collector.db")
    source = store.save_source({"name": "Example", "publisher_id": "example", "url": "https://example.org/rss"})
    def add(i):
        store.ingest(source["id"], [{**document(), "external_id": str(i)}], {})
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(add, range(12)))
    events = store.changes(0)["events"]
    assert [e["seq"] for e in events] == list(range(1, 14))


def test_tokens_version_conflict_and_restore(tmp_path):
    store = Store(tmp_path / "collector.db")
    source = store.save_source({"name": "Example", "publisher_id": "example", "url": "https://example.org/rss"})
    store.save_source({**source, "name": "Renamed"}, source["id"])
    with pytest.raises(ValueError, match="version"):
        store.save_source(source, source["id"])
    token = store.create_token("stand", ["data:read"])
    assert store.scopes(token) == ["data:read"]
    assert store.scopes("wrong") == []
    before = store.info()
    backup = tmp_path / "backup.db"
    store.backup(backup)
    store.restore(backup)
    assert store.info()["epoch"] != before["epoch"]
    assert store.info()["collector_id"] == before["collector_id"]
