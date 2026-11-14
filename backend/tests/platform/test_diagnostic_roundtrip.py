"""Real source -> anonymized ZIP -> isolated database -> existing dossier."""
import json

from sqlalchemy import func, select

from api.modules.assets.models import AssetUser, AssetUserGroup
from api.platform.diagnostics.exporter import build_bundle
from api.platform.diagnostics.storage import PackageStore, encode_archive
from api.platform.diagnostics.workspace import ACCESS, open_dataset, without_live_links
from api.platform.search.models import SearchRequest
from api.platform.search.service import search
from tests.platform.test_diagnostic_export import source  # noqa: F401


def test_roundtrip_keeps_stale_assets_and_current_ad_independent(source, tmp_path):  # noqa: F811
    production, data_dir = source
    bundle = build_bundle(production, data_dir, "user", 1)
    archive = encode_archive(bundle)
    store = PackageStore(tmp_path / "destination")
    first = store.import_archive(archive)
    second = store.import_archive(archive)
    assert first["id"] != second["id"]
    for imported in [first, second]:
        directory = store.import_path(imported["id"])
        with open_dataset(directory) as isolated:
            assert isolated.scalar(select(func.count()).select_from(AssetUserGroup)) == 101
            root = imported["root"]
            result = search(isolated, SearchRequest(query=root["title"], kind="user",
                            entity_id=f"user:{root['id']}"), ACCESS, directory)
            groups = next(section for section in result.dossier.sections if section.id == "groups")
            assert len(groups.items) == 67 and not groups.has_more
            assert "сохранённые группы" not in groups.note
            clean = without_live_links(result.model_dump(mode="json"))
            serialized = json.dumps(clean)
            assert "/assets/" not in serialized and "/ad/" not in serialized
            assert "secret.corp" not in serialized and "Alice Private" not in serialized
    assert production.scalar(select(func.count()).select_from(AssetUserGroup)) == 101
    assert production.get(AssetUser, 1).note == "password=hunter2"


def test_auto_search_works_in_real_import(source, tmp_path):  # noqa: F811
    production, data_dir = source
    store = PackageStore(tmp_path / "destination")
    imported = store.import_archive(encode_archive(build_bundle(production, data_dir, "user", 1)))
    directory = store.import_path(imported["id"])
    with open_dataset(directory) as isolated:
        result = search(isolated, SearchRequest(query=imported["root"]["title"], kind="auto"), ACCESS, directory)
        assert result.dossier.entity.id == f"user:{imported['root']['id']}"


def test_ksc_group_search_works_in_real_host_import(source, tmp_path):  # noqa: F811
    from api.modules.assets.models import AssetObservation
    from api.modules.ksc.models import KscHost, KscServer, KscSnapshot
    from tests.platform.test_diagnostic_export import NOW

    production, data_dir = source
    production.add(KscServer(id=1, name="Private server"))
    production.add(KscSnapshot(id=1, server_id=1, collected_at=NOW, source="file"))
    production.add(KscHost(id=1, snapshot_id=1, host_id="private-host", name="unrelated-secret-host",
                           group_id=4, group_path="Private parent/Private group"))
    production.add(AssetObservation(asset_id=1, source="ksc", source_key="1:private-host", seen_at=NOW))
    production.commit()
    bundle = build_bundle(production, data_dir, "host", 1)
    store = PackageStore(tmp_path / "destination")
    imported = store.import_archive(encode_archive(bundle))
    directory = store.import_path(imported["id"])
    path = bundle["tables"]["ksc_host"][0]["group_path"]
    with open_dataset(directory) as isolated:
        for kind in ["group", "auto"]:
            result = search(isolated, SearchRequest(query=path, kind=kind), ACCESS, directory)
            assert result.dossier.entity.id.startswith("kscgroup:")
            members = next(section for section in result.dossier.sections if section.id == "members")
            assert len(members.items) == 1


def test_omitted_gpo_host_total_is_unknown_not_zero(source, tmp_path):  # noqa: F811
    from api.modules.assets.models import AssetGroup, AssetGroupGpo
    from tests.platform.test_diagnostic_export import DOMAIN, NOW, SID

    production, data_dir = source
    production.add(AssetGroup(id=1, group_key="ad:test", sid=f"{SID}-2000", name="Private group", domain=DOMAIN))
    production.add(AssetGroupGpo(domain=DOMAIN, group_sid=f"{SID}-2000", group_name="Private group",
                                gpo_name="Private policy", hosts_total=42, hosts=["private.host"], seen_at=NOW))
    production.commit()
    bundle = build_bundle(production, data_dir, "user", 1)
    store = PackageStore(tmp_path / "destination")
    imported = store.import_archive(encode_archive(bundle))
    directory = store.import_path(imported["id"])
    group_id = bundle["tables"]["asset_group"][0]["id"]
    with open_dataset(directory) as isolated:
        result = search(isolated, SearchRequest(query="group", kind="group", entity_id=f"group:{group_id}"), ACCESS, directory)
        body = without_live_links(result.model_dump(mode="json"))
        section = next(item for item in body["dossier"]["sections"] if item["id"] == "ad_policies")
        host_count = next(fact for fact in section["items"][0]["facts"] if fact["label"] == "Хостов")
        assert host_count["value"] == "Не включено в пакет"
