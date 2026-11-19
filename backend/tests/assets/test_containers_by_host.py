from datetime import UTC, datetime

from api.modules.assets.models import Asset, AssetObservation
from api.modules.vm.docker_models import VmDockerImage, VmDockerSnapshot
from api.modules.vm.models import VmImage

URL = "/api/assets/container-images/by-host"
VM_URL = "/api/vm/images/by-host"
STAMP = datetime(2026, 11, 19, tzinfo=UTC)
MATCHED = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64


def container(key, status, **extra):
    return {"id": key, "name": key, "status": status, "ports": [], "created_at": "", "started_at": "", **extra}


def host(name, *containers):
    return {"hostname": name, "ip": "10.1.1.1", "containers": list(containers)}


def observed(db, key, digest, hosts, refs):
    db.add(VmDockerImage(image_key=key, image_id=digest, title="team/app", tags=["latest"], platform="",
                         host_count=len(hosts), container_count=sum(len(h["containers"]) for h in hosts),
                         status="running", details={"references": refs, "hosts": hosts},
                         search_text="", collected_at=STAMP))


def test_host_rows_filter_the_container_and_confirm_only_verified_ids(db_session, client_as):
    db = db_session
    local = [{"registry": "harbor.example", "repo": "team/app", "tag": "v1"}]
    external = [{"registry": "elsewhere.example", "repo": "team/app", "tag": "edge"}]
    for n in range(2):
        db.add(VmImage(project="team", repository=f"app{n}", digest=f"manifest{n}", runtime_ids=[MATCHED]))
    db.add(VmImage(project="team", repository="chart", digest="chart", artifact_kind="helm", runtime_ids=[OTHER]))
    db.add(VmImage(project="team", repository="uncertain", digest=OTHER, runtime_error="MANIFEST_HTTP_401"))
    db.add(VmDockerSnapshot(id=1, attempted_at=STAMP, collected_at=STAMP, error="previous snapshot retained"))
    asset = Asset(name="alpha")
    obsolete = Asset(name="another")
    db.add_all([asset, obsolete])
    db.flush()
    db.add_all([AssetObservation(asset_id=asset.id, source="vm", source_key="alpha|10.1.1.1", seen_at=STAMP),
                AssetObservation(asset_id=obsolete.id, source="vm", source_key="beta|10.1.1.1",
                                 seen_at=STAMP, gone_at=STAMP)])
    observed(db, "known", MATCHED, [host("alpha", container("api", "running", references=local)),
                                    host("beta", container("api", "exited")), host("idle")], local + external)
    observed(db, "outside", OTHER, [host("beta", container("worker", "running"))], external)
    observed(db, "no-id", "", [host("alpha", container("helper", "running"))], local)
    db.commit()

    client = client_as({"assets": "read"})
    def get(**params):
        response = client.get(URL, params=params)
        assert response.status_code == 200, response.text[:250]
        return response.json()

    all_rows = get()
    assert all_rows["total"] == 4 and all_rows["mp_vm"]["error"] and all_rows["asset"] is None
    assert [r["container"]["id"] for r in all_rows["items"]] == ["api", "helper", "api", "worker"]
    mine = get(asset_id=asset.id, running_only=True)
    assert mine["total"] == 2 and mine["asset"] == {"id": asset.id, "name": "alpha"}
    api = mine["items"][0]
    assert api["harbor_matched"] and api["asset_id"] == asset.id and api["references"] == local
    assert api["references_source"] == "container" and api["image_id"] == MATCHED
    assert [(i["project"], i["repository"]) for i in api["harbor_images"]] == [("team", "app0"), ("team", "app1")]
    assert len({i["id"] for i in api["harbor_images"]}) == 2
    assert get(asset_id=obsolete.id)["total"] == 0
    assert get(q="beta", running_only=True)["total"] == 1
    unmatched = get(running_only=True, unmatched_only=True)
    assert [(row["image_id"], row["hostname"]) for row in unmatched["items"]] == [("", "alpha"), (OTHER, "beta")]
    assert all(row["harbor_images"] == [] for row in unmatched["items"])
    assert unmatched["items"][1]["asset_id"] is None and unmatched["items"][1]["references_source"] == "image"
    assert get(q="elsewhere.example/team/app:edge", running_only=True)["total"] == 1
    assert get(q="%")["total"] == 0
    assert get(limit=1, offset=3)["items"][0] == all_rows["items"][3]
    assert get(limit=1, offset=40)["items"] == [] and get(offset=40)["total"] == 4
    assert client.get(URL, params={"asset_id": 987654321}).status_code == 404
    assert client.get(VM_URL).status_code == 403
    vm = client_as({"vm": "read"})
    assert vm.get(URL).status_code == 403
    assert vm.get(VM_URL, params={"asset_id": asset.id}).status_code == 403
    vm_rows = vm.get(VM_URL, params={"running_only": True}).json()
    assert vm_rows["total"] == 3 and all(row["asset_id"] is None for row in vm_rows["items"])
    assert vm_rows["items"][0]["harbor_images"] == api["harbor_images"]
    assert vm.get(VM_URL, params={"running_only": True, "unmatched_only": True}).json()["total"] == 2
    both = client_as({"vm": "read", "assets": "read"})
    assert both.get(VM_URL, params={"asset_id": asset.id, "running_only": True}).json() == mine


def test_conflicting_observations_and_unsuccessful_first_snapshot(db_session, client_as):
    client = client_as({"assets": "read"})
    assert client.get(URL).json()["mp_vm"] is None
    db_session.add(VmDockerSnapshot(id=1, attempted_at=STAMP, error="failed"))
    observed(db_session, "first", MATCHED, [host("same", container("shared", "running"))], [])
    observed(db_session, "second", OTHER, [host("same", container("shared", "exited"))], [])
    db_session.add(VmImage(project="p", repository="app", digest="m", runtime_ids=[MATCHED]))
    db_session.commit()
    assert client.get(URL).json()["total"] == 0
    db_session.get(VmDockerSnapshot, 1).collected_at = STAMP
    db_session.commit()
    data = client.get(URL, params={"unmatched_only": True}).json()
    assert data["total"] == 1
    row = data["items"][0]
    assert row["container"]["status"] == "unknown" and row["image_row_id"] is None
    assert row["image_id"] == "" and not row["harbor_matched"] and row["harbor_images"] == []
    assert client.get(URL, params={"running_only": True}).json()["total"] == 0


def test_container_keeps_its_observed_tag_when_an_image_has_aliases(tmp_path):
    from api.modules.vm.core.docker_inventory import parse_inventory
    from tests.vm.test_docker_inventory import BASE, write_samples

    alias = [*BASE]
    alias[5] = "another-tag"
    rows = [BASE + ["c1", "app", "running", "80", "8080", "tcp"],
            BASE + ["c1", "app", "running", "443", "8443", "tcp"]]
    image, = parse_inventory(*write_samples(tmp_path, [BASE, alias], rows))
    assert len(image["references"]) == 2
    container_ref, = image["hosts"][0]["containers"][0]["references"]
    assert container_ref["tag"] == BASE[5]
