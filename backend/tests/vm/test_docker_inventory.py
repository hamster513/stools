from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest

from api.modules.vm.core.docker_inventory import DockerFormatError, parse_inventory

ENGINE = 'Host.Softs<DockerEngine>'
DIGEST = 'sha256:' + 'a' * 64


def sample(kind, rows):
    prefix = ENGINE + ('.Images.' if kind == 'images' else '.Containers.Image.')
    columns = ['@Host', 'Host.@UpdateTime'] + [prefix + f for f in ('ID', 'Registry', 'Repo', 'Tag', 'OsFamily', 'Architecture')]
    if kind == 'containers':
        columns += [ENGINE + '.Containers.' + f for f in ('@Id', 'Name', 'Status', 'Ports.ContainerPort', 'Ports.HostPorts', 'Ports.Protocol')]
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(columns)
    writer.writerows(rows)
    return output.getvalue()


def write_samples(tmp_path, images=(), containers=()):
    paths = [tmp_path / 'images.csv', tmp_path / 'containers.csv']
    for path, kind, rows in zip(paths, ('images', 'containers'), (images, containers)):
        path.write_text(sample(kind, rows), encoding='utf-8-sig')
    return paths


BASE = ['host-a (10.0.0.1)', '2026-11-05T10:00:00Z', DIGEST, 'registry.example', 'team/app', 'v1', 'linux', 'amd64']


def test_hosts_tags_ports_and_missing_image(tmp_path: Path):
    second = [*BASE]; second[0] = 'host-b (10.0.0.2)'; second[5] = 'v2'
    paths = write_samples(tmp_path, [BASE, second], [
        BASE + ['node-1', 'web', 'running', '80', '8080', 'tcp'],
        BASE + ['node-1', 'web', 'running', '443', '8443', 'tcp'],
        [*BASE[:2], '', '', '', '', '', '', 'node-2', 'unknown', 'exited', '', '', ''],
    ])
    records = parse_inventory(*paths)
    known = next(r for r in records if r['image_id'])
    assert known['image_id'] == DIGEST
    assert len(known['hosts']) == 2
    a, b = sorted(known['hosts'], key=lambda h: h['hostname'])
    assert a['status'] == 'running' and b['status'] == 'unused'
    assert len(a['containers']) == 1 and len(a['containers'][0]['ports']) == 2
    assert {r['tag'] for r in known['references']} == {'v1', 'v2'}
    unknown = next(r for r in records if not r['image_id'])
    assert unknown['hosts'][0]['containers'][0]['name'] == 'unknown'
    assert unknown['status'] == 'stopped'


def test_unknown_status_is_not_stopped(tmp_path):
    paths = write_samples(tmp_path, [], [BASE + ['n', 'web', '', '', '', '']])
    assert parse_inventory(*paths)[0]['status'] == 'unknown'


def test_empty_valid_export(tmp_path):
    assert parse_inventory(*write_samples(tmp_path)) == []


@pytest.mark.parametrize('bad', ['', '<html>bad</html>', '@Host;wrong\nnode;value\n'])
def test_invalid_export_rejected(tmp_path, bad):
    paths = write_samples(tmp_path)
    paths[1].write_text(bad)
    with pytest.raises(DockerFormatError):
        parse_inventory(*paths)


def test_truncated_quoted_csv_rejected(tmp_path):
    paths = write_samples(tmp_path, [BASE])
    # Unterminated last cell must not absorb following rows as one image.
    content = paths[0].read_text().rstrip().rsplit(';', 1)[0] + ';"amd64\n'
    paths[0].write_text(content + ';'.join(BASE) + '\n')
    with pytest.raises(DockerFormatError):
        parse_inventory(*paths)


def test_different_image_ids_are_not_merged_by_tag(tmp_path):
    other = [*BASE]; other[2] = 'sha256:' + 'b' * 64
    assert len(parse_inventory(*write_samples(tmp_path, [BASE, other]))) == 2


def test_unresolved_container_prevents_unused_claim(tmp_path):
    missing = [*BASE[:2], '', '', '', '', '', '', 'unknown-id', 'web', 'running', '', '', '']
    records = parse_inventory(*write_samples(tmp_path, [BASE], [missing]))
    known = next(r for r in records if r['image_id'])
    assert known['status'] == 'unknown'
    assert known['hosts'][0]['status'] == 'unknown'


def test_snapshot_is_atomic_and_ids_stable(db_session, tmp_path):
    from sqlalchemy import select

    from api.modules.vm.docker_models import VmDockerImage, VmDockerSnapshot
    from api.modules.vm.services.docker_inventory import collect_inventory
    from api.modules.vm.services.settings import Connection

    class Client:
        broken = False

        def export_csv(self, query, path):
            kind = 'containers' if '.Containers.' in query else 'images'
            path.write_text('invalid' if self.broken and kind == 'containers' else sample(kind, [BASE] if kind == 'images' else []))

    client = Client()
    conn = Connection(host='vm.example', api_token='test')
    assert collect_inventory(db_session, client, conn, tmp_path)
    row = db_session.scalars(select(VmDockerImage)).one()
    previous_id = row.id
    assert collect_inventory(db_session, client, conn, tmp_path)
    assert db_session.scalars(select(VmDockerImage.id)).one() == previous_id
    client.broken = True
    assert not collect_inventory(db_session, client, conn, tmp_path)
    assert db_session.scalars(select(VmDockerImage.id)).one() == previous_id
    assert db_session.get(VmDockerSnapshot, 1).error
    assert not collect_inventory(db_session, client, conn.model_copy(update={'limit': 20}), tmp_path)
    assert db_session.scalars(select(VmDockerImage.id)).one() == previous_id


def test_docker_hosts_without_cves_are_assets(db_session, tmp_path):
    from api.modules.assets.services.sync import observations_from_vm
    from api.modules.vm.services.docker_inventory import collect_inventory
    from api.modules.vm.services.settings import Connection

    class Client:
        def export_csv(self, query, path):
            kind = 'containers' if '.Containers.' in query else 'images'
            path.write_text(sample(kind, [BASE] if kind == 'images' else []))

    collect_inventory(db_session, Client(), Connection(host='vm.example', api_token='test'), tmp_path)
    hosts = list(observations_from_vm(db_session))
    assert len(hosts) == 1
    assert hosts[0].source_key == 'host-a|10.0.0.1'


@pytest.mark.parametrize('empty_cves', [False, True])
def test_online_import_collects_docker_even_without_vulnerable_hosts(db_session, tmp_path, monkeypatch, empty_cves):
    import json

    import httpx
    from sqlalchemy import select

    from api.modules.vm.docker_models import VmDockerImage
    from tests.vm.test_groups_import import FakeVm, _run_vm

    class InventoryVm(FakeVm):
        def handler(self, request):
            if request.url.path.endswith('/assets_grid'):
                pdql = json.loads(request.content)['pdql']
                if 'Host.Softs<DockerEngine>' in pdql:
                    token = 'docker-containers' if '.Containers.' in pdql else 'docker-images'
                    return httpx.Response(200, json={'token': token})
            return super().handler(request)

    bodies = {'docker-images': sample('images', [BASE]).encode(), 'docker-containers': sample('containers', []).encode()}
    if empty_cves:
        bodies['main'] = b'@Host;Host.@Vulners.CVEs\n'
    fake = InventoryVm(bodies=bodies)
    if empty_cves:
        with pytest.raises(ValueError, match='нет ни одного хоста'):
            _run_vm(db_session, tmp_path, monkeypatch, fake)
    else:
        _run_vm(db_session, tmp_path, monkeypatch, fake)
    assert db_session.scalars(select(VmDockerImage.image_id)).one() == DIGEST
