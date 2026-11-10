"""Running-image filter shares confirmed identities and snapshot rules with host counts."""
import csv
import io

import pytest

from api.modules.vm.docker_models import VmDockerSnapshot
from api.modules.vm.models import VmImage
from api.modules.vm.services.docker_inventory import collect_inventory
from api.modules.vm.services.settings import Connection
from tests.vm.test_docker_inventory import BASE, sample


def digest(letter):
    return 'sha256:' + letter * 64


@pytest.fixture
def inventory(db_session, tmp_path):
    rows = {letter: [*BASE[:2], digest(letter), *BASE[3:]] for letter in 'abcde'}

    class Client:
        def export_csv(self, query, path):
            kind = 'containers' if '.Containers.' in query else 'images'
            containers = [
                rows['a'] + ['a1', 'app', 'running', '', '', ''],
                rows['a'] + ['a2', 'old', 'exited', '', '', ''],
                rows['b'] + ['b1', 'worker', 'running', '', '', ''],
                rows['c'] + ['c1', 'old', 'exited', '', '', ''],
                rows['e'] + ['e1', 'unknown', 'unknown', '', '', ''],
            ]
            path.write_text(sample(kind, list(rows.values()) if kind == 'images' else containers))

    collect_inventory(db_session, Client(), Connection(host='vm.example', api_token='test'), tmp_path)
    specs = [
        ('team', 'app', [digest('a'), digest('b')]),
        ('other', 'app', [digest('a')]),
        ('team', 'stopped', [digest('c')]),
        ('team', 'unused', [digest('d')]),
        ('team', 'unknown', [digest('e')]),
        ('team', 'unmapped', []),
        ('team', 'missing', [digest('f')]),
    ]
    for i, (project, name, refs) in enumerate(specs):
        db_session.add(VmImage(project=project, repository=name, digest=digest('a'), runtime_ids=refs, risk_max=10+i))
    db_session.commit()


def test_running_filter_applies_before_pages_and_facets(auth_client, inventory):
    response = auth_client.get('/api/vm/images?running_only=true&sort=name&limit=1')
    assert response.status_code == 200
    first = response.json()
    assert first['total'] == 2
    assert first['facets']['project'] == {'other': 1, 'team': 1}
    assert [(row['project'], row['repository']) for row in first['items']] == [('other', 'app')]
    assert first['items'][0]['running_host_count'] > 0
    second = auth_client.get('/api/vm/images?running_only=true&sort=name&limit=1&offset=1').json()
    assert [(row['project'], row['repository']) for row in second['items']] == [('team', 'app')]
    assert second['items'][0]['running_host_count'] > 0
    assert auth_client.get('/api/vm/images?running_only=true&offset=2').json()['items'] == []
    assert auth_client.get('/api/vm/images').json()['total'] == 7
    assert auth_client.get('/api/vm/images?running_only=false').json()['total'] == 7


def test_running_filter_combines_with_search_project_and_export(auth_client, inventory):
    args = 'running_only=true&project=team&q=app'
    listing = auth_client.get('/api/vm/images?' + args).json()
    assert listing['total'] == 1
    assert listing['facets']['project'] == {'team': 1}
    for suffix, expected in [('', {'team/app', 'other/app'}), ('&project=team', {'team/app'})]:
        exported = auth_client.get('/api/vm/images/export?format=csv&running_only=true' + suffix)
        assert exported.status_code == 200
        rows = list(csv.DictReader(io.StringIO(exported.content.decode('utf-8-sig')), delimiter=';'))
        assert {row['Образ'] for row in rows} == expected
        assert len(rows) == len(expected)
    assert auth_client.get('/api/vm/images?running_only=true&q=unused').json()['total'] == 0


@pytest.mark.parametrize('missing', [False, True])
def test_running_filter_requires_completed_snapshot(auth_client, db_session, inventory, missing):
    snapshot = db_session.get(VmDockerSnapshot, 1)
    if missing:
        db_session.delete(snapshot)
    else:
        snapshot.collected_at = None
    db_session.commit()
    body = auth_client.get('/api/vm/images?running_only=true').json()
    assert body['items'] == [] and body['total'] == 0 and body['facets']['project'] == {}


def test_running_filter_uses_last_successful_snapshot(auth_client, db_session, inventory):
    snapshot = db_session.get(VmDockerSnapshot, 1)
    snapshot.error = 'Последний сбор не удался'
    db_session.commit()
    body = auth_client.get('/api/vm/images?running_only=true').json()
    assert body['total'] == 2
    assert all(row['running_host_count'] > 0 for row in body['items'])


def test_running_filter_rejects_invalid_boolean(auth_client):
    assert auth_client.get('/api/vm/images?running_only=maybe').status_code == 422
