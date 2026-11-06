import csv
import io
import json

import pytest
from sqlalchemy import select

from api.db.models import AppSetting
from api.modules.vm.docker_models import VmDockerImage
from api.modules.vm.models import VmImage
from tests.assets.test_container_images_style import seed_catalog


@pytest.mark.parametrize(('raw', 'expected'), [
    ('https://HARBOR.EXAMPLE./', 'harbor.example'),
    ('harbor.example:443', 'harbor.example'),
    ('http://harbor.example:80/base', 'harbor.example'),
    ('harbor.example:8443', 'harbor.example:8443'),
    ('registry.evil/harbor.example', 'registry.evil'),
    ('[2001:db8::1]:5000', '[2001:db8::1]:5000'),
    ('', None), ('https://', None), ('bad host', None),
    ('https://user:secret@harbor.example', None), ('harbor.example:bad', None),
    ('ftp://harbor.example', None), ('harbor.example\\@evil', None),
])
def test_registry_identity(raw, expected):
    from api.modules.assets.services.image_origins import registry_identity
    assert registry_identity(raw) == expected


@pytest.mark.parametrize(('addresses', 'known', 'expected'), [
    (['harbor.example'], {'harbor.example'}, 'corporate'),
    (['docker.io'], {'harbor.example'}, 'external'),
    (['harbor.example.evil'], {'harbor.example'}, 'external'),
    (['harbor.example:5000'], {'harbor.example'}, 'external'),
    (['harbor.example', 'docker.io'], {'harbor.example'}, 'mixed'),
    (['harbor.example', ''], {'harbor.example'}, 'unknown'),
    (['docker.io', ''], {'harbor.example'}, 'external'),
    ([''], {'harbor.example'}, 'unknown'),
    ([], {'harbor.example'}, 'unknown'),
    (['docker.io'], set(), 'unknown'),
])
def test_origin_requires_registry_evidence(addresses, known, expected):
    from api.modules.assets.services.image_origins import origin_for_references
    result = origin_for_references([{'registry': r, 'repo': 'same/app', 'tag': 'latest'} for r in addresses], known)
    assert result['registry_origin'] == expected
    assert result['external_registries'] == ([] if expected not in ('external', 'mixed') else sorted({r for r in addresses if r and r not in known}))


def test_origin_consistent_in_list_detail_export_and_uses_saved_harbor(db_session, client_as):
    seed_catalog(db_session)
    db_session.add(AppSetting(key='vm_harbor', value_json=json.dumps({'url': 'https://HARBOR.EXAMPLE'})))
    harbor = db_session.scalar(select(VmImage).limit(1))
    harbor.registry_url = 'https://previous.example'
    docker = list(db_session.scalars(select(VmDockerImage).order_by(VmDockerImage.id).limit(10)))
    for item, addresses in zip(docker, [['harbor.example', 'docker.io'], ['previous.example'], ['']]):
        item.details = {'references': [{'registry': r, 'repo': 'same/app', 'tag': 'v1'} for r in addresses]}
    db_session.commit()
    client = client_as({'assets': 'read'})
    base = '/api/assets/container-images'
    data = client.get(base).json()
    origins = {(i['source'], i['id']): i['registry_origin'] for i in data['items']}
    assert origins[('harbor', harbor.id)] == 'corporate'
    assert [origins[('mp_vm', i.id)] for i in docker] == ['mixed', 'corporate', 'unknown']
    for item in data['items']:
        detail = client.get(f"{base}/{item['source']}/{item['id']}").json()
        assert detail['registry_origin'] == item['registry_origin']
        assert detail['registries'] == item['registries']
        assert detail['external_registries'] == item['external_registries']
    mixed = client.get(f'{base}/mp_vm/{docker[0].id}').json()
    assert mixed['external_registries'] == ['docker.io']
    rows = list(csv.DictReader(io.StringIO(client.get(base + '/export').content.decode('utf-8-sig')), delimiter=';'))
    assert {r['Реестр'] for r in rows} == {'Корпоративный', 'Есть внешние реестры', 'Не определён'}
    assert any(r['Внешние реестры'] == 'docker.io' for r in rows)


def test_image_removed_during_enrichment_keeps_list_readable(db_session, monkeypatch):
    from sqlalchemy import delete

    from api.modules.assets.routers.container_images import _catalog, _items

    seed_catalog(db_session)
    removed_id = db_session.scalar(select(VmDockerImage.id).order_by(VmDockerImage.id).limit(1))
    execute = db_session.execute
    removed = False

    def execute_with_sync(statement, *args, **kwargs):
        nonlocal removed
        result = execute(statement, *args, **kwargs)
        if not removed:
            # The catalogue SELECT already returned; synchronization removes an
            # image before the next query fetches its tags and registry evidence.
            removed = True
            execute(delete(VmDockerImage).where(VmDockerImage.id == removed_id))
            db_session.commit()
        return result

    monkeypatch.setattr(db_session, 'execute', execute_with_sync)
    items = _items(db_session, _catalog(), {'q': '', 'source': None, 'status': None, 'image_id': None}, limit=100)
    item = next(i for i in items if i['source'] == 'mp_vm' and i['id'] == removed_id)
    assert item['registry_origin'] == 'unknown'
    assert item['external_registries'] == []
