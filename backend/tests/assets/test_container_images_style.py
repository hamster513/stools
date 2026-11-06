import csv
import datetime as dt
import io

from openpyxl import load_workbook

from api.modules.vm.docker_models import VmDockerImage
from api.modules.vm.models import VmImage


def seed_catalog(db):
    for i, state in enumerate(('running', 'stopped', 'unused')):
        db.add(VmDockerImage(image_key=str(i), image_id=f'sha256:{i}', title=f'team/app-{i}',
                            tags=['v1'], platform='linux/amd64', status=state, host_count=1,
                            container_count=0 if state == 'unused' else 1, details={},
                            search_text=f'team/app-{i} host-{i}', collected_at=dt.datetime.now(dt.UTC)))
    db.add(VmImage(project='team', repository='app', digest='sha256:harbor', tags='["v1"]'))
    db.commit()


def test_catalog_multi_filters_and_disjunctive_facets(db_session, client_as):
    seed_catalog(db_session)
    client = client_as({'assets': 'read'})
    base = '/api/assets/container-images'
    data = client.get(base + '?source=mp_vm&status=running&status=stopped&limit=1').json()
    assert data['total'] == 2 and len(data['items']) == 1
    assert data['facets']['status'] == {'running': 1, 'stopped': 1, 'unused': 1, 'unknown': 0}
    assert data['facets']['source'] == {'harbor': 0, 'mp_vm': 2}
    assert client.get(base + '?source=mp_vm&source=harbor').json()['total'] == 4
    assert client.get(base + '?q=host-0').json()['facets']['source'] == {'harbor': 0, 'mp_vm': 1}
    assert client.get(base + '?q=%25').json()['total'] == 0
    assert client.get(base + '?offset=1').json()['facets'] is None
    assert client.get(base + '?source=bad').status_code == 422
    assert client.get(base + '?image_id=1').status_code == 422
    assert client.get(base + '?image_id=1&source=harbor&source=mp_vm').status_code == 422
    assert client.get(base + '?image_id=1&source=harbor').json()['total'] == 1


def test_catalog_export_matches_filters_not_page_and_is_safe(db_session, client_as):
    seed_catalog(db_session)
    db_session.add(VmImage(project='=formula', repository='app', digest='other', tags='[]'))
    db_session.commit()
    client = client_as({'assets': 'read'})
    base = '/api/assets/container-images/export'
    response = client.get(base + '?source=mp_vm&status=running&status=stopped&limit=1&offset=1')
    assert response.status_code == 200
    rows = list(csv.DictReader(io.StringIO(response.content.decode('utf-8-sig')), delimiter=';'))
    assert len(rows) == 2
    assert {r['Образ'] for r in rows} == {'team/app-0', 'team/app-1'}
    assert {r['Источник'] for r in rows} == {'MaxPatrol VM'}
    response = client.get(base + '?source=harbor&format=xlsx')
    assert response.status_code == 200
    book = load_workbook(io.BytesIO(response.content))
    cells = list(book.active.rows)
    assert len(cells) == 3
    assert cells[1][0].data_type != 'f'
    assert cells[1][0].value == '=formula/app'
    assert "'=formula/app" in client.get(base + '?source=harbor').text
    assert client.get(base + '?source=harbor&image_id=1').text.count('team/app') == 1
    assert client.get(base + '?format=bad').status_code == 422
    assert client_as({'vm': 'read'}).get(base).status_code == 403
