import csv
import datetime as dt
import io
import json

import pytest
from openpyxl import load_workbook

from api.db.models import AppSetting
from api.modules.vm.docker_models import VmDockerImage
from api.modules.vm.models import VmImage


def seed(db):
    db.add(AppSetting(key='vm_harbor', value_json=json.dumps({'url': 'https://harbor.example'})))
    db.add(VmImage(project='team', repository='app', digest='sha256:harbor', registry_url='https://harbor.example', tags='["latest"]', platform='linux/amd64'))
    samples = [
        ('external', ['docker.io'], 'team/app', ['v1'], 'linux/amd64'),
        ('missing', ['docker.io'], 'sha256:' + 'a'*64, ['<none>'], 'linux/arm64'),
        ('mixed', ['harbor.example', 'docker.io'], 'team/mixed', ['v1', 'none'], 'linux/amd64, linux/arm64'),
        ('unknown', [''], '', [], ''),
        ('corp', ['harbor.example'], 'team/corp', [' NONE '], 'linux/amd64'),
        ('literal', ['docker.io'], 'team/literal', ['v1,stable'], 'linux/amd64'),
    ]
    for key, registries, repo, tags, platform in samples:
        refs = [{'registry': r, 'repo': repo, 'tag': t} for r in registries for t in tags or ['']]
        db.add(VmDockerImage(image_key=key, image_id='sha256:'+'a'*64, title=repo or 'Образ не определён',
                            tags=tags, platform=platform, status='running', host_count=1, container_count=1,
                            details={'references': refs}, search_text=f'{key} {repo}', collected_at=dt.datetime.now(dt.UTC)))
    db.commit()


def test_filter_combinations_facets_and_export(db_session, client_as):
    seed(db_session)
    client=client_as({'assets':'read'})
    base='/api/assets/container-images'
    data=client.get(base+'?registry=docker.io&name_state=missing&tag=-&limit=1').json()
    assert data['total']==1
    assert data['items'][0]['display_title']=='Без названия'
    assert data['items'][0]['image_id'].startswith('sha256:')
    assert data['facets']['name_state']=={'present':1,'missing':1}  # mixed also has a none alias
    assert client.get(base+'?registry_origin=external&registry_origin=mixed').json()['total']==4
    assert client.get(base+'?tag=-').json()['total']==4
    assert client.get(base+'?tag=v1%2Cstable').json()['total']==1
    assert client.get(base+'?registry=harbor.example').json()['total']==3
    assert client.get(base+'?platform=linux%2Farm64').json()['total']==2
    assert client.get(base+'?registry=-&platform=-').json()['total']==1
    assert client.get(base+'?name_state=present&name_state=missing').json()['total']==7
    data=client.get(base+'?tag=v1&tag=-&limit=2').json()
    assert data['total']==5 and len(data['items'])==2
    pages=[client.get(base+f'?tag=v1&tag=-&limit=2&offset={n}').json() for n in (0,2,4)]
    keys=[(i['source'],i['id']) for page in pages for i in page['items']]
    assert len(set(keys))==len(keys)==5
    assert pages[1]['facets'] is None
    csv_rows=list(csv.DictReader(io.StringIO(client.get(base+'/export?tag=v1&tag=-&limit=2').content.decode('utf-8-sig')),delimiter=';'))
    assert len(csv_rows)==5
    workbook=load_workbook(io.BytesIO(client.get(base+'/export?registry=docker.io&name_state=missing&format=xlsx').content))
    assert len(list(workbook.active.rows))==2
    assert client.get(base+'?q=missing&registry=harbor.example').json()['total']==0
    assert client.get(base+'?registry_origin=other').status_code==422
    assert client.get(base+'?name_state=invalid').status_code==422
    assert client_as({'vm':'read'}).get(base+'?tag=-').status_code==403


@pytest.mark.parametrize(('repo','expected'), [('',True),('none',True),('<none>',True),('a'*64,True),('sha256:'+'a'*64,True),('team/none',False),('team/real',False)])
def test_name_is_based_on_repository_not_registry(repo,expected):
    from api.modules.assets.services.image_filters import image_filter_fields
    item={'title':'harbor.example/'+repo, 'image_id':'sha256:'+'a'*64, 'tags':[]}
    result=image_filter_fields(item,[{'registry':'harbor.example','repo':repo,'tag':''}])
    assert (result['name_state']=='missing') is expected


def test_literal_all_tag_is_not_a_wildcard(db_session, client_as):
    seed(db_session)
    db_session.add(VmImage(project='team', repository='all-tag', digest='other', tags='["all"]'))
    db_session.commit()
    client=client_as({'assets':'read'})
    base='/api/assets/container-images'
    data=client.get(base+'?tag=all').json()
    assert data['total']==1 and data['items'][0]['title']=='team/all-tag'
    assert client.get(base+'?tag=all&tag=latest').json()['total']==2
    rows=list(csv.DictReader(io.StringIO(client.get(base+'/export?tag=all').content.decode('utf-8-sig')),delimiter=';'))
    assert len(rows)==1


def test_blank_reference_tag_is_preserved_with_a_real_tag():
    from api.modules.assets.services.image_filters import image_filter_fields
    fields=image_filter_fields({'title':'team/app','image_id':'sha256:id','tags':['v1']},
                              [{'repo':'team/app','tag':'v1'},{'repo':'team/app','tag':''}])
    assert set(fields['filter_tags'])=={'v1','-'}
