"""All VM addresses survive import without changing host/CVE identity."""
import csv
import datetime as dt
import io
import json

import pytest
from sqlalchemy import select

from api.modules.assets.core.matching import Candidate, Observed, match
from api.modules.assets.models import AssetObservation
from api.modules.assets.services.assets import apply_observation, asset_detail
from api.modules.assets.services.read_model import refresh
from api.modules.assets.services.sync import observations_from_vm
from api.modules.vm.core.mpvm import build_pdql
from api.modules.vm.core.sources import iter_csv, iter_json
from api.modules.vm.models import VmHost, VmHostCve
from api.modules.vm.sbom_models import VmHostCoverage, VmPackageFeed, VmPackageHost
from api.modules.vm.services.settings import Connection
from tests.vm.test_import import _upload

HOST = 'multi.example.test (192.0.2.10)'
KEY = 'multi.example.test|192.0.2.10'
CVE = 'CVE-2026-12345'


def export(*rows):
    out = io.StringIO()
    writer = csv.writer(out, delimiter=';')
    writer.writerow(['@Host', 'Host.@Vulners.CVEs', 'Host.@IpAddresses'])
    writer.writerows(rows)
    return out.getvalue().encode()


def test_online_query_collects_full_address_alias():
    assert 'Host.@IpAddresses' in build_pdql(Connection())


@pytest.mark.parametrize('value', [
    '192.0.2.11, 2001:DB8:0:0::1, 192.0.2.11, invalid',
    '192.0.2.11\n2001:DB8:0:0::1\n192.0.2.11',
    '["192.0.2.11", "2001:DB8:0:0::1", "192.0.2.11"]',
])
def test_csv_keeps_all_ipv4_ipv6_addresses(value):
    row = next(iter_csv(io.StringIO(export((HOST, CVE, value)).decode())))
    assert row.ip == '192.0.2.10'
    assert row.ips == ['192.0.2.10', '192.0.2.11', '2001:db8::1']


def test_json_and_legacy_inputs():
    row = next(iter_json(io.BytesIO(json.dumps([{'host': HOST, 'cve': CVE, 'ips': ['192.0.2.11', '2001:DB8::1', None, 'invalid']}]).encode())))
    assert row.ips == ['192.0.2.10', '192.0.2.11', '2001:db8::1']
    legacy = next(iter_csv(io.StringIO('@Host;Host.@Vulners.CVEs\n'+HOST+';'+CVE+'\n')))
    assert legacy.ips == ['192.0.2.10']


def test_import_unions_addresses_and_keeps_host_pair_counts(auth_client, db_session):
    body = export((HOST, CVE, '192.0.2.11'), (HOST, CVE, '2001:DB8::1'),
                  ('clean.example.test (192.0.2.30)', '', '192.0.2.31'))
    assert _upload(auth_client, 'ips.csv', body)['status'] == 'done'
    assert len(db_session.scalars(select(VmHost).limit(5)).all()) == 1
    assert len(db_session.scalars(select(VmHostCve).limit(5)).all()) == 1
    assert db_session.get(VmHostCoverage, KEY).ips == ['192.0.2.10', '192.0.2.11', '2001:db8::1']
    assert db_session.get(VmHostCoverage, 'clean.example.test|192.0.2.30').ips == ['192.0.2.30', '192.0.2.31']
    observation = next(x for x in observations_from_vm(db_session) if x.source_key == KEY)
    assert observation.ip == '192.0.2.10' and observation.ips == ['192.0.2.10', '192.0.2.11', '2001:db8::1']
    asset, _ = apply_observation(db_session, observation)
    db_session.commit()
    refresh(db_session)
    db_session.commit()
    found = auth_client.get("/api/assets/assets", params={"q": "2001:db8::1"})
    assert found.status_code == 200
    assert [item["id"] for item in found.json()["items"]] == [asset.id]
    detail = asset_detail(db_session, asset.id)
    assert next(x for x in detail['observations'] if x['source_key'] == KEY)['ips'] == observation.ips
    db_session.commit()
    assert _upload(auth_client, 'next.csv', export((HOST, CVE, '192.0.2.12')))['status'] == 'done'
    updated = next(x for x in observations_from_vm(db_session) if x.source_key == KEY)
    assert updated.ips == ['192.0.2.10', '192.0.2.12']
    apply_observation(db_session, updated)
    saved = db_session.scalar(select(AssetObservation).where(AssetObservation.source_key == KEY).limit(1))
    assert saved.asset_id == asset.id and saved.ips == updated.ips


def test_addresses_reach_package_hosts_without_cves(auth_client, db_session):
    assert _upload(auth_client, 'ips.csv', export((HOST, CVE, ''), ('clean.example.test (192.0.2.30)', '', '192.0.2.31')))['status'] == 'done'
    db_session.add(VmPackageFeed(kind='unix', checked_at=dt.datetime.now(dt.UTC), collected_at=dt.datetime.now(dt.UTC)))
    db_session.add(VmPackageHost(kind='unix', source_key='clean.example.test|192.0.2.30', hostname='clean.example.test', ip='192.0.2.30', os_name='Linux', packages=[], changed_at=dt.datetime.now(dt.UTC)))
    db_session.commit()
    row = next(x for x in observations_from_vm(db_session) if x.source_key == 'clean.example.test|192.0.2.30')
    assert row.ips == ['192.0.2.30', '192.0.2.31']


def test_missing_primary_uses_an_address_without_changing_source_key(auth_client, db_session):
    assert _upload(auth_client, 'ips.csv', export(('no-primary.example.test', CVE, '192.0.2.40,2001:db8::40')))['status'] == 'done'
    row = next(x for x in observations_from_vm(db_session) if x.source_key == 'no-primary.example.test|')
    assert row.ip == '192.0.2.40' and row.ips == ['192.0.2.40', '2001:db8::40']


def test_truncated_import_preserves_addresses(auth_client, db_session):
    assert _upload(auth_client, 'ips.csv', export((HOST, CVE, '192.0.2.11')))['status'] == 'done'
    before = db_session.get(VmHostCoverage, KEY).ips.copy()
    assert _upload(auth_client, 'broken.csv', export((HOST, CVE, '192.0.2.99'))+b'"unfinished')['status'] == 'failed'
    assert db_session.get(VmHostCoverage, KEY).ips == before


@pytest.mark.parametrize('shared', ['127.0.0.1', '::1', '0.0.0.0', '::', '169.254.1.1', 'fe80::1', '224.0.0.1', 'ff02::1'])
def test_non_unique_interface_addresses_do_not_merge_hosts(shared):
    old = Observed(source='vm', source_key='192.0.2.10|', ip='192.0.2.10', ips=['192.0.2.10', shared])
    new = Observed(source='vm', source_key='192.0.2.20|', ip='192.0.2.20', ips=['192.0.2.20', shared])
    candidate = Candidate(asset_id=1, name='', fqdn='', domain='', ip=old.ip, observations=[old])
    assert match(new, [candidate])[0] is None
