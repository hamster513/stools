"""Opt-in roundtrip of a real downloader bundle, always in disposable test DB."""
import os
from pathlib import Path

import pytest

from api.modules.siem.hunting.intel import read_bundle

BUNDLE = os.environ.get('STOOLS_TH_INTEL_BUNDLE', '')


@pytest.mark.skipif(not BUNDLE, reason='set STOOLS_TH_INTEL_BUNDLE to an offline downloader ZIP')
def test_downloaded_bundle_roundtrip(auth_client):
    data = Path(BUNDLE).read_bytes()
    manifest, items = read_bundle(data)
    response = auth_client.post('/api/siem/hunting/intel/import', files={'file': ('live.zip', data, 'application/zip')})
    assert response.status_code == 200, response.text
    assert response.json()['added'] == len(items) == manifest.items_count
    listing = auth_client.get('/api/siem/hunting/intel', params={'limit': 1}).json()
    assert listing['total'] == len(items)
    if items:
        row = auth_client.get('/api/siem/hunting/intel/'+listing['items'][0]['id']).json()
        assert row['source']['name']
    again = auth_client.post('/api/siem/hunting/intel/import', files={'file': ('live.zip', data, 'application/zip')})
    assert again.status_code == 200 and again.json()['duplicate']
    assert auth_client.get('/api/siem/hunting/intel').json()['total'] == len(items)
