"""NVD yearly feeds have a separate, still bounded decompressed limit."""
import gzip
import json

import pytest

from api.modules.vm.models import VmJob, VmRefNvd
from api.modules.vm.services import refs


@pytest.mark.parametrize("unpacked_limit,expected_status", [(50_000, "done"), (1_000, "failed")])
def test_nvd_unpacked_limit_is_separate_and_enforced(auth_client, db_session, monkeypatch, unpacked_limit, expected_status):
    monkeypatch.setattr(refs, "MAX_FEED_BYTES", 10_000)
    monkeypatch.setattr(refs, "MAX_NVD_UNPACKED_BYTES", unpacked_limit, raising=False)
    old = VmRefNvd(cve_id="CVE-2026-12345", year=2026, description="original", applicability_loaded=False)
    db_session.add(old); db_session.commit()
    data = {"vulnerabilities": [{"cve": {"id": "CVE-2026-12345", "descriptions": [{"lang": "en", "value": "a" * 20_000}]}}]}
    payload = gzip.compress(json.dumps(data).encode())
    assert len(payload) < refs.MAX_FEED_BYTES
    response = auth_client.post("/api/vm/refs/nvd/upload", files=[("files", ("nvd.json.gz", payload, "application/gzip"))])
    assert response.status_code == 202
    db_session.expire_all()
    job = db_session.get(VmJob, response.json()["job_id"])
    assert job.status == expected_status, job.error
    saved = db_session.get(VmRefNvd, "CVE-2026-12345")
    if expected_status == "done":
        assert saved.applicability_loaded and len(saved.description) == 20_000
    else:
        assert "больше лимита" in job.error
        assert saved.description == "original" and not saved.applicability_loaded
