"""A consistent read-only export with canonical affected-asset counts."""
from sqlalchemy import func, select

from api.modules.vm.ghsa_models import VmRefGhsa, VmRefGhsaAlias
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmImage, VmImageCve, VmZone
from scripts.export_vm_priority_snapshot import export_snapshot


def test_export_is_read_only_and_preserves_context_and_alias_counts(db_session):
    cve, ghsa = "CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"
    db_session.add_all([VmCve(cve_id=cve, cvss=9.8, v3_av="", v2_av="NETWORK"), VmCve(cve_id=ghsa, cvss=9.8), VmRefGhsa(ghsa_id=ghsa),
                        VmZone(name="unmarked", internet_access=True, confidential_data=True, marked=False)])
    db_session.flush()
    db_session.add(VmRefGhsaAlias(ghsa_id=ghsa, alias=cve))
    host = VmHost(hostname="synthetic", zone="unmarked", criticality="High")
    image = VmImage(project="synthetic", repository="test", digest="sha256:test")
    db_session.add_all([host, image]); db_session.flush()
    db_session.add_all([VmHostCve(host_id=host.id, cve_id=cve, risk=20), VmHostCve(host_id=host.id, cve_id=ghsa, risk=20)])
    db_session.add_all([VmImageCve(image_id=image.id, cve_id=identifier, package=package, installed_version="1", trivy_severity="high")
                       for identifier in (cve, ghsa) for package in ("one", "two")])
    db_session.commit()
    snapshot = export_snapshot(db_session.get_bind())
    assert snapshot["meta"]["transaction_read_only"] == "on"
    assert snapshot["meta"]["transaction_isolation"] == "repeatable read"
    assert next(c for c in snapshot["cves"] if c["cve_id"] == cve)["av"] == "NETWORK"
    assert snapshot["canonical"][ghsa] == cve
    assert snapshot["prevalence"][cve] == {"hosts": 1, "images": 1}
    assert sum(c["findings"] for c in snapshot["contexts"]) == 6
    host_context = next(c for c in snapshot["contexts"] if c["kind"] == "host")
    assert host_context["internet"] is True and host_context["zone_marked"] is False
    assert "hostname" not in host_context and "ip" not in host_context
    assert db_session.scalar(select(func.count()).select_from(VmHostCve)) == 2
    assert db_session.scalar(select(func.count()).select_from(VmImageCve)) == 4


def test_empty_settings_use_default_weights(db_session):
    from api.db.models import AppSetting
    from api.modules.vm.core.weights import Weights
    from api.modules.vm.services.settings import VM_KEY

    db_session.add(AppSetting(key=VM_KEY, value_json=""))
    db_session.commit()
    snapshot = export_snapshot(db_session.get_bind())
    assert snapshot["meta"]["weights"] == Weights().model_dump()
    assert snapshot["contexts"] == []
