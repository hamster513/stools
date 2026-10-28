"""Риск пар «образ × CVE» по формуле VM и сохранность витрины для образов."""
from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from api.modules.vm.core.risk import reach, score
from api.modules.vm.core.weights import Weights
from api.modules.vm.models import VmCve, VmHost, VmHostCve, VmImage, VmImageCve
from api.modules.vm.services.scoring import (
    drop_orphan_cves,
    image_value,
    rescore_all,
    rescore_image_pairs,
)
from tests.vm.test_import import _upload

CVE = "CVE-2024-0001"


def _image(db: Any, repository: str = "alpine") -> VmImage:
    image = VmImage(project="library", repository=repository, digest=f"sha256:{repository}", tags='["3.20"]')
    db.add(image)
    db.flush()
    return image


def _pair(db: Any, image: VmImage, cve_id: str = CVE, package: str = "busybox") -> None:
    db.add(VmImageCve(image_id=image.id, cve_id=cve_id, package=package, installed_version="1.36.1-r0", trivy_severity="High"))


def test_rescore_image_pairs_uses_cve_mart(db_session: Any) -> None:
    w = Weights()
    db_session.add(VmCve(cve_id=CVE, likelihood=0.5, cvss10=0.8, av_class="network"))
    image = _image(db_session)
    _pair(db_session, image)
    # Второй образ без CVE из витрины: максимум считается по своим парам, а не по всем.
    other = _image(db_session, "web")
    _pair(db_session, other, cve_id="GHSA-x")
    db_session.commit()

    assert rescore_image_pairs(db_session, w) == 1

    db_session.expire_all()
    expected = score(0.5 * 0.8 * reach("network", False, w) * image_value(w))
    pair = db_session.get(VmImageCve, (image.id, CVE, "busybox", "1.36.1-r0"))
    assert pair.risk == expected and expected > 0
    img = db_session.get(VmImage, image.id)
    assert img.risk_max == pair.risk and img.cves_scored == 1
    assert db_session.get(VmImage, other.id).risk_max is None


def test_non_cve_pair_has_null_risk(db_session: Any) -> None:
    image = _image(db_session)
    _pair(db_session, image, cve_id="GHSA-x")
    db_session.commit()
    # Риск, оставшийся от прежнего пересчёта, сбрасывается.
    db_session.query(VmImageCve).update({"risk_raw": 0.3, "risk": 30})
    db_session.query(VmImage).update({"risk_max": 30, "cves_scored": 1})
    db_session.commit()

    assert rescore_image_pairs(db_session, Weights()) == 0

    db_session.expire_all()
    pair = db_session.get(VmImageCve, (image.id, "GHSA-x", "busybox", "1.36.1-r0"))
    assert pair.risk is None and pair.risk_raw is None
    img = db_session.get(VmImage, image.id)
    assert img.risk_max is None and img.cves_scored == 0


def test_drop_orphan_keeps_image_cves(db_session: Any) -> None:
    db_session.add_all([VmCve(cve_id=CVE), VmCve(cve_id="CVE-2024-0002")])
    image = _image(db_session)
    _pair(db_session, image)
    db_session.commit()

    assert drop_orphan_cves(db_session) == 1

    db_session.expire_all()
    assert db_session.get(VmCve, CVE) is not None
    assert db_session.get(VmCve, "CVE-2024-0002") is None


def test_rescore_all_counts_both(db_session: Any) -> None:
    db_session.add(VmCve(cve_id=CVE, likelihood=0.5, cvss10=0.8, av_class="network"))
    host = VmHost(hostname="srv01", ip="10.0.0.1")
    db_session.add(host)
    db_session.flush()
    db_session.add(VmHostCve(host_id=host.id, cve_id=CVE))
    _pair(db_session, _image(db_session, "web"))
    db_session.commit()

    assert rescore_all(db_session, Weights()) == 2


def test_import_keeps_image_cves(auth_client: TestClient, db_session: Any) -> None:
    db_session.add(VmCve(cve_id=CVE, likelihood=0.5, cvss10=0.8, av_class="network"))
    image = _image(db_session)
    _pair(db_session, image)
    db_session.commit()

    assert _upload(auth_client, "hosts.csv")["status"] == "done"

    db_session.expire_all()
    assert db_session.get(VmCve, CVE) is not None
    # Импорт пересчитывает и пары образов: риск по витрине на месте.
    pair = db_session.get(VmImageCve, (image.id, CVE, "busybox", "1.36.1-r0"))
    assert pair.risk is not None


def test_image_tables_match_models(db_session: Any) -> None:
    """Таблицы образов из миграции совпадают с моделями."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from api.db.models import Base

    ctx = MigrationContext.configure(db_session.connection(), opts={"compare_type": True, "compare_server_default": False})
    diffs = [d for d in compare_metadata(ctx, Base.metadata) if "vm_image" in repr(d)]
    assert diffs == []
