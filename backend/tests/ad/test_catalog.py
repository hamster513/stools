from api.modules.ad.core.checks import CHECKS
from api.modules.ad.core.checks.catalog import GUIDANCE
from api.modules.ad.core.checks.common import CATEGORIES


def test_every_check_has_category_and_remediation():
    for c in CHECKS:
        assert c.category in CATEGORIES, c.code
        assert len(c.remediation) >= 30, c.code
        assert all(url.startswith("https://") and title for title, url in c.references), c.code


def test_catalog_has_no_orphans():
    assert set(GUIDANCE) == {c.code for c in CHECKS}
