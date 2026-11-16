"""Initial additive policy: evidence, uncertainty, and non-compensable floors."""
import math

import pytest

from api.modules.vm.core.priority import AssetContext, priority_score
from api.modules.vm.core.risk import CveInputs


@pytest.mark.parametrize("epss,points", [(0, 2), (.0009, 2), (.001, 6), (.01, 12), (.1, 20), (.5, 30), (1, 30), (None, 8)])
def test_epss_bands(epss, points):
    result = priority_score(CveInputs(epss=epss), AssetContext())
    assert result.blocks["exploitation"].points == points


def test_exploit_sources_do_not_stack():
    context = AssetContext(criticality="Medium", internet=False, confidential=False)
    plain = priority_score(CveInputs(cvss=7, av="NETWORK", epss=.8, msf_rank="good"), context)
    extra = priority_score(CveInputs(cvss=7, av="NETWORK", epss=.8, msf_rank="good", exploitdb_type="remote"), context)
    assert plain.score == extra.score
    assert extra.blocks["exploitation"].points == 32


def test_missing_data_remains_visible_and_does_not_zero_score():
    result = priority_score(CveInputs(cvss=9.8, av="NETWORK", kev_loaded=False), AssetContext())
    assert result.score == 53
    assert {"epss", "kev_catalog", "criticality", "exposure"} <= set(result.missing)
    assert result.blocks["exploitation"].assumed


@pytest.mark.parametrize("internet,floor", [(False, 70), (None, 70), (True, 90)])
def test_kev_floors_require_known_external_exposure(internet, floor):
    result = priority_score(CveInputs(cvss=0, epss=0, av="NETWORK", kev=True),
                            AssetContext(criticality="Low", internet=internet, confidential=False), high_threshold=65)
    assert result.score == floor
    assert result.floor == floor


def test_external_local_vulnerability_does_not_get_network_floor():
    result = priority_score(CveInputs(cvss=0, epss=0, av="LOCAL", kev=True),
                            AssetContext(criticality="Low", internet=True, confidential=False), high_threshold=65)
    assert result.score == 70


@pytest.mark.parametrize("rank,criticality,cvss,floor", [
    ("good", "Critical", 9, 85), ("excellent", "Critical", 10, 85),
    ("normal", "Critical", 9, 0), ("good", "High", 9, 0), ("good", "Critical", 8.9, 0),
])
def test_critical_asset_ready_exploit_floor(rank, criticality, cvss, floor):
    result = priority_score(CveInputs(cvss=cvss, epss=0, av="LOCAL", msf_rank=rank),
                            AssetContext(criticality=criticality, internet=False, confidential=False))
    assert result.floor == floor


def test_maximum_and_no_double_internet_bonus():
    cve = CveInputs(cvss=10, av="NETWORK", kev=True)
    result = priority_score(cve, AssetContext(criticality="Critical", internet=True, confidential=True))
    assert result.score == 100
    assert sum(block.points for block in result.blocks.values()) == 100
    low = priority_score(CveInputs(cvss=5, av="NETWORK", epss=0), AssetContext(criticality="High", internet=False, confidential=False))
    high = priority_score(CveInputs(cvss=5, av="NETWORK", epss=0), AssetContext(criticality="High", internet=True, confidential=False))
    assert high.score - low.score == 10
    assert high.blocks["asset"].points == low.blocks["asset"].points == 12


def test_scores_are_monotonic_in_cvss_and_epss():
    context = AssetContext(criticality="High", internet=True, confidential=True)
    scores = [priority_score(CveInputs(cvss=x/10, epss=.02, av="NETWORK"), context).score for x in range(101)]
    assert scores == sorted(scores)
    scores = [priority_score(CveInputs(cvss=8, epss=x/100, av="NETWORK"), context).score for x in range(101)]
    assert scores == sorted(scores)
    assert all(0 <= s <= 100 for s in scores)


@pytest.mark.parametrize("value", [-1, 11, math.nan, math.inf])
def test_invalid_cvss_is_rejected(value):
    with pytest.raises(ValueError):
        priority_score(CveInputs(cvss=value), AssetContext())
