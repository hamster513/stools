"""SQL counterpart of core.priority; parity is tested over the full input grid."""
from sqlalchemy import case, func, literal, null

from api.modules.vm.core.priority import READY_MSF, priority_policy


def priority_raw(cve, *, criticality=None, internet=None, confidential=None):
    """Normalized additive score before rounding; unknown context is SQL NULL.

    No per-finding Python work or correlated lookups: usable in bulk UPDATE FROM.
    """
    criticality = null() if criticality is None else criticality
    internet = null() if internet is None else internet
    confidential = null() if confidential is None else confidential
    policy = priority_policy()
    epss = case(
        (cve.epss.is_(None), 8), (cve.epss < .001, 2), (cve.epss < .01, 6),
        (cve.epss < .1, 12), (cve.epss < .5, 20), else_=30,
    )
    ready = cve.msf_rank.in_(sorted(READY_MSF))
    public = func.nullif(cve.exploitdb_type, "").is_not(None) | func.nullif(cve.msf_rank, "").is_not(None)
    exploitation = func.greatest(epss, case((public, 24), else_=0),
                                  case((ready, 32), else_=0), case((cve.kev, 40), else_=0))
    severity = func.coalesce(cve.cvss, 5.0) * 2.5
    exposure = case(
        ((cve.av_class == "network") & internet.is_(None), 12),
        ((cve.av_class == "network") & internet.is_(True), 20),
        (cve.av_class == "network", 10), (cve.av_class == "adjacent", 8),
        (cve.av_class == "local", 4), else_=12,
    )
    value = case({"Critical": 15, "High": 12, "Medium": 8, "Low": 4}, value=criticality, else_=8)
    asset = func.least(15, value + case((confidential.is_(True), 2), else_=0))
    floors = policy["floors"]
    floor = func.greatest(
        case((cve.kev, floors["kev_minimum"]), else_=0),
        case((cve.kev & (cve.av_class == "network") & internet.is_(True), floors["kev_network_external_zone"]), else_=0),
        case((ready & (cve.cvss >= 9) & (criticality == "Critical"), floors["ready_exploit_critical_asset"]), else_=0),
    )
    return func.least(100, func.greatest(exploitation + severity + exposure + asset, floor)) / literal(100.0)
