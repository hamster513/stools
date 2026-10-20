from api.modules.ad.core.score import score

CAT = {"A": "accounts", "B": "accounts", "C": "kerberos", "D": "acl"}


def test_check_contributes_its_worst_finding_once():
    s = score([("A", "Low")] * 300 + [("A", "High"), ("B", "Medium")], CAT)
    assert s["categories"]["accounts"]["score"] == 30 and s["total"] == 30


def test_category_is_capped_and_total_is_max():
    rows = [("C", "Critical")] + [("D", "Critical")] * 2 + [("A", "Low")]
    s = score(rows, {**CAT, "E": "acl", "F": "acl"} | {"D": "acl"})
    assert s["categories"]["kerberos"]["score"] == 40 and s["total"] == 40
    many = score([(c, "Critical") for c in ("D", "E", "F")], {"D": "acl", "E": "acl", "F": "acl"})
    assert many["categories"]["acl"]["score"] == 100 and many["total"] == 100


def test_info_and_unknown_checks_do_not_count():
    assert score([("A", "Info"), ("Z", "Critical")], CAT)["total"] == 0
