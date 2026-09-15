from kbaudit.parsers.metainfo import parse_metainfo

CORRELATION = """
Category:
EventDescriptions:
- Criteria: 'correlation_name = "DEMO_HC_002_029_Impacket" and object.name = "svcctl"'
  LocalizationId: 6f1e-uuid
PtkbId: aaaa-bbbb
ObjectId: LOC-CR-5797
Origin: Local
"""

ENRICHMENT = """
Rule: DEMO_Trojan_Was_Detected
PtkbId: cccc-dddd
ObjectId: LOC-ER-395
Origin: Local
"""


def test_correlation_metainfo() -> None:
    meta = parse_metainfo(CORRELATION.encode())
    assert meta.object_id == "LOC-CR-5797"
    assert meta.origin == "Local"
    assert meta.category is None
    assert meta.correlation_names == ["DEMO_HC_002_029_Impacket"]


def test_enrichment_metainfo_uses_rule_key() -> None:
    meta = parse_metainfo(ENRICHMENT.encode())
    assert meta.rule_name == "DEMO_Trojan_Was_Detected"
    assert meta.object_id == "LOC-ER-395"


def test_broken_yaml_yields_empty_metainfo() -> None:
    meta = parse_metainfo("\tэто: [не, yaml\n".encode())
    assert meta.object_id is None
    assert meta.criteria == []


def test_null_correlation_name_is_not_collected() -> None:
    raw = b"""
EventDescriptions:
- Criteria: 'correlation_name = "null"'
"""
    assert parse_metainfo(raw).correlation_names == []
