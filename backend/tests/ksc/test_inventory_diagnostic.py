"""The production probe reports schema/counts, never host or software values."""
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "ops/diagnose_ksc_inventory.sh"


@pytest.mark.parametrize("key", ["KLEVP_EA_PARAM_1", "GNRL_EA_PARAM_1"])
def test_diagnostic_does_not_expose_inventory_values(key):
    source = SCRIPT.read_text().split("<<'KSC_PROBE_PY'\n", 1)[1].split("\nKSC_PROBE_PY", 1)[0]
    namespace = {"__name__": "test_probe"}
    exec(compile(source, str(SCRIPT), "exec"), namespace)
    response = {"PxgRetVal": {"type": "params", "value": {
        key: [{"type": "params", "value": {"DisplayName": "SECRET_NAME", "DisplayVersion": "SECRET_VERSION", "InstallDir": "SECRET_PATH"}}, 42],
        "SECRET_DYNAMIC_FIELD": "SECRET_VALUE",
    }}, "SECRET_SESSION": "SECRET_TOKEN"}
    report = namespace["response_shape"](response)
    assert "SECRET" not in json.dumps(report)
    assert report["fields"][key] == {"type": "list", "count": 2, "invalid_record_count": 1, "named_record_count": 1, "versioned_record_count": 1}
    assert report["other_field_count"] == 1


@pytest.mark.parametrize("value", [None, {}, [], {"GNRL_EA_PARAM_1": None}, {"GNRL_EA_PARAM_1": []}])
def test_diagnostic_handles_missing_and_malformed_payload(value):
    source = SCRIPT.read_text().split("<<'KSC_PROBE_PY'\n", 1)[1].split("\nKSC_PROBE_PY", 1)[0]
    namespace = {"__name__": "test_probe"}
    exec(compile(source, str(SCRIPT), "exec"), namespace)
    report = namespace["response_shape"]({"PxgRetVal": value})
    assert report["return_present"] is True
    assert report["return_type"] == type(value).__name__
