"""Diagnostic SQLite keeps IP lookup semantics without PostgreSQL functions."""
import datetime as dt

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.modules.assets.models import Asset, AssetObservation
from api.modules.toolbox.services import lookup_inventory, lookup_types
from api.platform.search.service import candidate_rows


@pytest.fixture
def offline_db():
    engine = create_engine("sqlite://")
    lookup_types.configure_sqlite_lookup(engine)
    Asset.__table__.create(engine)
    AssetObservation.__table__.create(engine)
    with Session(engine) as db:
        host = Asset(name="host-1", name_key="host-1", ip="2001:0db8:0:0:0:0:0:1")
        malformed = Asset(name="host-2", name_key="host-2", ip="not an IP")
        db.add_all([host, malformed])
        db.flush()
        db.add(AssetObservation(asset_id=host.id, source="ksc", source_key="1:1",
                               seen_at=dt.datetime.now(dt.UTC),
                               ips=["192.0.2.4", "2001:0db8:0:0:0:0:0:2", "invalid"]))
        db.commit()
        yield db, host.id
    engine.dispose()


@pytest.mark.parametrize("query", ["2001:db8::1", "2001:db8::2", "192.0.2.4"])
def test_diagnostic_primary_and_secondary_ip_lookup(offline_db, query):
    db, host_id = offline_db
    assert [host.id for host in candidate_rows(db, query, "ip")] == [host_id]
    result = lookup_inventory.assets(db, query, "ip")
    assert [item.id for item in result[0].items] == [str(host_id)]


def test_diagnostic_ip_lookup_does_not_match_unrelated_or_invalid_addresses(offline_db):
    db, _ = offline_db
    assert candidate_rows(db, "192.0.2.40", "ip") == []
    assert lookup_inventory.assets(db, "2001:db8::99", "ip")[0].items == []
