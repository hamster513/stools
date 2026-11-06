"""Add newly shipped sources without resetting operator configuration or cursors."""
import json
from pathlib import Path

from .contracts import Source


def import_catalog(store, rows=None):
    if rows is None:
        rows = json.loads(Path(__file__).with_name('sources.json').read_text())
    sources = [Source.model_validate(row).model_dump() for row in rows]
    known = {source['url'] for source in store.sources()}
    added = 0
    for source in sources:
        if source['url'] in known:
            continue
        # Enabling collection remains an explicit operator choice, including upgrades.
        source['enabled'] = False
        store.save_source(source)
        known.add(source['url'])
        added += 1
    return added
