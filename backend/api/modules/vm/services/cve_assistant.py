"""Persisted reference-CVE reading help, independent of trend cards and inventory."""
from fastapi import HTTPException

from .cve_search import identifier, primary_url, public_cve
from .trends import assistant, assistant_cache

PREFIX = 'lookup:'  # A trend card can translate several articles; keep its answers separate.


def context(db, target, request):
    key = identifier(target.removeprefix(PREFIX))
    data = public_cve(db, key)
    if not data['description']:
        raise HTTPException(409, 'В загруженных базах нет описания уязвимости для перевода или объяснения.')
    original = data['description']
    return {'generation': None, 'revisions': [], 'truncated': len(original) > 8000, 'data_class': 'public',
        'sources': [{'title': key, 'url': primary_url(key)}],
        'content': {'identifier': key, 'aliases': data['aliases'], 'publications': [], 'cve': {
            'description': original[:8000], 'cvss': data['cvss'], 'epss': data['epss'],
            'known_exploited': data['known_exploited'], 'affected_products': data['affected_products']}}}


def generate(db, target, request, original):
    return assistant.generate(db, target.removeprefix(PREFIX), request, original)


def saved(db, key, request):
    public_cve(db, key)
    return assistant_cache.saved(db, PREFIX+key, request, context)


def respond(db, key, request):
    return assistant_cache.respond(db, PREFIX+key, request, context, generate)
