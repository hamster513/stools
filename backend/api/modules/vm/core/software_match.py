"""Conservative, pure NVD configuration evaluation for host software inventory.

Three-valued logic preserves uncertainty. A separate positive-target value prevents
an environment-only OR branch from turning another application's CVE into a finding.
"""
import re

_CORPORATE = re.compile(r'(?:[\s,]+(?:corporation|corp|incorporated|inc|llc|ltd|limited)\.?)+$', re.IGNORECASE)
_ARCH = re.compile(r'\s*(?:\((?:x86|x64|32-bit|64-bit)\)|\b(?:x86|x64|32-bit|64-bit))$', re.IGNORECASE)
_VENDOR_ALIASES = {'adobe_systems': 'adobe', 'mozilla_foundation': 'mozilla'}
_PRODUCT_ALIASES = {
    ('mozilla', 'mozilla_firefox'): 'firefox',
    ('google', 'google_chrome'): 'chrome',
    ('microsoft', 'microsoft_edge'): 'edge',
}
_BOUNDS = (
    ('versionStartIncluding', '>=', lambda x: x >= 0),
    ('versionStartExcluding', '>', lambda x: x > 0),
    ('versionEndIncluding', '<=', lambda x: x <= 0),
    ('versionEndExcluding', '<', lambda x: x < 0),
)


def _token(value):
    return re.sub(r'[\s_]+', '_', str(value or '').strip().casefold())


def product_key(publisher: str, name: str, version: str = '') -> tuple[str, str]:
    """Exact normalized identity; deliberately no fuzzy product aliasing."""
    vendor = _token(_CORPORATE.sub('', str(publisher or '').strip()))
    vendor = _VENDOR_ALIASES.get(vendor, vendor)
    product = _ARCH.sub('', str(name or '').strip()).strip()
    if version:
        product = re.sub(r'\s+(?:' + re.escape(str(version)) + r'|\(' +
                         re.escape(str(version)) + r'\))$', '', product).strip()
    product = _token(product)
    return vendor, _PRODUCT_ALIASES.get((vendor, product), product)


def _cpe(criteria):
    if not isinstance(criteria, str):
        return None
    fields, current, escaped = [], [], False
    for char in criteria:
        if escaped:
            current.extend(('\\', char))
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == ':':
            fields.append(''.join(current))
            current = []
        else:
            current.append(char)
    fields.append(''.join(current))
    if escaped or len(fields) != 13 or fields[:2] != ['cpe', '2.3']:
        return None
    return fields


def _literal(value):
    return re.sub(r'\\(.)', r'\1', value)


def _pattern(value):
    return bool(re.search(r'(?<!\\)[*?]', value))


def cpe_identity(criteria: str) -> tuple[str, str, str] | None:
    fields = _cpe(criteria)
    if not fields or fields[2] not in ('a', 'o', 'h'):
        return None
    if any(not value or value == '-' or _pattern(value) for value in fields[3:5]):
        return None
    vendor, product = product_key(_literal(fields[3]), _literal(fields[4]))
    return fields[2], vendor, product


def iter_products(configurations: list) -> set[tuple[str, str]]:
    """Extract only explicit vulnerable application identities for candidate lookup."""
    products = set()

    def visit(node):
        if not isinstance(node, dict):
            return
        rows = node.get('cpeMatch', [])
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and row.get('vulnerable') is True:
                identity = cpe_identity(row.get('criteria'))
                if identity and identity[0] == 'a':
                    products.add(identity[1:])
        for key in ('nodes', 'children'):
            children = node.get(key, [])
            for child in children if isinstance(children, list) else []:
                visit(child)

    if isinstance(configurations, list):
        for configuration in configurations:
            visit(configuration)
    return products


def _and(values):
    return False if False in values else None if None in values else True


def _or(values):
    return True if True in values else None if None in values else False


def _compare(left, right):
    if not all(isinstance(value, str) and re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', value)
               for value in (left, right)):
        return None
    a, b = (tuple(int(part) for part in value.split('.')) for value in (left, right))
    width = max(len(a), len(b))
    a, b = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (a > b) - (a < b)


def _version(item, fields, row, evidence):
    installed = str(item.get('version') or '').strip()
    checks, constraints = [], []
    required = fields[5]
    if required != '*':
        comparison = _compare(installed, _literal(required))
        exact = (installed == _literal(required) and required != '-' and not _pattern(required))
        checks.append(True if exact else None if comparison is None else comparison == 0)
        constraints.append('= ' + _literal(required))
    for key, symbol, operation in _BOUNDS:
        if key in row:
            comparison = _compare(installed, row[key])
            checks.append(None if comparison is None else operation(comparison))
            constraints.append(f'{symbol} {row[key]}')
    if not installed:
        checks.append(None)
    if any(value != '*' for value in fields[6:]):
        checks.append(None)
        evidence.append('CPE ограничивает обновление, редакцию, язык или платформу; '
                        'эти атрибуты не подтверждены инвентаризацией.')
    evidence.append(f'{item.get("name") or "ПО"}: установлена версия {installed or "неизвестна"}; '
                    f'условие CPE: {", ".join(constraints) or "все версии"}.')
    return _and(checks)


def evaluate(software: dict, configurations: list, inventory: list[dict],
             os_name: str = '') -> dict:
    """Return affected/not_affected/unknown without assuming inventory completeness."""
    evidence = []
    target = product_key(software.get('publisher'), software.get('name'), software.get('version'))
    inventory = [software] + [item for item in (inventory or []) if isinstance(item, dict)]

    def leaf(row):
        if not isinstance(row, dict):
            return None, None, False
        fields = _cpe(row.get('criteria'))
        identity = cpe_identity(row.get('criteria'))
        if not identity or not fields:
            evidence.append('Некорректный CPE или нет точного поставщика и продукта.')
            return None, None, False
        is_target = identity == ('a', *target)
        vulnerable = row.get('vulnerable')
        if not isinstance(vulnerable, bool):
            return None, None, is_target
        own = is_target and vulnerable
        if own:
            value = _version(software, fields, row, evidence)
            return value, value, True
        if identity[0] == 'a':
            candidates = [item for item in inventory if product_key(
                item.get('publisher'), item.get('name'), item.get('version')) == identity[1:]]
        elif identity[0] == 'o':
            # Only explicit OS names establish identity. No guessed family/build mapping.
            os_product = re.sub(r'^microsoft_', '', _token(os_name))
            known_windows = {'windows_7', 'windows_8', 'windows_8.1', 'windows_10', 'windows_11'}
            candidates = ([{'name': os_name, 'version': '*'}]
                          if identity[1:] == ('microsoft', os_product)
                          and os_product in known_windows and fields[5] == '*'
                          and not any(key in row for key, _, _ in _BOUNDS) else [])
        else:
            candidates = []
        if not candidates:
            evidence.append(f'Условие окружения {identity[1]}/{identity[2]} '
                            'не подтверждено; инвентаризация может быть неполной.')
            return None, False, False
        return _or([_version(item, fields, row, evidence) for item in candidates]), False, False

    def node(value):
        if not isinstance(value, dict):
            return None, None, False
        operator = value.get('operator', 'OR')
        if operator not in ('AND', 'OR') or not isinstance(value.get('negate', False), bool):
            return None, None, False
        children = []
        for key in ('nodes', 'children', 'cpeMatch'):
            if key not in value:
                continue
            if not isinstance(value[key], list):
                return None, None, False
            children.extend((leaf(child) if key == 'cpeMatch' else node(child))
                            for child in value[key])
        if not children:
            return None, None, False
        truth = (_and if operator == 'AND' else _or)([child[0] for child in children])
        positive = _or([child[1] for child in children])
        if operator == 'AND':
            positive = _and([truth, positive])
        seen = any(child[2] for child in children)
        if value.get('negate'):
            truth = None if truth is None else not truth
            positive = None if seen else False
        return truth, positive, seen

    if not isinstance(configurations, list) or not configurations or not all(target):
        result, seen = None, False
    else:
        roots = [node(value) for value in configurations]
        result, seen = _or([root[1] for root in roots]), any(root[2] for root in roots)
    state = ('affected' if result is True else 'not_affected' if result is False else 'unknown') if seen else 'unknown'
    reasons = {
        'affected': 'Совпали поставщик, продукт и версия; условия применимости подтверждены.',
        'not_affected': 'Версия или обязательное условие исключает применимость к этому ПО.',
        'unknown': 'Недостаточно данных для точного подтверждения применимости CVE.',
    }
    return {'state': state, 'reason': reasons[state], 'evidence': list(dict.fromkeys(evidence))}
