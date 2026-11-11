"""Pure matching tests: incomplete inventory must never prove applicability."""
import pytest

from api.modules.vm.core.software_match import (
    cpe_identity,
    evaluate,
    iter_products,
    product_key,
)


def software(version='1.5', **kw):
    return {'publisher': 'Example Corp.', 'name': 'Widget', 'version': version, **kw}


def match(version='*', vendor='example', product='widget', part='a', **kw):
    return {'vulnerable': True,
            'criteria': f'cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*', **kw}


def config(*matches, operator='OR', **kw):
    return [{'nodes': [{'operator': operator, 'cpeMatch': list(matches), **kw}]}]


def state(configurations, version='1.5', inventory=None, **kw):
    return evaluate(software(version), configurations, inventory or [], **kw)['state']


@pytest.mark.parametrize(('publisher', 'name', 'version', 'expected'), [
    ('Mozilla Corporation', 'Mozilla Firefox (x64)', '', ('mozilla', 'firefox')),
    ('Google LLC', 'Google Chrome 123.0 (64-bit)', '123.0', ('google', 'chrome')),
    ('Example Corp.', 'Widget', '', ('example', 'widget')),
    ('Example Corp.', 'Widget Enterprise', '', ('example', 'widget_enterprise')),
    ('Example Corp.', 'Widget Plugin', '', ('example', 'widget_plugin')),
])
def test_product_identity(publisher, name, version, expected):
    assert product_key(publisher, name, version) == expected


def test_cpe_escaped_separator_and_index():
    escaped = match(product=r'widget\:pro')
    assert cpe_identity(escaped['criteria']) == ('a', 'example', 'widget:pro')
    assert cpe_identity('invalid') is None
    assert iter_products(config(escaped, match(vulnerable=False), match(part='o'),
                                match(vendor='*'))) == {('example', 'widget:pro')}


@pytest.mark.parametrize(('version', 'expected'), [
    ('1.0', 'affected'), ('1.9', 'affected'), ('1.10', 'affected'),
    ('2.0', 'not_affected'), ('0.9', 'not_affected'), ('1.5-ubuntu1', 'unknown'),
])
def test_numeric_range(version, expected):
    assert state(config(match(versionStartIncluding='1.0', versionEndExcluding='2.0')),
                 version) == expected


@pytest.mark.parametrize(('bound', 'version', 'expected'), [
    ('versionStartExcluding', '1.9', 'not_affected'),
    ('versionStartExcluding', '1.10', 'affected'),
    ('versionEndIncluding', '1.9', 'affected'),
    ('versionEndIncluding', '1.10', 'not_affected'),
])
def test_other_numeric_boundaries(bound, version, expected):
    assert state(config(match(**{bound: '1.9'})), version) == expected


@pytest.mark.parametrize(('cpe_version', 'installed', 'expected'), [
    ('*', '1.2-beta', 'affected'), ('*', '', 'unknown'),
    ('1.5', '1.5.0', 'affected'), ('1.5', '1.6', 'not_affected'),
    ('1.5-beta', '1.5-beta', 'affected'), ('1.5-beta', '1.5', 'unknown'),
    ('1.?', '1.5', 'unknown'), ('-', '1.5', 'unknown'),
])
def test_exact_and_all_versions(cpe_version, installed, expected):
    assert state(config(match(cpe_version)), installed) == expected


def test_no_fuzzy_vendor_or_product_match():
    assert state(config(match(vendor='other'))) == 'unknown'
    assert state(config(match(product='widget_enterprise'))) == 'unknown'
    assert state(config(match(vulnerable=False))) == 'unknown'


@pytest.mark.parametrize('index', [6, 7, 8, 9, 10, 11, 12])
def test_unproven_cpe_attributes(index):
    row = match()
    fields = row['criteria'].split(':')
    fields[index] = 'enterprise' if index != 6 else 'sp1'
    row['criteria'] = ':'.join(fields)
    assert state(config(row)) == 'unknown'


def test_and_environment_requires_positive_inventory_evidence():
    configurations = config(match(), match(product='runtime', vulnerable=False,
                                          versionStartIncluding='3.0'), operator='AND')
    assert state(configurations) == 'unknown'
    assert state(configurations, inventory=[software('3.1', name='Runtime')]) == 'affected'
    assert state(configurations, inventory=[software('2.0', name='Runtime')]) == 'not_affected'


def test_os_prerequisite():
    configurations = config(match(), match(part='o', vendor='microsoft', product='windows_10',
                                          vulnerable=False), operator='AND')
    assert state(configurations) == 'unknown'
    assert state(configurations, os_name='Microsoft Windows 10') == 'affected'
    assert state(configurations, os_name='Linux') == 'unknown'


def test_environment_only_or_branch_cannot_mark_target_affected():
    configurations = config(match('1.0'), match(product='runtime', vulnerable=False))
    assert state(configurations, inventory=[software(name='Runtime')]) == 'not_affected'


def test_nested_and_or_and_negation():
    environment = {'operator': 'OR', 'negate': True,
                   'cpeMatch': [match('1.0', product='runtime', vulnerable=False)]}
    configurations = [{'operator': 'AND', 'nodes': [
        {'operator': 'OR', 'cpeMatch': [match('1.5'), match('2.0')]}, environment]}]
    assert state(configurations, inventory=[software('2.0', name='Runtime')]) == 'affected'
    assert state(configurations, inventory=[software('1.0', name='Runtime')]) == 'not_affected'
    assert state(configurations) == 'unknown'
    assert state(config(match(), negate=True)) == 'unknown'


@pytest.mark.parametrize('configurations', [[], [{}], None, [{'nodes': []}],
    [{'nodes': [{'operator': 'XOR', 'cpeMatch': [match()]}]}],
    [{'nodes': [{'cpeMatch': [{'criteria': match()['criteria']}]}]}],
    [{'nodes': [{'cpeMatch': [{'criteria': 'broken', 'vulnerable': True}]}]}],
])
def test_incomplete_configurations(configurations):
    assert state(configurations) == 'unknown'


def test_evidence_explains_installed_version_and_range():
    result = evaluate(software(), config(match(versionEndExcluding='2.0')), [])
    assert result['reason']
    assert any('1.5' in line and '2.0' in line for line in result['evidence'])


@pytest.mark.parametrize('configurations', [
    [{'nodes': 3}], [{'cpeMatch': 3}], [{'nodes': {'cpeMatch': [match()]}}],
])
def test_malformed_tree_is_safe_for_index_and_evaluation(configurations):
    assert iter_products(configurations) == set()
    assert state(configurations) == 'unknown'


def test_non_string_version_bound_is_unknown():
    assert state(config(match(versionStartIncluding=1))) == 'unknown'
