from types import SimpleNamespace
from api.modules.ksc.core.firewall.compare import compare_rules, list_signature


def rule(i, name='HTTPS', **patch):
    return SimpleNamespace(**(dict(id=i, layer='packet', position=i, name=name, action='разрешить', direction='исходящий', protocol='TCP', local_ports='', remote_ports='443', addresses='', enabled=True, scope_json='{"remote": [], "unread": []}') | patch))


def test_identical_profiles_ignore_source_ids_but_preserve_order():
    a = [rule(1), rule(2, 'DNS')]
    b = [rule(11, position=1), rule(12, 'DNS', position=2)]
    assert list_signature(a) == list_signature(b)
    assert compare_rules(a, b).summary == dict(unchanged=2, added=0, removed=0, changed=0, moved=0)
    assert list_signature(a) != list_signature(list(reversed(b)))


def test_actions_enabled_and_structured_scope_are_not_duplicates():
    base = [rule(1), rule(2, 'DNS'), rule(3, 'Other')]
    other = [rule(11, position=1, action='запретить'), rule(12, 'DNS', position=2, enabled=False), rule(13, 'Other', position=3, scope_json='{"remote": [{"ip":"192.0.2.1"}], "unread": []}')]
    result = compare_rules(base, other)
    assert result.summary['changed'] == 3
    assert [d.fields for d in result.deltas] == [['action'], ['enabled'], ['scope']]
    assert list_signature(base) != list_signature(other)


def test_added_removed_and_duplicates_keep_multiplicity():
    result = compare_rules([rule(1), rule(2)], [rule(3, position=1), rule(4, 'DNS', position=2)])
    assert result.summary == dict(unchanged=1, added=1, removed=1, changed=0, moved=0)
    assert {d.kind for d in result.deltas} == {'added', 'removed'}


def test_insertion_does_not_mark_every_following_rule_as_moved():
    result = compare_rules([rule(1, 'A'), rule(2, 'B')], [rule(10, 'New', position=1), rule(11, 'A', position=2), rule(12, 'B', position=3)])
    assert result.summary == dict(unchanged=2, added=1, removed=0, changed=0, moved=0)


def test_reordering_is_a_difference_even_with_identical_content():
    result = compare_rules([rule(1, 'A'), rule(2, 'B')], [rule(11, 'B', position=1), rule(12, 'A', position=2)])
    assert result.summary['moved'] == 1
    assert any(d.moved and d.previous for d in result.deltas)


def test_ambiguous_same_names_are_not_arbitrarily_paired():
    result = compare_rules([rule(1), rule(2)], [rule(11, position=1, action='запретить'), rule(12, position=2, enabled=False)])
    assert result.summary['changed'] == 0
    assert result.summary['added'] == result.summary['removed'] == 2


def test_json_key_order_does_not_create_false_differences():
    assert list_signature([rule(1)]) == list_signature([rule(2, position=1, scope_json='{"unread": [], "remote": []}')])
