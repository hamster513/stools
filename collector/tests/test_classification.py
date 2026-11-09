import pytest
from stools_threat_collector.classify import classify_publication

def classify(title, text='', scope='security_news', **kw):
    return classify_publication({'title':title,'text':text, **kw}, {'content_scope':scope})

def test_old_cve_with_new_attack_remains_relevant():
    r=classify('Attackers exploit CVE-2011-3402 today', 'A new campaign is exploiting this vulnerability.')
    assert r.category == 'relevant' and r.identifier_roles[0].role == 'primary'

def test_multicve_advisory_keeps_all_actionable_ids():
    r=classify('Security update', 'Patched CVE-2026-12345 and CVE-2026-54321', 'vendor_advisory')
    assert {i.role for i in r.identifier_roles} == {'actionable'}

def test_history_is_mentioned_not_actionable():
    r=classify('History of CVE-2011-3402', 'A retrospective of the old vulnerability')
    assert r.identifier_roles[0].role == 'mentioned'

@pytest.mark.parametrize('title',['AI detects diseases years early','Цена GeForce выросла в России','Singapore Airlines updates aircraft cabins'])
def test_background_news_filtered(title):
    assert classify(title, scope='general_it').category == 'background'

def test_chinese_and_early_signals():
    assert classify('安全公告 CVE-2026-12345', '漏洞正在被利用', 'vendor_advisory').category == 'relevant'
    assert classify('Обнаружена новая уязвимость VPN', 'Удалённое выполнение кода без авторизации').category == 'early_signal'

def test_roles_have_exact_evidence_and_bdu_alias_is_not_invented():
    doc={'title':'Уязвимость BDU:2026-12345','text':'Исправление доступно для BDU:2026-12345'}
    r=classify_publication(doc,{'content_scope':'vendor_advisory'})
    assert r.identifier_roles[0].identifier == 'BDU:2026-12345'
    assert r.identifier_roles[0].evidence_text in doc['title']
