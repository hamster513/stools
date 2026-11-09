from api.modules.vm.services.trends.applicability import evaluate_applicability

def item(**kw): return {'product':'server','vendor':'vendor','version':'1.5','ecosystem':'generic','local_ref':'image:1', **kw}
def metadata(**kw): return {'cpe_matches':[{'vendor':'vendor','product':'server','ecosystem':'generic','versionStartIncluding':'1.0','versionEndExcluding':'2.0','complete':True, **kw}]}

def test_numeric_range_boundaries():
    assert evaluate_applicability(item(),metadata())['state']=='affected'
    assert evaluate_applicability(item(version='2.0'),metadata())['state']=='not_affected'

def test_incomplete_and_backports_are_unknown():
    assert evaluate_applicability(item(version='3.0'),metadata(complete=False))['state']=='unknown'
    assert evaluate_applicability(item(version='1.5-ubuntu1'),metadata())['state']=='unknown'

def test_scanner_match_survives_version_disagreement():
    result=evaluate_applicability(item(version='3.0'),metadata(),exact_scanner=True)
    assert result['state']=='affected' and result['confidence_kind']=='exact_scanner'

def test_other_ecosystem_or_plugin_is_not_inferred():
    assert evaluate_applicability(item(ecosystem='npm'),metadata())['state']=='unknown'
    assert evaluate_applicability(item(product='server-plugin'),metadata())['state']=='unknown'
