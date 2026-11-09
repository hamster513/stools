import io
import pytest
from api.modules.vm.services.trends.source_import import parse_sources,export_sources

def test_csv_preview_parses_without_writes_and_export_no_secrets():
    rows=parse_sources(b'name,url,adapter\nNews,https://example.org/feed,rss\n','sources.csv')
    assert rows[0]['source']['url']=='https://example.org/feed'
    result=export_sources([{'name':'=formula','url':'https://example.org','adapter':'rss','token':'secret','proxy_profile':'private'}])
    assert 'secret' not in result and 'private' not in result and "'=formula" in result

def test_xlsx_formula_rejected():
    from openpyxl import Workbook
    workbook=Workbook();sheet=workbook.active;sheet.append(['name','url','adapter']);sheet.append(['=1+1','https://example.org','rss'])
    content=io.BytesIO();workbook.save(content)
    rows=parse_sources(content.getvalue(),'sources.xlsx')
    assert rows[0]['error']

def test_limits_and_missing_fields():
    with pytest.raises(ValueError): parse_sources(b'x'*(5*1024*1024+1),'sources.csv')
    assert parse_sources(b'name,url\nOnly name,\n','sources.csv')[0]['error']
